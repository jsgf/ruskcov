use anyhow::{Context, Error};
use gimli::read::Reader;
use inject_types::{BreakpointInst, ObjectInfo, SetBreakpointsReq, SetBreakpointsResp, SOCKET_ENV};
use nix::{
    sys::{signal, wait},
    unistd::Pid,
};
use object::read::Object;
use regex::RegexSet;
use std::{
    borrow::Borrow,
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    iter,
    ops::{Deref, Index, Range},
    os::unix::{ffi::OsStrExt, net::UnixListener, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
};
use structopt::StructOpt;

mod error;
mod mapped_slice;
mod process;
mod srcloc;
mod symtab;

use srcloc::{Location, SrcPath};

#[cfg_attr(
    any(target_arch = "x86", target_arch = "x86_64"),
    path = "ptrace_x86.rs"
)]
mod ptrace;

use error::ObjectError;
use mapped_slice::MappedSlice;

#[cfg(target_os = "macos")]
const INJECT_LIBRARY_VAR: &str = "DYLD_INSERT_LIBRARIES"; // XXX may not be enough to interpose dlopen
#[cfg(all(unix, not(target_os = "macos")))]
const INJECT_LIBRARY_VAR: &str = "LD_PRELOAD";

#[derive(StructOpt, Debug, Clone)]
#[structopt(rename_all = "kebab-case")]
struct Args {
    /// Path to libruskcov_inject.so (TODO: build in)
    #[structopt(long, default_value = "libruskcov_inject.so", number_of_values(1))]
    inject: Vec<PathBuf>,
    /// Include sources in directories matching this REGEX
    #[structopt(long, number_of_values(1))]
    include_dir: Vec<String>,
    /// Include sources in directories matching this REGEX
    #[structopt(long, number_of_values(1))]
    exclude_dir: Vec<String>,
    /// Print verbose debug gunk
    #[structopt(long)]
    debug: bool,
    binary: PathBuf,
    args: Vec<String>,
}

/// Filter for interesting source files. By default, all files are
/// considered interesting, and then the include and exclude filters are applied. Include
/// takes precidence over exclude.
#[derive(Clone, Debug)]
struct Filter {
    /// Include all directories matching this set
    dir_include: RegexSet,
    /// Exclude all directories matching this set (include takes precidence)
    dir_exclude: RegexSet,
}

struct State {
    primary: Child,
    tracees: HashSet<u32>,
}

impl State {
    fn new(primary: Child) -> Self {
        let mut tracees = HashSet::new();
        let _ = tracees.insert(primary.id());

        State { primary, tracees }
    }

    fn add_child(&mut self, child: &Child) {
        let _ = self.tracees.insert(child.id());
    }
}

fn load_debug(
    path: &Path,
    debug: bool,
) -> Result<symtab::Context<gimli::EndianReader<gimli::RunTimeEndian, MappedSlice>>, Error> {
    let map = {
        let file = File::open(path).context("Failed to open object")?;

        MappedSlice::new(file)?
    };
    let objfile = object::File::parse(&*map)
        .map_err(ObjectError)
        .context("object file parse failed")?;

    let linkobj;
    let linkmap;

    let (objfile, mapping) = if let Some((name, crc)) = objfile.gnu_debuglink() {
        let name = Path::new(OsStr::from_bytes(name));
        if debug {
            println!(
                "{} => debuglink {} {:x}",
                path.display(),
                name.display(),
                crc
            );
        }

        let objdir = path.parent().unwrap_or(Path::new("."));
        let relobjdir = objdir
            .components()
            .filter(|c| match c {
                Component::Prefix { .. } | Component::RootDir => false,
                _ => true,
            })
            .collect::<PathBuf>();

        let paths = vec![
            objdir.join(name),
            objdir.join(".debug").join(name),
            Path::new("/usr/lib/debug").join(&relobjdir).join(name),
            // TODO: option for other debug dirs
        ];

        let mut file = None;

        for path in paths {
            if let Ok(f) = File::open(&path) {
                if debug {
                    println!("Using debuglink {}", path.display());
                }
                file = Some(f);
                break;
            }
        }

        if let Some(file) = file {
            linkmap = MappedSlice::new(file)?;
            let linked_crc = crc::crc32::checksum_ieee(&*linkmap);
            if crc == linked_crc {
                match object::File::parse(&*linkmap) {
                    Ok(obj) => {
                        linkobj = obj;

                        drop(objfile);
                        drop(map);
                        (&linkobj, &linkmap)
                    }
                    Err(err) => {
                        println!("Failed to parse debuglink {:?}", err);
                        (&objfile, &map)
                    }
                }
            } else {
                // CRC mismatch
                if debug {
                    println!(
                        "debuglink {} crc mismatch got {:08x} wanted {:08x}",
                        path.display(),
                        linked_crc,
                        crc
                    );
                }
                (&objfile, &map)
            }
        } else {
            // Couldn't find debuglink, use the object
            (&objfile, &map)
        }
    } else {
        // No debuglink, just use the object
        (&objfile, &map)
    };

    symtab::Context::new_from_mapping(mapping, objfile).map_err(Error::from)
}

fn get_breakpoints(
    obj: &ObjectInfo,
    filter: &Filter,
    debug: bool,
) -> Result<Vec<(u64, Location)>, Error> {
    if debug {
        println!("Object {:x?}", obj);
    }

    let ctxt = load_debug(&obj.path, debug)?;

    let mut locations = Vec::new();

    //println!("units for {}: {:#?}", obj.path.display(), ctxt.units());
    for unit in ctxt.units() {
        let comp_dir = unit
            .comp_dir
            .as_ref()
            .map(|dir| dir.to_string_lossy().map(|dir| dir.into_owned()))
            .transpose()?;
        let comp_dir = Path::new(comp_dir.as_ref().map(String::as_str).unwrap_or("."));

        if debug {
            println!(
                "==== NEW UNIT ==== {} {}",
                comp_dir.display(),
                unit.name
                    .as_ref()
                    .map(|name| name.to_string_lossy().unwrap().into_owned())
                    .unwrap_or("???".to_string()),
            );
        }

        if let Some(ilnp) = &unit.line_program {
            let header = ilnp.header();
            // Directory-level filter, indexed by the per-unit directory index number.
            let allowed_dirs: Vec<(String, bool)> = (0..)
                .map(|idx| header.directory(idx))
                .take_while(Option::is_some)
                .map(Option::unwrap)
                .map(|dir| -> Result<(String, bool), Error> {
                    let dir = ctxt
                        .sections
                        .attr_string(unit, dir)?
                        .to_string_lossy()?
                        .into_owned();
                    let strdir = comp_dir.join(dir).display().to_string();

                    let allow = filter.dir_include.is_match(&strdir)
                        || !filter.dir_exclude.is_match(&strdir);

                    Ok((strdir, allow))
                })
                .collect::<Result<_, _>>()?;

            if debug {
                println!("allowed_dirs {:?}", allowed_dirs);
            }

            let mut rows = ilnp.clone().rows();
            while let Some((header, row)) = rows.next_row()? {
                if !row.is_stmt() {
                    continue;
                }
                let file = row.file(header).unwrap();
                if !allowed_dirs[file.directory_index() as usize].1 {
                    continue;
                }
                let dirname = &allowed_dirs[file.directory_index() as usize].0;
                let filename = ctxt.sections.attr_string(unit, file.path_name())?;
                let line = row.line().unwrap_or(0);

                let addr = row.address() + obj.addr as u64;
                let loc = Location::new(
                    SrcPath::new(dirname, &*filename.to_string_lossy()?),
                    line as u32,
                );

                if debug {
                    println!(
                        "Location: {}:{} {:x}",
                        loc.srcpath().display(),
                        loc.line(),
                        addr
                    );
                }

                locations.push((addr, loc));
            }
        }
    }

    Ok(locations)
}

fn try_main() -> Result<(), Error> {
    let args = Args::from_args();

    if args.debug {
        println!("Args {:#?}", args);
    }

    let tempdir = tempfile::Builder::new()
        .prefix("ruskcov")
        .tempdir()
        .context("Making tempdir")?;

    let filter = Filter {
        dir_include: RegexSet::new(&args.include_dir)?,
        dir_exclude: RegexSet::new(&args.exclude_dir)?,
    };

    let sock_path = tempdir.path().join("rustkcov.sock");

    let listener = UnixListener::bind(&sock_path).context("Socket bind")?;

    let mut command = Command::new(args.binary);
    command
        .args(args.args)
        .env(INJECT_LIBRARY_VAR, std::env::join_paths(&args.inject)?)
        .env(SOCKET_ENV, &sock_path);

    let child = command.spawn().context("process spawn")?;
    let child_id = Pid::from_raw(child.id() as i32);

    let mut state = Arc::new(Mutex::new(State::new(child)));

    thread::spawn({
        let state = state.clone();
        move || {
            ptrace::seize(
                child_id,
                ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK, //| ptrace::Options::PTRACE_O_TRACESYSGOOD
            )
            .context("attaching to child")
            .expect("seize failed");
            while let Ok(status) = wait::wait() {
                use wait::WaitStatus::*;
                println!("wait status {:?}", status);
                match status {
                    Exited(pid, status) => {
                        println!("pid {} exited status {}", pid, status);
                    }
                    Signaled(pid, sig, coredumped) => unimplemented!("{:?}", status),
                    Stopped(pid, signal) => {
                        let ip = match ptrace::getregs(pid).expect("getregs") {
                            ptrace::UserRegs::I386(regs) => u64::from(regs.eip),
                            ptrace::UserRegs::X86_64(regs) => u64::from(regs.rip),
                        };

                        println!("stopped pid {} signal {} rip {:x}", pid, signal, ip);
                        if signal == signal::SIGTRAP {
                            ptrace::cont(pid, None).expect("cont failed");
                        } else {
                            ptrace::cont(pid, Some(signal)).expect("cont signal failed");
                        }
                    }
                    PtraceEvent(pid, sig, event) => {
                        let ev: ptrace::Event = unsafe { std::mem::transmute(event) };
                        unimplemented!("{:?} ev {:?}", status, ev)
                    }
                    PtraceSyscall(pid) => unimplemented!("{:?}", status),
                    Continued(pid) => unimplemented!("{:?}", status),
                    StillAlive => {}
                }
            }
        }
    });

    let mut objseen = HashSet::new();

    eprintln!("listening child pid {}", child_id);
    for conn in listener.incoming() {
        match conn {
            Ok(conn) => {
                eprintln!("connection");
                let mut reader = BufReader::new(conn.try_clone().expect("clone failed"));
                let mut writer = BufWriter::new(conn);

                let objinfo: Vec<ObjectInfo> =
                    bincode::deserialize_from(&mut reader).expect("ObjectInfo decode failed");
                for obj in &objinfo {
                    if objseen.insert((obj.pid, obj.path.clone())) {
                        match get_breakpoints(obj, &filter, args.debug) {
                            Ok(bp) => println!(
                                "{}: would set {} breakpoints for obj {}",
                                obj.pid,
                                bp.len(),
                                obj.path.display()
                            ),
                            Err(err) => {
                                println!("Failed to get bps for {}: {}", obj.path.display(), err)
                            }
                        }
                    }
                }

                bincode::serialize_into(&mut writer, &SetBreakpointsReq::default())
                    .expect("serialize nil breakpoints");
                writer.flush().expect("flush send");
            }
            Err(err) => println!("Failed to get connection: {}", err),
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = try_main() {
        eprintln!("Failed : {}", err);
        for err in err.chain().skip(1) {
            eprintln!("Because: {}", err);
        }
    }
}
