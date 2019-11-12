use anyhow::{Context, Error};
use gimli::read::Reader;
use inject_types::{ObjectInfo, SetBreakpointsReq, SetBreakpointsResp, SOCKET_ENV};
use object::read::Object;
use regex::RegexSet;
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    ops::{Deref, Index, Range},
    os::unix::{ffi::OsStrExt, net::UnixListener, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::Arc,
};
use structopt::StructOpt;

mod error;
mod mapped_slice;
mod symtab;

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
    #[structopt(long, default_value = "libruskcov_inject.so")]
    inject: PathBuf,
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
) -> Result<impl Iterator<Item = usize>, Error> {
    if debug {
        println!("Object {:x?}", obj);
    }

    let ctxt = load_debug(&obj.path, debug)?;

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
            // directory-level filter
            let allowed_dirs: Vec<bool> = (0..)
                .map(|idx| header.directory(idx))
                .take_while(Option::is_some)
                .map(Option::unwrap)
                .map(|dir| -> Result<bool, Error> {
                    let dir = ctxt
                        .sections
                        .attr_string(unit, dir)?
                        .to_string_lossy()?
                        .into_owned();
                    let strdir = comp_dir.join(dir).display().to_string();

                    let allow = filter.dir_include.is_match(&strdir)
                        || !filter.dir_exclude.is_match(&strdir);

                    if debug {
                        println!("dir {} allow {:?}", strdir, allow);
                    }
                    Ok(allow)
                })
                .collect::<Result<_, _>>()?;
            println!("allowed_dirs {:?}", allowed_dirs);

            let mut rows = ilnp.clone().rows();
            while let Some((header, row)) = rows.next_row()? {
                if !row.is_stmt() {
                    continue;
                }
                let file = row.file(header).unwrap();
                if !allowed_dirs[file.directory_index() as usize] {
                    continue;
                }
                if debug {
                    println!(
                        "row: addr: {:x}, (mapped {:x}), dir: {} idx {} {:?}, file {}:{}",
                        row.address(),
                        row.address() + obj.addr as u64,
                        ctxt.sections
                            .attr_string(unit, file.directory(header).unwrap())?
                            .to_string_lossy()?,
                        file.directory_index(),
                        allowed_dirs[file.directory_index() as usize],
                        ctxt.sections
                            .attr_string(unit, file.path_name())?
                            .to_string_lossy()?,
                        row.line().unwrap_or(0),
                    );
                }
            }
        }
    }

    Ok(std::iter::empty())
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
        .env(INJECT_LIBRARY_VAR, &args.inject)
        .env(SOCKET_ENV, &sock_path);
    if false {
        // XXX calling this will trap on exec so parent needs to start handling us
        unsafe {
            command.pre_exec(|| {
                println!("about to traceme");
                let res = nix::sys::ptrace::traceme()
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err));
                println!("traceme done {:?}", res);
                if let Err(err) = &res {
                    eprintln!("ptrace traceme failed: {}", err);
                }
                res
            })
        };
    }
    let child = command.spawn().context("process spawn")?;

    let mut objseen = HashSet::new();

    eprintln!("listening child pid {}", child.id());
    for conn in listener.incoming() {
        match conn {
            Ok(conn) => {
                eprintln!("connection");
                let mut reader = BufReader::new(conn.try_clone().expect("clone failed"));
                let mut writer = BufWriter::new(conn);

                let objinfo: Vec<ObjectInfo> =
                    bincode::deserialize_from(&mut reader).expect("ObjectInfo decode failed");
                for obj in &objinfo {
                    if objseen.insert(obj.path.clone()) {
                        let _ = get_breakpoints(obj, &filter, args.debug);
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
