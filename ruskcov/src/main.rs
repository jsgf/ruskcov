use anyhow::{Context, Error};
use gimli::read::Reader;
use inject_types::{ObjectInfo, SetBreakpointsReq, SetBreakpointsResp, SOCKET_ENV};
use object::read::Object;
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    os::unix::{ffi::OsStrExt, net::UnixListener, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::Command,
};
use structopt::StructOpt;

mod error;
mod symtab;

use error::ObjectError;

#[cfg(target_os = "macos")]
const INJECT_LIBRARY_VAR: &str = "DYLD_INSERT_LIBRARIES"; // XXX may not be enough to interpose dlopen
#[cfg(all(unix, not(target_os = "macos")))]
const INJECT_LIBRARY_VAR: &str = "LD_PRELOAD";

#[derive(StructOpt)]
struct Args {
    /// Path to libruskcov_inject.so (TODO: build in)
    #[structopt(long, default_value = "libruskcov_inject.so")]
    inject: PathBuf,
    /// Print verbose debug gunk
    #[structopt(long)]
    debug: bool,
    binary: PathBuf,
    args: Vec<String>,
}

fn get_breakpoints(obj: &ObjectInfo, debug: bool) -> Result<impl Iterator<Item = usize>, Error> {
    if debug {
        println!("Object {:x?}", obj);
    }
    let map = {
        let file = File::open(&obj.path).context("Failed to open object")?;
        unsafe { memmap::Mmap::map(&file).context("mmap failed")? }
    };
    let objfile = object::File::parse(&*map)
        .map_err(ObjectError)
        .context("object file parse failed")?;

    // pre-declare to get the right lifetime
    let linkmap;
    let linkobjfile;

    let objfile = if let Some((name, crc)) = objfile.gnu_debuglink() {
        let name = Path::new(OsStr::from_bytes(name));
        if debug {
            println!(
                "{} => debuglink {} {:x}",
                obj.path.display(),
                name.display(),
                crc
            );
        }

        let objdir = obj.path.parent().unwrap_or(Path::new("."));
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
            linkmap = unsafe { memmap::Mmap::map(&file).context("mmap failed")? };
            let linked_crc = crc::crc32::checksum_ieee(&*linkmap);
            if crc == linked_crc {
                match object::File::parse(&*linkmap) {
                    Ok(obj) => {
                        linkobjfile = obj;
                        drop(objfile);
                        drop(map);
                        &linkobjfile
                    }
                    Err(err) => {
                        println!("Failed to parse debuglink {:?}", err);
                        &objfile
                    }
                }
            } else {
                // CRC mismatch
                &objfile
            }
        } else {
            // Couldn't find debuglink, use the object
            &objfile
        }
    } else {
        // No debuglink, just use the object
        &objfile
    };

    let ctxt = symtab::Context::new(objfile)?;

    //println!("units for {}: {:#?}", obj.path.display(), ctxt.units());
    for unit in ctxt.units() {
        if debug {
            println!(
                "==== NEW UNIT ==== {} {}",
                unit.comp_dir
                    .as_ref()
                    .map(|dir| dir.to_string_lossy().unwrap().into_owned())
                    .unwrap_or("<no dir>".to_string()),
                unit.name
                    .as_ref()
                    .map(|name| name.to_string_lossy().unwrap().into_owned())
                    .unwrap_or("<no name>".to_string()),
            );
        }
        if let Some(ilnp) = &unit.line_program {
            let mut rows = ilnp.clone().rows();
            while let Some((header, row)) = rows.next_row()? {
                if !row.is_stmt() {
                    continue;
                }
                let file = row.file(header).unwrap();
                if debug {
                    println!(
                        "row: addr: {:x}, (mapped {:x}), dir: {}, file {:?}",
                        row.address(),
                        row.address() + obj.addr as u64,
                        ctxt.sections
                            .attr_string(unit, file.directory(header).unwrap())?
                            .to_string_lossy()?,
                        ctxt.sections
                            .attr_string(unit, file.path_name())?
                            .to_string_lossy()?
                    );
                }
            }
        }
    }

    Ok(std::iter::empty())
}

fn try_main() -> Result<(), Error> {
    let args = Args::from_args();

    let tempdir = tempfile::Builder::new()
        .prefix("ruskcov")
        .tempdir()
        .context("Making tempdir")?;

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
                        let _ = get_breakpoints(obj, args.debug);
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
