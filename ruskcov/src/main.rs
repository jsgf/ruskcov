use anyhow::{Context, Error};
use inject_types::{ObjectInfo, SetBreakpointsReq, SetBreakpointsResp, SOCKET_ENV};
use object::read::Object;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    process::Command,
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    /// Path to libruskcov_inject.so (TODO: build in)
    #[structopt(long, default_value = "libruskcov_inject.so")]
    inject: PathBuf,
    binary: PathBuf,
    args: Vec<String>,
}

fn get_breakpoints(obj: &ObjectInfo) -> Result<impl Iterator<Item = usize>, Error> {
    let file = File::open(&obj.path).context("Failed to open object")?;
    let map = unsafe { memmap::Mmap::map(&file).context("mmap failed")? };
    let obj = &object::File::parse(&*map).expect("object file parse failed");
    let symbols = obj.symbol_map();

    println!("obj {:#?}", obj);

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

    let child = Command::new(args.binary)
        .args(args.args)
        .env("LD_PRELOAD", &args.inject)
        .env(SOCKET_ENV, &sock_path)
        .spawn()
        .context("process spawn")?;

    for conn in listener.incoming() {
        match conn {
            Ok(conn) => {
                let mut reader = BufReader::new(conn.try_clone().expect("clone failed"));
                let mut writer = BufWriter::new(conn);

                let objinfo: Vec<ObjectInfo> =
                    bincode::deserialize_from(&mut reader).expect("ObjectInfo decode failed");
                println!("objinfo {:#?}", objinfo);

                for obj in &objinfo {
                    let _ = get_breakpoints(obj);
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
