use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    binary: PathBuf,
}

fn main() {
    let args = Args::from_args();
}