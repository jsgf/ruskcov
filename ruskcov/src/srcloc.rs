//! Locations in source code

use inject_types::{BreakpointInst, ObjectInfo, SetBreakpointsReq, SetBreakpointsResp, SOCKET_ENV};
use internment::Intern;
use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

/// Information about a breakpoint address. Does not contain the address itself,
/// on the assumption that its the key of some mapping structure.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Location {
    // Filename referenced
    srcpath: SrcPath,
    // Line number
    line: u32,
    // Replaced instruction when breakpoint set
    replaced: Option<BreakpointInst>,
}

impl Location {
    pub fn new(srcpath: SrcPath, line: u32) -> Self {
        Location {
            srcpath,
            line,
            replaced: None,
        }
    }

    pub fn srcpath(&self) -> PathBuf {
        self.srcpath.to_pathbuf()
    }

    pub fn line(&self) -> u32 {
        self.line
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SrcPath(SrcDir, SrcFile);

impl SrcPath {
    pub fn new<D: Into<PathBuf>, F: Into<PathBuf>>(dir: D, file: F) -> Self {
        SrcPath(From::from(dir), From::from(file))
    }

    fn to_pathbuf(&self) -> PathBuf {
        self.0.join(&*self.1)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct SrcDir(Intern<PathBuf>);

impl<T> From<T> for SrcDir
where
    T: Into<PathBuf>,
{
    fn from(p: T) -> Self {
        SrcDir(Intern::new(p.into()))
    }
}

impl Deref for SrcDir {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        self.0.as_path()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct SrcFile(Intern<PathBuf>);

impl<T> From<T> for SrcFile
where
    T: Into<PathBuf>,
{
    fn from(p: T) -> Self {
        SrcFile(Intern::new(p.into()))
    }
}

impl Deref for SrcFile {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        self.0.as_path()
    }
}
