use std::{
    error::Error,
    fmt::{self, Display},
};

/// Wrapper for `object`'s errors
#[derive(Debug, Copy, Clone)]
pub struct ObjectError(pub &'static str);

impl Display for ObjectError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.0)
    }
}

impl From<&'static str> for ObjectError {
    fn from(s: &'static str) -> Self {
        ObjectError(s)
    }
}

impl Error for ObjectError {}