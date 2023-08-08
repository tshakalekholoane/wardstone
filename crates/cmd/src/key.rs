//! Key types supported by the application.
use std::{fmt, io};

pub mod certificate;

/// Represents an error that could arise as a result of reading a key or
/// parsing it's contents.
#[derive(Debug)]
pub enum Error {
  Io(io::Error),
  Parse(openssl::error::ErrorStack),
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Error::Io(err) => match err.kind() {
        io::ErrorKind::NotFound => write!(f, "Key not found."),
        io::ErrorKind::PermissionDenied => write!(f, "Permission denied."),
        _ => write!(f, "Unexpected error. Please file an issue."),
      },
      Error::Parse(_) => write!(f, "Key parse error."),
    }
  }
}

impl From<io::Error> for Error {
  fn from(err: io::Error) -> Self {
    Self::Io(err)
  }
}

impl From<openssl::error::ErrorStack> for Error {
  fn from(err: openssl::error::ErrorStack) -> Self {
    Self::Parse(err)
  }
}
