use std::{fmt, io};

pub mod certificate;

#[derive(Debug)]
pub enum KeyError {
  Io(std::io::Error),
  Parse(openssl::error::ErrorStack),
}

impl fmt::Display for KeyError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      KeyError::Io(err) => match err.kind() {
        io::ErrorKind::NotFound => write!(f, "Key not found."),
        io::ErrorKind::PermissionDenied => write!(f, "Permission denied."),
        _ => write!(f, "Unexpected error. Please file an issue."),
      },
      KeyError::Parse(_) => write!(f, "Key parse error."),
    }
  }
}

impl From<io::Error> for KeyError {
  fn from(err: io::Error) -> Self {
    Self::Io(err)
  }
}

impl From<openssl::error::ErrorStack> for KeyError {
  fn from(err: openssl::error::ErrorStack) -> Self {
    Self::Parse(err)
  }
}
