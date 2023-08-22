//! Key types supported by the application.
use std::{fmt, io};

use openssh_keys::errors::OpenSSHKeyError;
use openssl::error::ErrorStack;
use wardstone_core::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;
use x509_parser::nom::Err as NomError;
use x509_parser::prelude::{PEMError, X509Error};

pub mod certificate;
pub mod ssh;

/// Represents a cryptographic key.
pub trait Key {
  fn hash_function(&self) -> Option<Hash>;
  fn signature_algorithm(&self) -> Asymmetric;
}

/// Represents an error that could arise as a result of reading a key or
/// parsing it's contents.
#[derive(Debug)]
pub enum Error {
  Io(io::Error),
  ParsePEM(NomError<PEMError>),
  ParseSsh(OpenSSHKeyError),
  ParseX509(ErrorStack),
  ParseX509Certificate(NomError<X509Error>),
  Unrecognised(String),
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Error::Io(err) => match err.kind() {
        io::ErrorKind::NotFound => write!(f, "Key not found."),
        io::ErrorKind::PermissionDenied => write!(f, "Permission denied."),
        _ => write!(f, "Unexpected error. Please file an issue."),
      },
      Error::ParsePEM(_) => write!(f, "Cannot parse PEM file."),
      Error::ParseSsh(_) => write!(f, "Cannot parse SSH public key."),
      Error::ParseX509Certificate(_) | Error::ParseX509(_) => {
        write!(f, "Cannot parse X.509 certificate.")
      },
      Error::Unrecognised(oid) => write!(f, "Unrecognised key: {}. Please file an issue.", oid),
    }
  }
}

impl From<io::Error> for Error {
  fn from(err: io::Error) -> Self {
    Self::Io(err)
  }
}

impl From<NomError<PEMError>> for Error {
  fn from(err: NomError<PEMError>) -> Self {
    Self::ParsePEM(err)
  }
}

impl From<ErrorStack> for Error {
  fn from(err: ErrorStack) -> Self {
    Self::ParseX509(err)
  }
}

impl From<NomError<X509Error>> for Error {
  fn from(err: NomError<X509Error>) -> Self {
    Self::ParseX509Certificate(err)
  }
}

impl From<OpenSSHKeyError> for Error {
  fn from(err: OpenSSHKeyError) -> Self {
    Self::ParseSsh(err)
  }
}
