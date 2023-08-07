use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::{fmt, io};

use openssl::pkey::Id;
use openssl::x509::X509;
use wardstone_core::primitive::hash::Hash;

use crate::bridge::{Asymmetric, HASH_FUNCTIONS, SIGNATURE_ALGORITHMS};

/// Represents a TLS certificate.
#[derive(Debug)]
pub struct Certificate(X509);

impl Certificate {
  pub fn extract_hash_function(&self) -> Option<&Hash> {
    let name = self
      .0
      .signature_algorithm()
      .object()
      .nid()
      .signature_algorithms()?
      .digest
      .long_name()
      .ok()?;
    HASH_FUNCTIONS.get(name).copied()
  }

  pub fn extract_signature_algorithm(&self) -> Option<&Asymmetric> {
    let public_key = self.0.public_key().ok()?;
    match public_key.id() {
      Id::DH
      | Id::DSA
      | Id::EC
      | Id::RSA
      | Id::ED25519
      | Id::ED448
      | Id::SM2
      | Id::X25519
      | Id::X448 => {
        let name = public_key
          .ec_key()
          .ok()?
          .group()
          .curve_name()?
          .long_name()
          .ok()?;
        SIGNATURE_ALGORITHMS.get(name)
      },
      _ => None,
    }
  }

  pub fn from_pem_file(path: &PathBuf) -> Result<Certificate, Error> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let certificate = X509::from_pem(&contents)?;
    Ok(Self(certificate))
  }
}

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
