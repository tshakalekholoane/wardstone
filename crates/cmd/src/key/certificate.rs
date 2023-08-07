use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use openssl::pkey::Id;
use openssl::x509::X509;

use crate::key::Error;
use crate::primitive::asymmetric::Asymmetric;
use crate::primitive::hash::HashFunc;

/// Represents a TLS certificate.
#[derive(Debug)]
pub struct Certificate(X509);

impl Certificate {
  pub fn extract_hash_function(&self) -> Option<HashFunc> {
    let name = self
      .0
      .signature_algorithm()
      .object()
      .nid()
      .signature_algorithms()?
      .digest
      .long_name()
      .ok()?;
    Some(name.into())
  }

  pub fn extract_signature_algorithm(&self) -> Option<Asymmetric> {
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
        Some(name.into())
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
