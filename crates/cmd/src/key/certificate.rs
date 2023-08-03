use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use openssl::pkey::Id;
use openssl::x509::X509;
use wardstone_core::primitive::hash::Hash;

use crate::adapter::{SignatureAlgorithm, HASH_FUNCTIONS, SIGNATURE_ALGORITHMS};

/// Represents a TLS certificate.
#[derive(Debug)]
pub struct Certificate(X509);

impl Certificate {
  pub fn extract_hash_function(&self) -> &Hash {
    let algorithms = self
      .0
      .signature_algorithm()
      .object()
      .nid()
      .signature_algorithms()
      .expect("algorithms");
    let long_name = algorithms.digest.long_name().expect("long name");
    let instance = HASH_FUNCTIONS.get(long_name).expect("instance");
    instance
  }

  pub fn extract_signature_algorithm(&self) -> &SignatureAlgorithm {
    let public_key = self.0.public_key().expect("public key");
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
        let key = public_key.ec_key().expect("elliptic curve key");
        let nid = key.group().curve_name().expect("curve name");
        let long_name = nid.long_name().expect("long name");
        let instance = SIGNATURE_ALGORITHMS.get(long_name).expect("instance");
        instance
      },
      _ => unimplemented!(),
    }
  }

  pub fn from_pem_file(path: &PathBuf) -> Certificate {
    let mut file = File::open(path).expect("open certificate");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read file");
    let certificate = X509::from_pem(&bytes).expect("PEM encoded X509 certificate");
    Self(certificate)
  }
}
