use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::ValueEnum;
use once_cell::sync::Lazy;
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::x509::X509;
use wardstone_core::primitive::ecc::*;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Guide {
  /// The BSI TR-02102 series of technical guidelines.
  Bsi,
}

// Maintains a mapping of OpenSSL NIDs and their wardstone_core
// equivalents.
static CORE_INSTANCES: Lazy<HashMap<Nid, Ecc>> = Lazy::new(|| {
  let mut m = HashMap::new();
  // TODO: Fill.
  m.insert(Nid::BRAINPOOL_P256R1, BRAINPOOLP256R1);
  m
});

struct Certificate(X509);

impl Certificate {
  pub fn from_file(path: &PathBuf) -> Certificate {
    let mut file = File::open(path).expect("open certificate");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read file");
    let certificate = X509::from_pem(&bytes).expect("PEM encoded X509 certificate");
    Self(certificate)
  }

  // TODO: The return type could also be a generic type encompassing all
  // supported signature algorithms.
  pub fn key(&self) -> Option<&Ecc> {
    let public_key = self.0.public_key().expect("public key");
    match public_key.id() {
      Id::EC => {
        let key = public_key.ec_key().expect("elliptic curve key");
        let id = key.group().curve_name().expect("curve name");
        CORE_INSTANCES.get(&id)
      },
      _ => todo!(),
    }
  }
}

pub fn x509(path: &PathBuf, _against: &Guide) {
  let certificate = Certificate::from_file(path);
  let key = certificate.key();
  // TODO: Validate.
  println!("debug: validate key: {:?}", key)
}
