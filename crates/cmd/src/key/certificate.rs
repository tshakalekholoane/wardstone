//! Create X.509 certificate representations and perform actions on
//! them.
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use once_cell::sync::Lazy;
use wardstone_core::primitive::ecc::{BRAINPOOLP160R1, ED25519, ED448};
use wardstone_core::primitive::hash::SHA256;
use x509_parser::pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::key::Error;
use crate::primitive::asymmetric::Asymmetric;
use crate::primitive::hash_func::HashFunc;

static ELLIPTIC_CURVES: Lazy<HashMap<String, Asymmetric>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("1.3.36.3.3.2.8.1.1.1".to_string(), BRAINPOOLP160R1.into());
  m
});

/// Represents a TLS certificate.
#[derive(Debug)]
pub struct Certificate {
  hash_function: Option<HashFunc>,
  signature_algorithm: Asymmetric,
}

impl Certificate {
  fn is_likely_pem(data: &[u8]) -> bool {
    !matches!((data[0], data[1]), (0x30, 0x81..=0x83))
  }

  pub fn hash_function(&self) -> &Option<HashFunc> {
    &self.hash_function
  }

  pub fn signature_algorithm(&self) -> &Asymmetric {
    &self.signature_algorithm
  }

  pub fn from_file(path: &PathBuf) -> Result<Certificate, Error> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Certificates do not own their data.
    let pem;
    let tbs_certificate = if Self::is_likely_pem(&data) {
      (_, pem) = pem::parse_x509_pem(&data)?;
      let x509_certificate = pem.parse_x509()?;
      x509_certificate.tbs_certificate
    } else {
      let (_, x509_certificate) = X509Certificate::from_der(&data)?;
      x509_certificate.tbs_certificate
    };

    let oid = tbs_certificate.signature.oid().to_id_string();
    match oid.as_str() {
      "1.3.101.112" /* id-Ed25519(112) or id-EdDSA25519 */=> Ok(Self {
        hash_function: None,
        signature_algorithm: ED25519.into(),
      }),
      "1.3.101.113" /* id-Ed448(113) or id-EdDSA448 */ => Ok(Self {
        hash_function: None,
        signature_algorithm: ED448.into(),
      }),
      "1.2.840.10045.4.3.2" /* edsa-with-SHA256(2) */ => {
        let hash_function = Some(SHA256.into());
        let parameters = tbs_certificate
          .subject_pki
          .algorithm
          .parameters
          .expect("elliptic curve should specify curve");
        let oid = parameters.oid().expect("elliptic curve should have identifier").to_id_string();
        let signature_algorithm = ELLIPTIC_CURVES.get(&oid).cloned().ok_or(Error::Unrecognised(oid))?;
        Ok(Self { hash_function, signature_algorithm })
      },
      _ => todo!()
    }
  }
}
