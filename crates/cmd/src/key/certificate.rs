//! Create X.509 certificate representations and perform actions on
//! them.
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use once_cell::sync::Lazy;
use wardstone_core::primitive::ecc::*;
use wardstone_core::primitive::hash::*;
use x509_parser::pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::key::Error;
use crate::primitive::asymmetric::Asymmetric;

static ELLIPTIC_CURVES: Lazy<HashMap<String, Asymmetric>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("1.2.840.10045.3.0.1".to_string(), C2PNB163V1.into());
  m.insert("1.2.840.10045.3.0.10".to_string(), C2PNB208W1.into());
  m.insert("1.2.840.10045.3.0.11".to_string(), C2TNB239V1.into());
  m.insert("1.2.840.10045.3.0.12".to_string(), C2TNB239V2.into());
  m.insert("1.2.840.10045.3.0.13".to_string(), C2TNB239V3.into());
  m.insert("1.2.840.10045.3.0.16".to_string(), C2PNB272W1.into());
  m.insert("1.2.840.10045.3.0.17".to_string(), C2PNB304W1.into());
  m.insert("1.2.840.10045.3.0.18".to_string(), C2TNB359V1.into());
  m.insert("1.2.840.10045.3.0.19".to_string(), C2PNB368W1.into());
  m.insert("1.2.840.10045.3.0.2".to_string(), C2PNB163V2.into());
  m.insert("1.2.840.10045.3.0.20".to_string(), C2TNB431R1.into());
  m.insert("1.2.840.10045.3.0.3".to_string(), C2PNB163V3.into());
  m.insert("1.2.840.10045.3.0.4".to_string(), C2PNB176V1.into());
  m.insert("1.2.840.10045.3.0.5".to_string(), C2TNB191V1.into());
  m.insert("1.2.840.10045.3.0.6".to_string(), C2TNB191V2.into());
  m.insert("1.2.840.10045.3.0.7".to_string(), C2TNB191V3.into());
  m.insert("1.2.840.10045.3.1.1".to_string(), PRIME192V1.into());
  m.insert("1.2.840.10045.3.1.2".to_string(), PRIME192V2.into());
  m.insert("1.2.840.10045.3.1.3".to_string(), PRIME192V3.into());
  m.insert("1.2.840.10045.3.1.4".to_string(), PRIME239V1.into());
  m.insert("1.2.840.10045.3.1.5".to_string(), PRIME239V2.into());
  m.insert("1.2.840.10045.3.1.6".to_string(), PRIME239V3.into());
  m.insert("1.2.840.10045.3.1.7".to_string(), PRIME256V1.into());
  m.insert("1.3.132.0.1".to_string(), SECT163K1.into());
  m.insert("1.3.132.0.10".to_string(), SECP256K1.into());
  m.insert("1.3.132.0.15".to_string(), SECT163R2.into());
  m.insert("1.3.132.0.16".to_string(), SECT283K1.into());
  m.insert("1.3.132.0.17".to_string(), SECT283R1.into());
  m.insert("1.3.132.0.2".to_string(), SECT163R1.into());
  m.insert("1.3.132.0.22".to_string(), SECT131R1.into());
  m.insert("1.3.132.0.23".to_string(), SECT131R2.into());
  m.insert("1.3.132.0.24".to_string(), SECT193R1.into());
  m.insert("1.3.132.0.25".to_string(), SECT193R2.into());
  m.insert("1.3.132.0.26".to_string(), SECT233K1.into());
  m.insert("1.3.132.0.27".to_string(), SECT233R1.into());
  m.insert("1.3.132.0.28".to_string(), SECP128R1.into());
  m.insert("1.3.132.0.29".to_string(), SECP128R2.into());
  m.insert("1.3.132.0.3".to_string(), SECT239K1.into());
  m.insert("1.3.132.0.30".to_string(), SECP160R2.into());
  m.insert("1.3.132.0.31".to_string(), SECP192K1.into());
  m.insert("1.3.132.0.32".to_string(), SECP224K1.into());
  m.insert("1.3.132.0.33".to_string(), SECP224R1.into());
  m.insert("1.3.132.0.34".to_string(), SECP384R1.into());
  m.insert("1.3.132.0.35".to_string(), SECP521R1.into());
  m.insert("1.3.132.0.36".to_string(), SECT409K1.into());
  m.insert("1.3.132.0.37".to_string(), SECT409R1.into());
  m.insert("1.3.132.0.38".to_string(), SECT571K1.into());
  m.insert("1.3.132.0.39".to_string(), SECT571R1.into());
  m.insert("1.3.132.0.4".to_string(), SECT113R1.into());
  m.insert("1.3.132.0.5".to_string(), SECT113R2.into());
  m.insert("1.3.132.0.6".to_string(), SECP112R1.into());
  m.insert("1.3.132.0.7".to_string(), SECP112R2.into());
  m.insert("1.3.132.0.8".to_string(), SECP160R1.into());
  m.insert("1.3.132.0.9".to_string(), SECP160K1.into());
  m.insert("1.3.36.3.3.2.8.1.1.1".to_string(), BRAINPOOLP160R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.10".to_string(), BRAINPOOLP320T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.11".to_string(), BRAINPOOLP384R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.12".to_string(), BRAINPOOLP384T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.13".to_string(), BRAINPOOLP512R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.14".to_string(), BRAINPOOLP512T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.2".to_string(), BRAINPOOLP160T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.3".to_string(), BRAINPOOLP192R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.4".to_string(), BRAINPOOLP192T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.5".to_string(), BRAINPOOLP224R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.6".to_string(), BRAINPOOLP224T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.7".to_string(), BRAINPOOLP256R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.8".to_string(), BRAINPOOLP256T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.9".to_string(), BRAINPOOLP320R1.into());
  m.insert("1.2.156.10197.1.301".to_string(), SM2.into());
  m.insert("2.23.43.1.4.12".to_string(), WAP_WSG_IDM_ECID_WTLS11.into());
  m.insert("2.23.43.1.4.1".to_string(), WAP_WSG_IDM_ECID_WTLS1.into());
  m.insert("2.23.43.1.4.3".to_string(), WAP_WSG_IDM_ECID_WTLS3.into());
  m.insert("2.23.43.1.4.4".to_string(), WAP_WSG_IDM_ECID_WTLS4.into());
  m.insert("2.23.43.1.4.5".to_string(), WAP_WSG_IDM_ECID_WTLS5.into());
  m.insert("2.23.43.1.4.6".to_string(), WAP_WSG_IDM_ECID_WTLS6.into());
  m.insert("2.23.43.1.4.7".to_string(), WAP_WSG_IDM_ECID_WTLS7.into());
  m.insert("2.23.43.1.4.8".to_string(), WAP_WSG_IDM_ECID_WTLS8.into());
  m.insert("2.23.43.1.4.9".to_string(), WAP_WSG_IDM_ECID_WTLS9.into());
  m.insert("2.23.43.1.4.10".to_string(), WAP_WSG_IDM_ECID_WTLS10.into());
  m.insert("2.23.43.1.4.11".to_string(), WAP_WSG_IDM_ECID_WTLS11.into());
  m.insert("2.23.43.1.4.12".to_string(), WAP_WSG_IDM_ECID_WTLS12.into());
  m
});

/// Represents a TLS certificate.
#[derive(Debug)]
pub struct Certificate {
  hash_function: Option<Hash>,
  signature_algorithm: Asymmetric,
}

impl Certificate {
  fn is_likely_pem(data: &[u8]) -> bool {
    !matches!((data[0], data[1]), (0x30, 0x81..=0x83))
  }

  pub fn hash_function(&self) -> Option<Hash> {
    self.hash_function
  }

  pub fn signature_algorithm(&self) -> Asymmetric {
    self.signature_algorithm
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
        let hash_function = Some(SHA256);
        let parameters = tbs_certificate
          .subject_pki
          .algorithm
          .parameters
          .expect("elliptic curve should specify curve");
        let oid = parameters.oid().expect("elliptic curve should have identifier").to_id_string();
        let signature_algorithm = ELLIPTIC_CURVES.get(&oid).cloned().ok_or(Error::Unrecognised(oid))?;
        Ok(Self { hash_function, signature_algorithm })
      },
      _ => Err(Error::Unrecognised(oid)),
    }
  }
}
