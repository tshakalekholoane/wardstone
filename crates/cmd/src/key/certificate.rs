//! Create X.509 certificate representations and perform actions on
//! them.
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use once_cell::sync::Lazy;
use openssl::x509::X509;
use wardstone_core::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::ecc::*;
use wardstone_core::primitive::hash::*;
use wardstone_core::primitive::ifc::*;
use x509_parser::pem;
use x509_parser::prelude::{FromDer, TbsCertificate, X509Certificate};

use crate::key::{Error, Key};

static ASYMMETRIC: Lazy<HashMap<&str, Asymmetric>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("1.2.840.10045.3.0.1", C2PNB163V1.into());
  m.insert("1.2.840.10045.3.0.10", C2PNB208W1.into());
  m.insert("1.2.840.10045.3.0.11", C2TNB239V1.into());
  m.insert("1.2.840.10045.3.0.12", C2TNB239V2.into());
  m.insert("1.2.840.10045.3.0.13", C2TNB239V3.into());
  m.insert("1.2.840.10045.3.0.16", C2PNB272W1.into());
  m.insert("1.2.840.10045.3.0.17", C2PNB304W1.into());
  m.insert("1.2.840.10045.3.0.18", C2TNB359V1.into());
  m.insert("1.2.840.10045.3.0.19", C2PNB368W1.into());
  m.insert("1.2.840.10045.3.0.2", C2PNB163V2.into());
  m.insert("1.2.840.10045.3.0.20", C2TNB431R1.into());
  m.insert("1.2.840.10045.3.0.3", C2PNB163V3.into());
  m.insert("1.2.840.10045.3.0.4", C2PNB176V1.into());
  m.insert("1.2.840.10045.3.0.5", C2TNB191V1.into());
  m.insert("1.2.840.10045.3.0.6", C2TNB191V2.into());
  m.insert("1.2.840.10045.3.0.7", C2TNB191V3.into());
  m.insert("1.2.840.10045.3.1.1", PRIME192V1.into());
  m.insert("1.2.840.10045.3.1.2", PRIME192V2.into());
  m.insert("1.2.840.10045.3.1.3", PRIME192V3.into());
  m.insert("1.2.840.10045.3.1.4", PRIME239V1.into());
  m.insert("1.2.840.10045.3.1.5", PRIME239V2.into());
  m.insert("1.2.840.10045.3.1.6", PRIME239V3.into());
  m.insert("1.2.840.10045.3.1.7", PRIME256V1.into());
  m.insert("1.3.132.0.1", SECT163K1.into());
  m.insert("1.3.132.0.10", SECP256K1.into());
  m.insert("1.3.132.0.15", SECT163R2.into());
  m.insert("1.3.132.0.16", SECT283K1.into());
  m.insert("1.3.132.0.17", SECT283R1.into());
  m.insert("1.3.132.0.2", SECT163R1.into());
  m.insert("1.3.132.0.22", SECT131R1.into());
  m.insert("1.3.132.0.23", SECT131R2.into());
  m.insert("1.3.132.0.24", SECT193R1.into());
  m.insert("1.3.132.0.25", SECT193R2.into());
  m.insert("1.3.132.0.26", SECT233K1.into());
  m.insert("1.3.132.0.27", SECT233R1.into());
  m.insert("1.3.132.0.28", SECP128R1.into());
  m.insert("1.3.132.0.29", SECP128R2.into());
  m.insert("1.3.132.0.3", SECT239K1.into());
  m.insert("1.3.132.0.30", SECP160R2.into());
  m.insert("1.3.132.0.31", SECP192K1.into());
  m.insert("1.3.132.0.32", SECP224K1.into());
  m.insert("1.3.132.0.33", SECP224R1.into());
  m.insert("1.3.132.0.34", SECP384R1.into());
  m.insert("1.3.132.0.35", SECP521R1.into());
  m.insert("1.3.132.0.36", SECT409K1.into());
  m.insert("1.3.132.0.37", SECT409R1.into());
  m.insert("1.3.132.0.38", SECT571K1.into());
  m.insert("1.3.132.0.39", SECT571R1.into());
  m.insert("1.3.132.0.4", SECT113R1.into());
  m.insert("1.3.132.0.5", SECT113R2.into());
  m.insert("1.3.132.0.6", SECP112R1.into());
  m.insert("1.3.132.0.7", SECP112R2.into());
  m.insert("1.3.132.0.8", SECP160R1.into());
  m.insert("1.3.132.0.9", SECP160K1.into());
  m.insert("1.3.36.3.3.2.8.1.1.1", BRAINPOOLP160R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.10", BRAINPOOLP320T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.11", BRAINPOOLP384R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.12", BRAINPOOLP384T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.13", BRAINPOOLP512R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.14", BRAINPOOLP512T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.2", BRAINPOOLP160T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.3", BRAINPOOLP192R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.4", BRAINPOOLP192T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.5", BRAINPOOLP224R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.6", BRAINPOOLP224T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.7", BRAINPOOLP256R1.into());
  m.insert("1.3.36.3.3.2.8.1.1.8", BRAINPOOLP256T1.into());
  m.insert("1.3.36.3.3.2.8.1.1.9", BRAINPOOLP320R1.into());
  m.insert("1.2.156.10197.1.301", SM2.into());
  m.insert("2.23.43.1.4.12", WAP_WSG_IDM_ECID_WTLS11.into());
  m.insert("2.23.43.1.4.1", WAP_WSG_IDM_ECID_WTLS1.into());
  m.insert("2.23.43.1.4.3", WAP_WSG_IDM_ECID_WTLS3.into());
  m.insert("2.23.43.1.4.4", WAP_WSG_IDM_ECID_WTLS4.into());
  m.insert("2.23.43.1.4.5", WAP_WSG_IDM_ECID_WTLS5.into());
  m.insert("2.23.43.1.4.6", WAP_WSG_IDM_ECID_WTLS6.into());
  m.insert("2.23.43.1.4.7", WAP_WSG_IDM_ECID_WTLS7.into());
  m.insert("2.23.43.1.4.8", WAP_WSG_IDM_ECID_WTLS8.into());
  m.insert("2.23.43.1.4.9", WAP_WSG_IDM_ECID_WTLS9.into());
  m.insert("2.23.43.1.4.10", WAP_WSG_IDM_ECID_WTLS10.into());
  m.insert("2.23.43.1.4.11", WAP_WSG_IDM_ECID_WTLS11.into());
  m.insert("2.23.43.1.4.12", WAP_WSG_IDM_ECID_WTLS12.into());
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

  fn edsa_with_sha(tbs_certificate: &TbsCertificate, sha: Hash) -> Result<Certificate, Error> {
    let hash_function = Some(sha);
    let parameters = tbs_certificate
      .subject_pki
      .algorithm
      .parameters
      .as_ref()
      .expect("elliptic curve should specify curve");
    let oid = parameters
      .clone()
      .oid()
      .expect("elliptic curve should have identifier")
      .to_id_string();
    let signature_algorithm = ASYMMETRIC
      .get(&oid.as_str())
      .cloned()
      .ok_or(Error::Unrecognised(oid))?;
    let certificate = Self {
      hash_function,
      signature_algorithm,
    };
    Ok(certificate)
  }

  fn id_ed25519() -> Result<Certificate, Error> {
    let certificate = Self {
      hash_function: None,
      signature_algorithm: ED25519.into(),
    };
    Ok(certificate)
  }

  fn id_ed448() -> Result<Certificate, Error> {
    let certificate = Self {
      hash_function: None,
      signature_algorithm: ED448.into(),
    };
    Ok(certificate)
  }

  fn rsassa_pss(data: &[u8]) -> Result<Certificate, Error> {
    // The x509_parser crate cannot seem to read rsassa-pss keys so
    // resort to openssl for that. But even that cannot seem to
    // extract the hash function so a lower level interface may be
    // required.
    let certificate = if Self::is_likely_pem(data) {
      X509::from_pem(data)?
    } else {
      X509::from_der(data)?
    };
    let public_key = certificate.public_key()?;
    let k = public_key.bits();
    let signature_algorithm = match k {
      1024 => RSA_PSS_1024.into(),
      1536 => RSA_PSS_1536.into(),
      2048 => RSA_PSS_2048.into(),
      3072 => RSA_PSS_3072.into(),
      4096 => RSA_PSS_4096.into(),
      7680 => RSA_PSS_7680.into(),
      8192 => RSA_PSS_8192.into(),
      15360 => RSA_PSS_15360.into(),
      _ => Ifc::new(ID_RSA_PSS, k as u16).into(),
    };
    let certificate = Self {
      hash_function: None,
      signature_algorithm,
    };
    Ok(certificate)
  }

  fn with_rsa_encryption(
    tbs_certificate: &TbsCertificate,
    sha: Hash,
  ) -> Result<Certificate, Error> {
    let hash_function = Some(sha);
    let k = tbs_certificate
      .subject_pki
      .parsed()
      .expect("should parse rsa public key")
      .key_size();
    let signature_algorithm = match k {
      1024 => RSA_PKCS1_1024.into(),
      1536 => RSA_PKCS1_1536.into(),
      2048 => RSA_PKCS1_2048.into(),
      3072 => RSA_PKCS1_3072.into(),
      4096 => RSA_PKCS1_4096.into(),
      7680 => RSA_PKCS1_7680.into(),
      8192 => RSA_PKCS1_8192.into(),
      15360 => RSA_PKCS1_15360.into(),
      _ => Ifc::new(ID_RSA_PKCS1, k as u16).into(),
    };
    let certificate = Self {
      hash_function,
      signature_algorithm,
    };
    Ok(certificate)
  }
}

impl Key for Certificate {
  fn from_file(path: &Path) -> Result<Certificate, Error> {
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
      "1.2.840.10045.4.1" => Self::edsa_with_sha(&tbs_certificate, SHA1),
      "1.2.840.10045.4.3.1" => Self::edsa_with_sha(&tbs_certificate, SHA224),
      "1.2.840.10045.4.3.2" => Self::edsa_with_sha(&tbs_certificate, SHA256),
      "1.2.840.10045.4.3.3" => Self::edsa_with_sha(&tbs_certificate, SHA384),
      "1.2.840.10045.4.3.4" => Self::edsa_with_sha(&tbs_certificate, SHA512),
      "1.2.840.113549.1.1.10" => Self::rsassa_pss(&data),
      "1.2.840.113549.1.1.11" => Self::with_rsa_encryption(&tbs_certificate, SHA256),
      "1.2.840.113549.1.1.12" => Self::with_rsa_encryption(&tbs_certificate, SHA384),
      "1.2.840.113549.1.1.13" => Self::with_rsa_encryption(&tbs_certificate, SHA512),
      "1.2.840.113549.1.1.14" => Self::with_rsa_encryption(&tbs_certificate, SHA224),
      "1.2.840.113549.1.1.15" => Self::with_rsa_encryption(&tbs_certificate, SHA512_224),
      "1.2.840.113549.1.1.16" => Self::with_rsa_encryption(&tbs_certificate, SHA512_256),
      "1.2.840.113549.1.1.3" => Self::with_rsa_encryption(&tbs_certificate, MD4),
      "1.2.840.113549.1.1.4" => Self::with_rsa_encryption(&tbs_certificate, MD5),
      "1.2.840.113549.1.1.5" => Self::with_rsa_encryption(&tbs_certificate, SHA1),
      "1.3.101.112" => Self::id_ed25519(),
      "1.3.101.113" => Self::id_ed448(),
      "2.16.840.1.101.3.4.3.10" => Self::edsa_with_sha(&tbs_certificate, SHA3_256),
      "2.16.840.1.101.3.4.3.11" => Self::edsa_with_sha(&tbs_certificate, SHA3_384),
      "2.16.840.1.101.3.4.3.12" => Self::edsa_with_sha(&tbs_certificate, SHA3_512),
      _ => Err(Error::Unrecognised(oid)),
    }
  }

  fn hash_function(&self) -> Option<Hash> {
    self.hash_function
  }

  fn signature_algorithm(&self) -> Asymmetric {
    self.signature_algorithm
  }
}
