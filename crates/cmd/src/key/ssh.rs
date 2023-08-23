//! Create SSH key representations and perform actions on them.
use std::fs;
use std::path::Path;

use openssh_keys::{Curve, Data, PublicKey};
use wardstone_core::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::ecc::*;
use wardstone_core::primitive::ffc::*;
use wardstone_core::primitive::hash::*;
use wardstone_core::primitive::ifc::*;

use crate::key::{Error, Key};

/// Represents an SSH public key.
#[derive(Debug)]
pub struct Ssh {
  hash_function: Option<Hash>,
  signature_algorithm: Asymmetric,
}

impl Key for Ssh {
  fn from_file(path: &Path) -> Result<Self, Error> {
    let contents = fs::read_to_string(path)?;
    let key = PublicKey::parse(contents.as_str())?;

    // It is not possible to infer the hash function used by looking at
    // the public key for RSA keys. RFC 4253 Section 6.6 specifies SHA-1
    // but a newer revision RFC 8332 specifies SHA-256 and SHA-512
    // without changes to the format for backwards compatibility.
    //
    // Similarly, for NIST elliptic curves, RFC 5656 does not specify
    // the length of the output of the hash function used (just that it
    // should come from the SHA2 family). Given that this information
    // cannot be determined reliably, the signature algorithm is assumed
    // to not use a hash function.
    let (hash_function, signature_algorithm) = match key.data {
      Data::Rsa { .. } => (None, {
        let k = key.size() as u16;
        let ifc = match k {
          1024 => RSA_PKCS1_1024,
          1536 => RSA_PKCS1_1536,
          2048 => RSA_PSS_2048,
          3072 => RSA_PKCS1_3072,
          4096 => RSA_PKCS1_4096,
          7680 => RSA_PKCS1_7680,
          8192 => RSA_PKCS1_15360,
          _ => Ifc::new(ID_RSA_PKCS1, k),
        };
        ifc.into()
      }),
      Data::Dsa { ref p, q, .. } => (Some(SHA1), {
        let p = (p.len() * 8) as u16;
        let q = (q.len() * 8) as u16;
        let ffc = match p {
          1024 => DSA_1024_160,
          2048 => DSA_2048_256,
          3072 => DSA_3072_256,
          7680 => DSA_7680_384,
          15360 => DSA_15360_512,
          _ => Ffc::new(ID_DSA, p, q),
        };
        ffc.into()
      }),
      Data::Ed25519 { .. } | Data::Ed25519Sk { .. } => (None, ED25519.into()),
      Data::Ecdsa { ref curve, .. } | Data::EcdsaSk { ref curve, .. } => match *curve {
        Curve::Nistp256 => (None, P256.into()),
        Curve::Nistp384 => (None, P384.into()),
        Curve::Nistp521 => (None, P521.into()),
      },
    };

    let key = Self {
      hash_function,
      signature_algorithm,
    };
    Ok(key)
  }

  fn hash_function(&self) -> Option<Hash> {
    self.hash_function
  }

  fn signature_algorithm(&self) -> Asymmetric {
    self.signature_algorithm
  }
}
