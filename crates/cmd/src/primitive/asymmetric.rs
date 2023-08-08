//! An asymmetric key primitive.
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result};

use bimap::BiMap;
use once_cell::sync::Lazy;
use wardstone_core::primitive::ecc::*;
use wardstone_core::primitive::ifc::*;

pub static ECC_REPR: Lazy<BiMap<Ecc, &str>> = Lazy::new(|| {
  let mut m = BiMap::new();
  m.insert(SM2, "SM2");
  m.insert(BRAINPOOLP160R1, "brainpoolP160r1");
  m.insert(BRAINPOOLP160T1, "brainpoolP160t1");
  m.insert(BRAINPOOLP192R1, "brainpoolP192r1");
  m.insert(BRAINPOOLP192T1, "brainpoolP192t1");
  m.insert(BRAINPOOLP224R1, "brainpoolP224r1");
  m.insert(BRAINPOOLP224T1, "brainpoolP224t1");
  m.insert(BRAINPOOLP256R1, "brainpoolP256r1");
  m.insert(BRAINPOOLP256T1, "brainpoolP256t1");
  m.insert(BRAINPOOLP320R1, "brainpoolP320r1");
  m.insert(BRAINPOOLP320T1, "brainpoolP320t1");
  m.insert(BRAINPOOLP384R1, "brainpoolP384r1");
  m.insert(BRAINPOOLP384T1, "brainpoolP384t1");
  m.insert(BRAINPOOLP512R1, "brainpoolP512r1");
  m.insert(BRAINPOOLP512T1, "brainpoolP512t1");
  m.insert(C2PNB163V1, "c2pnb163v1");
  m.insert(C2PNB163V2, "c2pnb163v2");
  m.insert(C2PNB163V3, "c2pnb163v3");
  m.insert(C2PNB176V1, "c2pnb176v1");
  m.insert(C2PNB208W1, "c2pnb208w1");
  m.insert(C2PNB272W1, "c2pnb272w1");
  m.insert(C2PNB304W1, "c2pnb304w1");
  m.insert(C2PNB368W1, "c2pnb368w1");
  m.insert(C2TNB191V1, "c2tnb191v1");
  m.insert(C2TNB191V2, "c2tnb191v2");
  m.insert(C2TNB191V3, "c2tnb191v3");
  m.insert(C2TNB239V1, "c2tnb239v1");
  m.insert(C2TNB239V2, "c2tnb239v2");
  m.insert(C2TNB239V3, "c2tnb239v3");
  m.insert(C2TNB359V1, "c2tnb359v1");
  m.insert(C2TNB431R1, "c2tnb431r1");
  m.insert(ED25519, "ed25519");
  m.insert(ED448, "ed448");
  m.insert(PRIME192V1, "prime192v1");
  m.insert(PRIME192V2, "prime192v2");
  m.insert(PRIME192V3, "prime192v3");
  m.insert(PRIME239V1, "prime239v1");
  m.insert(PRIME239V2, "prime239v2");
  m.insert(PRIME239V3, "prime239v3");
  m.insert(PRIME256V1, "prime256v1");
  m.insert(SECP112R1, "secp112r1");
  m.insert(SECP112R2, "secp112r2");
  m.insert(SECP128R1, "secp128r1");
  m.insert(SECP128R2, "secp128r2");
  m.insert(SECP160K1, "secp160k1");
  m.insert(SECP160R1, "secp160r1");
  m.insert(SECP160R2, "secp160r2");
  m.insert(SECP192K1, "secp192k1");
  m.insert(SECP224K1, "secp224k1");
  m.insert(SECP224R1, "secp224r1");
  m.insert(SECP256K1, "secp256k1");
  m.insert(SECP384R1, "secp384r1");
  m.insert(SECP521R1, "secp521r1");
  m.insert(SECT113R1, "sect113r1");
  m.insert(SECT113R2, "sect113r2");
  m.insert(SECT131R1, "sect131r1");
  m.insert(SECT131R2, "sect131r2");
  m.insert(SECT163K1, "sect163k1");
  m.insert(SECT163R1, "sect163r1");
  m.insert(SECT163R2, "sect163r2");
  m.insert(SECT193R1, "sect193r1");
  m.insert(SECT193R2, "sect193r2");
  m.insert(SECT233K1, "sect233k1");
  m.insert(SECT233R1, "sect233r1");
  m.insert(SECT239K1, "sect239k1");
  m.insert(SECT283K1, "sect283k1");
  m.insert(SECT283R1, "sect283r1");
  m.insert(SECT409K1, "sect409k1");
  m.insert(SECT409R1, "sect409r1");
  m.insert(SECT571K1, "sect571k1");
  m.insert(SECT571R1, "sect571r1");
  m.insert(WAP_WSG_IDM_ECID_WTLS1, "wap-wsg-idm-ecid-wtls1");
  m.insert(WAP_WSG_IDM_ECID_WTLS10, "wap-wsg-idm-ecid-wtls10");
  m.insert(WAP_WSG_IDM_ECID_WTLS11, "wap-wsg-idm-ecid-wtls11");
  m.insert(WAP_WSG_IDM_ECID_WTLS12, "wap-wsg-idm-ecid-wtls12");
  m.insert(WAP_WSG_IDM_ECID_WTLS3, "wap-wsg-idm-ecid-wtls3");
  m.insert(WAP_WSG_IDM_ECID_WTLS4, "wap-wsg-idm-ecid-wtls4");
  m.insert(WAP_WSG_IDM_ECID_WTLS5, "wap-wsg-idm-ecid-wtls5");
  m.insert(WAP_WSG_IDM_ECID_WTLS6, "wap-wsg-idm-ecid-wtls6");
  m.insert(WAP_WSG_IDM_ECID_WTLS7, "wap-wsg-idm-ecid-wtls7");
  m.insert(WAP_WSG_IDM_ECID_WTLS8, "wap-wsg-idm-ecid-wtls8");
  m.insert(WAP_WSG_IDM_ECID_WTLS9, "wap-wsg-idm-ecid-wtls9");
  m
});

pub static IFC_REPR: Lazy<HashMap<Ifc, &str>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert(IFC_2048, "rsa_2048");
  m
});

/// Represents an asymmetric key primitive.
///
/// The translation is done via a lookup tables that map OpenSSL string
/// representations and their equivalents in the core crate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Asymmetric {
  Ecc { algorithm: Ecc, name: String },
  Ifc { algorithm: Ifc, name: String },
}

impl Display for Asymmetric {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    match self {
      Asymmetric::Ecc { name, .. } => write!(f, "{name}"),
      Asymmetric::Ifc { name, .. } => write!(f, "{name}"),
    }
  }
}

impl From<&str> for Asymmetric {
  fn from(name: &str) -> Self {
    let algorithm = *ECC_REPR.get_by_right(&name).unwrap_or(&ECC_NOT_SUPPORTED);
    Self::Ecc {
      algorithm,
      name: name.to_string(),
    }
  }
}

impl From<Ecc> for Asymmetric {
  fn from(algorithm: Ecc) -> Self {
    let name = ECC_REPR.get_by_left(&algorithm).unwrap_or(&"UNRECOGNISED");
    Self::Ecc {
      algorithm,
      name: name.to_string(),
    }
  }
}

impl From<Ifc> for Asymmetric {
  fn from(algorithm: Ifc) -> Self {
    let name = IFC_REPR.get(&algorithm).unwrap_or(&"UNRECOGNISED");
    Self::Ifc {
      algorithm,
      name: name.to_string(),
    }
  }
}
