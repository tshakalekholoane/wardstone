//! Bridge between types.
use core::fmt;
use std::collections::HashMap;

use once_cell::sync::Lazy;
use wardstone_core::primitive::ecc::*;
use wardstone_core::primitive::hash::*;
use wardstone_core::primitive::ifc::*;

pub static HASH_FUNCTIONS: Lazy<HashMap<&str, &Hash>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("sha256", &SHA256);
  m
});

pub static SIGNATURE_ALGORITHMS: Lazy<HashMap<&str, Asymmetric>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("SM2", Asymmetric::Ecc(&SM2));
  m.insert("brainpoolP160r1", Asymmetric::Ecc(&BRAINPOOLP160R1));
  m.insert("brainpoolP160t1", Asymmetric::Ecc(&BRAINPOOLP160T1));
  m.insert("brainpoolP192r1", Asymmetric::Ecc(&BRAINPOOLP192R1));
  m.insert("brainpoolP192t1", Asymmetric::Ecc(&BRAINPOOLP192T1));
  m.insert("brainpoolP224r1", Asymmetric::Ecc(&BRAINPOOLP224R1));
  m.insert("brainpoolP224t1", Asymmetric::Ecc(&BRAINPOOLP224T1));
  m.insert("brainpoolP256r1", Asymmetric::Ecc(&BRAINPOOLP256R1));
  m.insert("brainpoolP256t1", Asymmetric::Ecc(&BRAINPOOLP256T1));
  m.insert("brainpoolP320r1", Asymmetric::Ecc(&BRAINPOOLP320R1));
  m.insert("brainpoolP320t1", Asymmetric::Ecc(&BRAINPOOLP320T1));
  m.insert("brainpoolP384r1", Asymmetric::Ecc(&BRAINPOOLP384R1));
  m.insert("brainpoolP384t1", Asymmetric::Ecc(&BRAINPOOLP384T1));
  m.insert("brainpoolP512r1", Asymmetric::Ecc(&BRAINPOOLP512R1));
  m.insert("brainpoolP512t1", Asymmetric::Ecc(&BRAINPOOLP512T1));
  m.insert("c2pnb163v1", Asymmetric::Ecc(&C2PNB163V1));
  m.insert("c2pnb163v2", Asymmetric::Ecc(&C2PNB163V2));
  m.insert("c2pnb163v3", Asymmetric::Ecc(&C2PNB163V3));
  m.insert("c2pnb176v1", Asymmetric::Ecc(&C2PNB176V1));
  m.insert("c2pnb208w1", Asymmetric::Ecc(&C2PNB208W1));
  m.insert("c2pnb272w1", Asymmetric::Ecc(&C2PNB272W1));
  m.insert("c2pnb304w1", Asymmetric::Ecc(&C2PNB304W1));
  m.insert("c2pnb368w1", Asymmetric::Ecc(&C2PNB368W1));
  m.insert("c2tnb191v1", Asymmetric::Ecc(&C2TNB191V1));
  m.insert("c2tnb191v2", Asymmetric::Ecc(&C2TNB191V2));
  m.insert("c2tnb191v3", Asymmetric::Ecc(&C2TNB191V3));
  m.insert("c2tnb239v1", Asymmetric::Ecc(&C2TNB239V1));
  m.insert("c2tnb239v2", Asymmetric::Ecc(&C2TNB239V2));
  m.insert("c2tnb239v3", Asymmetric::Ecc(&C2TNB239V3));
  m.insert("c2tnb359v1", Asymmetric::Ecc(&C2TNB359V1));
  m.insert("c2tnb431r1", Asymmetric::Ecc(&C2TNB431R1));
  m.insert("ed25519", Asymmetric::Ecc(&ED25519));
  m.insert("ed448", Asymmetric::Ecc(&ED448));
  m.insert("prime192v1", Asymmetric::Ecc(&PRIME192V1));
  m.insert("prime192v2", Asymmetric::Ecc(&PRIME192V2));
  m.insert("prime192v3", Asymmetric::Ecc(&PRIME192V3));
  m.insert("prime239v1", Asymmetric::Ecc(&PRIME239V1));
  m.insert("prime239v2", Asymmetric::Ecc(&PRIME239V2));
  m.insert("prime239v3", Asymmetric::Ecc(&PRIME239V3));
  m.insert("prime256v1", Asymmetric::Ecc(&PRIME256V1));
  m.insert("secp112r1", Asymmetric::Ecc(&SECP112R1));
  m.insert("secp112r2", Asymmetric::Ecc(&SECP112R2));
  m.insert("secp128r1", Asymmetric::Ecc(&SECP128R1));
  m.insert("secp128r2", Asymmetric::Ecc(&SECP128R2));
  m.insert("secp160k1", Asymmetric::Ecc(&SECP160K1));
  m.insert("secp160r1", Asymmetric::Ecc(&SECP160R1));
  m.insert("secp160r2", Asymmetric::Ecc(&SECP160R2));
  m.insert("secp192k1", Asymmetric::Ecc(&SECP192K1));
  m.insert("secp224k1", Asymmetric::Ecc(&SECP224K1));
  m.insert("secp224r1", Asymmetric::Ecc(&SECP224R1));
  m.insert("secp256k1", Asymmetric::Ecc(&SECP256K1));
  m.insert("secp384r1", Asymmetric::Ecc(&SECP384R1));
  m.insert("secp521r1", Asymmetric::Ecc(&SECP521R1));
  m.insert("sect113r1", Asymmetric::Ecc(&SECT113R1));
  m.insert("sect113r2", Asymmetric::Ecc(&SECT113R2));
  m.insert("sect131r1", Asymmetric::Ecc(&SECT131R1));
  m.insert("sect131r2", Asymmetric::Ecc(&SECT131R2));
  m.insert("sect163k1", Asymmetric::Ecc(&SECT163K1));
  m.insert("sect163r1", Asymmetric::Ecc(&SECT163R1));
  m.insert("sect163r2", Asymmetric::Ecc(&SECT163R2));
  m.insert("sect193r1", Asymmetric::Ecc(&SECT193R1));
  m.insert("sect193r2", Asymmetric::Ecc(&SECT193R2));
  m.insert("sect233k1", Asymmetric::Ecc(&SECT233K1));
  m.insert("sect233r1", Asymmetric::Ecc(&SECT233R1));
  m.insert("sect239k1", Asymmetric::Ecc(&SECT239K1));
  m.insert("sect283k1", Asymmetric::Ecc(&SECT283K1));
  m.insert("sect283r1", Asymmetric::Ecc(&SECT283R1));
  m.insert("sect409k1", Asymmetric::Ecc(&SECT409K1));
  m.insert("sect409r1", Asymmetric::Ecc(&SECT409R1));
  m.insert("sect571k1", Asymmetric::Ecc(&SECT571K1));
  m.insert("sect571r1", Asymmetric::Ecc(&SECT571R1));
  m.insert(
    "wap-wsg-idm-ecid-wtls1",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS1),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls10",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS10),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls11",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS11),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls12",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS12),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls3",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS3),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls4",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS4),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls5",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS5),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls6",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS6),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls7",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS7),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls8",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS8),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls9",
    Asymmetric::Ecc(&WAP_WSG_IDM_ECID_WTLS9),
  );
  m
});

#[derive(Eq, Hash, PartialEq)]
pub enum Asymmetric<'a> {
  Ecc(&'a Ecc),
  Ifc(&'a Ifc),
}

impl fmt::Display for Asymmetric<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Asymmetric::Ecc(instance) => instance.fmt(f),
      Asymmetric::Ifc(instance) => instance.fmt(f),
    }
  }
}

impl From<&'static Ecc> for Asymmetric {
  fn from(ecc: &'static Ecc) -> Self {
    Self::Ecc(&ecc)
  }
}

impl From<&'static Ifc> for Asymmetric {
  fn from(ifc: &'static Ifc) -> Self {
    Self::Ifc(&ifc)
  }
}
