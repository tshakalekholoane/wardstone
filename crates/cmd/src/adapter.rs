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

pub static SIGNATURE_ALGORITHMS: Lazy<HashMap<&str, SignatureAlgorithm>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert("SM2", SignatureAlgorithm::Ecc(&SM2));
  m.insert("brainpoolP160r1", SignatureAlgorithm::Ecc(&BRAINPOOLP160R1));
  m.insert("brainpoolP160t1", SignatureAlgorithm::Ecc(&BRAINPOOLP160T1));
  m.insert("brainpoolP192r1", SignatureAlgorithm::Ecc(&BRAINPOOLP192R1));
  m.insert("brainpoolP192t1", SignatureAlgorithm::Ecc(&BRAINPOOLP192T1));
  m.insert("brainpoolP224r1", SignatureAlgorithm::Ecc(&BRAINPOOLP224R1));
  m.insert("brainpoolP224t1", SignatureAlgorithm::Ecc(&BRAINPOOLP224T1));
  m.insert("brainpoolP256r1", SignatureAlgorithm::Ecc(&BRAINPOOLP256R1));
  m.insert("brainpoolP256t1", SignatureAlgorithm::Ecc(&BRAINPOOLP256T1));
  m.insert("brainpoolP320r1", SignatureAlgorithm::Ecc(&BRAINPOOLP320R1));
  m.insert("brainpoolP320t1", SignatureAlgorithm::Ecc(&BRAINPOOLP320T1));
  m.insert("brainpoolP384r1", SignatureAlgorithm::Ecc(&BRAINPOOLP384R1));
  m.insert("brainpoolP384t1", SignatureAlgorithm::Ecc(&BRAINPOOLP384T1));
  m.insert("brainpoolP512r1", SignatureAlgorithm::Ecc(&BRAINPOOLP512R1));
  m.insert("brainpoolP512t1", SignatureAlgorithm::Ecc(&BRAINPOOLP512T1));
  m.insert("c2pnb163v1", SignatureAlgorithm::Ecc(&C2PNB163V1));
  m.insert("c2pnb163v2", SignatureAlgorithm::Ecc(&C2PNB163V2));
  m.insert("c2pnb163v3", SignatureAlgorithm::Ecc(&C2PNB163V3));
  m.insert("c2pnb176v1", SignatureAlgorithm::Ecc(&C2PNB176V1));
  m.insert("c2pnb208w1", SignatureAlgorithm::Ecc(&C2PNB208W1));
  m.insert("c2pnb272w1", SignatureAlgorithm::Ecc(&C2PNB272W1));
  m.insert("c2pnb304w1", SignatureAlgorithm::Ecc(&C2PNB304W1));
  m.insert("c2pnb368w1", SignatureAlgorithm::Ecc(&C2PNB368W1));
  m.insert("c2tnb191v1", SignatureAlgorithm::Ecc(&C2TNB191V1));
  m.insert("c2tnb191v2", SignatureAlgorithm::Ecc(&C2TNB191V2));
  m.insert("c2tnb191v3", SignatureAlgorithm::Ecc(&C2TNB191V3));
  m.insert("c2tnb239v1", SignatureAlgorithm::Ecc(&C2TNB239V1));
  m.insert("c2tnb239v2", SignatureAlgorithm::Ecc(&C2TNB239V2));
  m.insert("c2tnb239v3", SignatureAlgorithm::Ecc(&C2TNB239V3));
  m.insert("c2tnb359v1", SignatureAlgorithm::Ecc(&C2TNB359V1));
  m.insert("c2tnb431r1", SignatureAlgorithm::Ecc(&C2TNB431R1));
  m.insert("ed25519", SignatureAlgorithm::Ecc(&ED25519));
  m.insert("ed448", SignatureAlgorithm::Ecc(&ED448));
  m.insert("prime192v1", SignatureAlgorithm::Ecc(&PRIME192V1));
  m.insert("prime192v2", SignatureAlgorithm::Ecc(&PRIME192V2));
  m.insert("prime192v3", SignatureAlgorithm::Ecc(&PRIME192V3));
  m.insert("prime239v1", SignatureAlgorithm::Ecc(&PRIME239V1));
  m.insert("prime239v2", SignatureAlgorithm::Ecc(&PRIME239V2));
  m.insert("prime239v3", SignatureAlgorithm::Ecc(&PRIME239V3));
  m.insert("prime256v1", SignatureAlgorithm::Ecc(&PRIME256V1));
  m.insert("secp112r1", SignatureAlgorithm::Ecc(&SECP112R1));
  m.insert("secp112r2", SignatureAlgorithm::Ecc(&SECP112R2));
  m.insert("secp128r1", SignatureAlgorithm::Ecc(&SECP128R1));
  m.insert("secp128r2", SignatureAlgorithm::Ecc(&SECP128R2));
  m.insert("secp160k1", SignatureAlgorithm::Ecc(&SECP160K1));
  m.insert("secp160r1", SignatureAlgorithm::Ecc(&SECP160R1));
  m.insert("secp160r2", SignatureAlgorithm::Ecc(&SECP160R2));
  m.insert("secp192k1", SignatureAlgorithm::Ecc(&SECP192K1));
  m.insert("secp224k1", SignatureAlgorithm::Ecc(&SECP224K1));
  m.insert("secp224r1", SignatureAlgorithm::Ecc(&SECP224R1));
  m.insert("secp256k1", SignatureAlgorithm::Ecc(&SECP256K1));
  m.insert("secp384r1", SignatureAlgorithm::Ecc(&SECP384R1));
  m.insert("secp521r1", SignatureAlgorithm::Ecc(&SECP521R1));
  m.insert("sect113r1", SignatureAlgorithm::Ecc(&SECT113R1));
  m.insert("sect113r2", SignatureAlgorithm::Ecc(&SECT113R2));
  m.insert("sect131r1", SignatureAlgorithm::Ecc(&SECT131R1));
  m.insert("sect131r2", SignatureAlgorithm::Ecc(&SECT131R2));
  m.insert("sect163k1", SignatureAlgorithm::Ecc(&SECT163K1));
  m.insert("sect163r1", SignatureAlgorithm::Ecc(&SECT163R1));
  m.insert("sect163r2", SignatureAlgorithm::Ecc(&SECT163R2));
  m.insert("sect193r1", SignatureAlgorithm::Ecc(&SECT193R1));
  m.insert("sect193r2", SignatureAlgorithm::Ecc(&SECT193R2));
  m.insert("sect233k1", SignatureAlgorithm::Ecc(&SECT233K1));
  m.insert("sect233r1", SignatureAlgorithm::Ecc(&SECT233R1));
  m.insert("sect239k1", SignatureAlgorithm::Ecc(&SECT239K1));
  m.insert("sect283k1", SignatureAlgorithm::Ecc(&SECT283K1));
  m.insert("sect283r1", SignatureAlgorithm::Ecc(&SECT283R1));
  m.insert("sect409k1", SignatureAlgorithm::Ecc(&SECT409K1));
  m.insert("sect409r1", SignatureAlgorithm::Ecc(&SECT409R1));
  m.insert("sect571k1", SignatureAlgorithm::Ecc(&SECT571K1));
  m.insert("sect571r1", SignatureAlgorithm::Ecc(&SECT571R1));
  m.insert(
    "wap-wsg-idm-ecid-wtls1",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS1),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls10",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS10),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls11",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS11),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls12",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS12),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls3",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS3),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls4",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS4),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls5",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS5),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls6",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS6),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls7",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS7),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls8",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS8),
  );
  m.insert(
    "wap-wsg-idm-ecid-wtls9",
    SignatureAlgorithm::Ecc(&WAP_WSG_IDM_ECID_WTLS9),
  );
  m
});

#[derive(Eq, Hash, PartialEq)]
pub enum SignatureAlgorithm {
  Ecc(&'static Ecc),
  Ifc(&'static Ifc),
}

impl fmt::Display for SignatureAlgorithm {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      SignatureAlgorithm::Ecc(instance) => instance.fmt(f),
      SignatureAlgorithm::Ifc(instance) => instance.fmt(f),
    }
  }
}
