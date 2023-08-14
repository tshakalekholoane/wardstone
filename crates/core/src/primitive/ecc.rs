//! Elliptic curve primitive and some common instances.
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result};

use once_cell::sync::Lazy;

use crate::primitive::{Primitive, Security};

/// Represents an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size (the size
/// of n, where n is the order of the base point G).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ecc {
  pub id: u16,
  pub f: u16,
}

impl Ecc {
  pub const fn new(id: u16, f: u16) -> Self {
    Self { id, f }
  }
}

// The name is kept in a lookup table instead of being embedded in the
// type because sharing strings across language boundaries is a bit
// dicey.
pub static REPR: Lazy<HashMap<Ecc, &str>> = Lazy::new(|| {
  let mut m = HashMap::new();
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

impl Display for Ecc {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    let unrecognised = "unrecognised";
    let name = REPR.get(self).unwrap_or(&unrecognised);
    write!(f, "{name}")
  }
}

impl Primitive for Ecc {
  /// Returns the security level of an elliptic curve key (which is
  /// approximately len(n)/2).
  fn security(&self) -> Security {
    self.f >> 1
  }
}

/// Represents the Weierstrass curve B-163 over a prime field. Also
/// known as sect163r2.
#[no_mangle]
pub static B163: Ecc = Ecc::new(1, 163);

/// Represents the Weierstrass curve B-223 over a prime field. Also
/// known as sect233r1 and wap-wsg-idm-ecid-wtls11.
#[no_mangle]
pub static B233: Ecc = Ecc::new(2, 233);

/// Represents the Weierstrass curve B-283 over a prime field. Also
/// known as sect283r1.
#[no_mangle]
pub static B283: Ecc = Ecc::new(3, 283);

/// Represents the Weierstrass curve B-409 over a prime field. Also
/// known as sect409r1.
#[no_mangle]
pub static B409: Ecc = Ecc::new(4, 409);

/// Represents the Weierstrass curve B-571 over a prime field. Also
/// known as sect571r1.
#[no_mangle]
pub static B571: Ecc = Ecc::new(5, 571);

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP160R1: Ecc = Ecc::new(6, 160);

/// Represents the curve brainpoolP160t1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP160T1: Ecc = Ecc::new(7, 160);

/// Represents the curve brainpoolP192r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP192R1: Ecc = Ecc::new(8, 192);

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP192T1: Ecc = Ecc::new(9, 192);

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224R1: Ecc = Ecc::new(10, 224);

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224T1: Ecc = Ecc::new(11, 224);

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256R1: Ecc = Ecc::new(12, 256);

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256T1: Ecc = Ecc::new(13, 256);

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320R1: Ecc = Ecc::new(14, 320);

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320T1: Ecc = Ecc::new(15, 320);

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384R1: Ecc = Ecc::new(16, 384);

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384T1: Ecc = Ecc::new(17, 384);

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512R1: Ecc = Ecc::new(18, 512);

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512T1: Ecc = Ecc::new(19, 512);

/// Represents the c2pnb163v1 curve as specified in ANSI x9.62. Also
/// known as wap-wsg-idm-ecid-wtls5.
#[no_mangle]
pub static C2PNB163V1: Ecc = Ecc::new(20, 163);

/// Represents the c2pnb163v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB163V2: Ecc = Ecc::new(21, 163);

/// Represents the c2pnb163v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB163V3: Ecc = Ecc::new(22, 163);

/// Represents the c2pnb176v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB176V1: Ecc = Ecc::new(23, 176);

/// Represents the c2pnb208w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB208W1: Ecc = Ecc::new(24, 208);

/// Represents the c2pnb272w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB272W1: Ecc = Ecc::new(25, 272);

/// Represents the c2pnb304w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB304W1: Ecc = Ecc::new(26, 304);

/// Represents the c2pnb368w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB368W1: Ecc = Ecc::new(27, 368);
/// Represents the c2tnb191v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V1: Ecc = Ecc::new(28, 191);

/// Represents the c2tnb191v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V2: Ecc = Ecc::new(29, 191);

/// Represents the c2tnb191v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V3: Ecc = Ecc::new(30, 191);

/// Represents the c2tnb239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V1: Ecc = Ecc::new(31, 239);

/// Represents the c2tnb239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V2: Ecc = Ecc::new(32, 239);

/// Represents the c2tnb239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V3: Ecc = Ecc::new(33, 239);

/// Represents the c2tnb359v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB359V1: Ecc = Ecc::new(34, 359);

/// Represents the c2tnb431r1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB431R1: Ecc = Ecc::new(35, 359);

/// Represents the Ed25519 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static ED25519: Ecc = Ecc::new(36, 256);

/// Represents the Ed448 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static ED448: Ecc = Ecc::new(37, 448);

/// Represents the Weierstrass curve K-163 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls3.
#[no_mangle]
pub static K163: Ecc = Ecc::new(38, 192);

/// Represents the Weierstrass curve K-223 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls10.
#[no_mangle]
pub static K233: Ecc = Ecc::new(39, 192);

/// Represents the Weierstrass curve K-283 over a prime field. Also
/// known as sect283k1.
#[no_mangle]
pub static K283: Ecc = Ecc::new(40, 192);

/// Represents the Weierstrass curve K-409 over a prime field.
#[no_mangle]
pub static K409: Ecc = Ecc::new(41, 409);

/// Represents the Weierstrass curve K-571 over a prime field.
#[no_mangle]
pub static K571: Ecc = Ecc::new(42, 571);

/// Represents the Weierstrass curve P-192 over a prime field. Also
/// known as prime192v1 and secp192r1.
#[no_mangle]
pub static P192: Ecc = Ecc::new(43, 192);

/// Represents the Weierstrass curve P-224 over a prime field. Also
/// known as secp224r1.
#[no_mangle]
pub static P224: Ecc = Ecc::new(44, 224);

/// Represents the Weierstrass curve P-256 over a prime field. Also
/// known as secp256r1.
#[no_mangle]
pub static P256: Ecc = Ecc::new(45, 256);

/// Represents the Weierstrass curve P-384 over a prime field. Also
/// known as secp384r1.
#[no_mangle]
pub static P384: Ecc = Ecc::new(46, 384);

/// Represents the Weierstrass curve P-521 over a prime field. Also
/// known as secp521r1.
#[no_mangle]
pub static P521: Ecc = Ecc::new(47, 521);

/// Represents the prime192v1 curve as specified in ANSI x9.62. Also
/// known as secp192r1 and P-192.
#[no_mangle]
pub static PRIME192V1: Ecc = Ecc::new(43 /* P192 */, 192);

/// Represents the prime192v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME192V2: Ecc = Ecc::new(48, 192);

/// Represents the prime192v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME192V3: Ecc = Ecc::new(49, 192);

/// Represents the prime239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V1: Ecc = Ecc::new(50, 239);

/// Represents the prime239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V2: Ecc = Ecc::new(51, 239);

/// Represents the prime239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V3: Ecc = Ecc::new(52, 239);

/// Represents the prime256v1 curve as specified in ANSI x9.62. Also
/// known as P-256 and secp256r1.
#[no_mangle]
pub static PRIME256V1: Ecc = Ecc::new(45, /* P256 */ 256);

/// Represents the secp112r1 curve as defined in [SEC 2]. Also known
/// as wap-wsg-idm-ecid-wtls6.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP112R1: Ecc = Ecc::new(53, 112);

/// Represents the secp112r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP112R2: Ecc = Ecc::new(54, 112);

/// Represents the secp128r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP128R1: Ecc = Ecc::new(55, 128);

/// Represents the secp128r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP128R2: Ecc = Ecc::new(56, 128);

/// Represents the secp160r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls7.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160R1: Ecc = Ecc::new(57, 160);

/// Represents the secp160k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160K1: Ecc = Ecc::new(58, 160);

/// Represents the secp160r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160R2: Ecc = Ecc::new(59, 160);

/// Represents the secp192r1 curve as defined in [SEC 2]. Also known as
/// prime192v1 and P-192.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP192R1: Ecc = Ecc::new(43, /* P192 */ 193);

/// Represents the secp192k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP192K1: Ecc = Ecc::new(60, 192);

/// Represents the secp224r1 curve as defined in [SEC 2]. Also known as
/// P-224 and wap-wsg-idm-ecid-wtls12.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP224R1: Ecc = Ecc::new(44, /* SECP224R1 */ 224);

/// Represents the secp224k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP224K1: Ecc = Ecc::new(61, 224);

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256K1: Ecc = Ecc::new(62, 256);

/// Represents the secp256r1 curve as defined in [SEC 2]. Also known as
/// prime256v1 and P-256.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256R1: Ecc = Ecc::new(45, /* P256 */ 256);

/// Represents the secp384r1 curve as defined in [SEC 2]. Also known as
/// P-384.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP384R1: Ecc = Ecc::new(46, /* P384 */ 384);

/// Represents the secp521r1 curve as defined in [SEC 2]. Also known as
/// P-521.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP521R1: Ecc = Ecc::new(47, /* P521 */ 521);

/// Represents the sect113r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls4.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT113R1: Ecc = Ecc::new(63, 113);

/// Represents the sect113r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT113R2: Ecc = Ecc::new(64, 113);

/// Represents the sect131r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT131R1: Ecc = Ecc::new(65, 131);

/// Represents the sect131r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT131R2: Ecc = Ecc::new(66, 131);

/// Represents the sect163k1 curve as defined in [SEC 2]. Also known as
/// K-163 and wap-wsg-idm-ecid-wtls3.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163K1: Ecc = Ecc::new(38, /* K163 */ 163);

/// Represents the sect163r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163R1: Ecc = Ecc::new(67, 163);

/// Represents the sect163r2 curve as defined in [SEC 2]. Also known as
/// B-163.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163R2: Ecc = Ecc::new(1, /* B163 */ 163);

/// Represents the sect193r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT193R1: Ecc = Ecc::new(68, 193);

/// Represents the sect193r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT193R2: Ecc = Ecc::new(69, 193);

/// Represents the sect233k1 curve as defined in [SEC 2]. Also known as
/// K-233 and wap-wsg-idm-ecid-wtls10.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT233K1: Ecc = Ecc::new(39, /* K233 */ 233);

/// Represents the sect233r1 curve as defined in [SEC 2]. Also known as
/// B-233 and wap-wsg-idm-ecid-wtls11.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT233R1: Ecc = Ecc::new(2, /* B233 */ 233);

/// Represents the sect239k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT239K1: Ecc = Ecc::new(70, 239);

/// Represents the sect283r1 curve as defined in [SEC 2]. Also known as
/// B-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT283R1: Ecc = Ecc::new(3, /* B283 */ 283);

/// Represents the sect283k1 curve as defined in [SEC 2]. Also known as
/// K-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT283K1: Ecc = Ecc::new(40, /* K283 */ 283);

/// Represents the sect409k1 curve as defined in [SEC 2]. Also known as
/// K-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT409K1: Ecc = Ecc::new(41, /* K409 */ 409);

/// Represents the sect409r1 curve as defined in [SEC 2]. Also known as
/// B-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT409R1: Ecc = Ecc::new(4, /* B409 */ 409);

/// Represents the sect571k1 curve as defined in [SEC 2]. Also known as
/// K-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT571K1: Ecc = Ecc::new(42, /* K571 */ 571);

/// Represents the sect571r1 curve as defined in [SEC 2]. Also known as
/// B-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT571R1: Ecc = Ecc::new(5, /* B571 */ 571);

/// Represents the SM2 digital signature algorithm as defined in
/// draft-shen-sm2-ecdsa-02.
///
/// [draft-shen-sm2-ecdsa-02]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02
#[no_mangle]
pub static SM2: Ecc = Ecc::new(71, 256);

/// Represents the wap-wsg-idm-ecid-wtls1 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS1: Ecc = Ecc::new(72, 113);

/// Represents the wap-wsg-idm-ecid-wtls3 curve as specified in
/// [WAP-WTLS curves]. Also known as sect163k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS3: Ecc = Ecc::new(38, /* K163 */ 163);

/// Represents the wap-wsg-idm-ecid-wtls4 curve as specified in
/// [WAP-WTLS curves]. Also known as sect113r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS4: Ecc = Ecc::new(63, /* SECT113R1 */ 113);

/// Represents the wap-wsg-idm-ecid-wtls5 curve as specified in
/// [WAP-WTLS curves]. Also known as c2pnb163v1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS5: Ecc = Ecc::new(30, /* C2PNB163V1 */ 163);

/// Represents the wap-wsg-idm-ecid-wtls6 curve as specified in
/// [WAP-WTLS curves]. Also known as secp112r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS6: Ecc = Ecc::new(53, /* SECP112R1 */ 112);

/// Represents the wap-wsg-idm-ecid-wtls7 curve as specified in
/// [WAP-WTLS curves]. Also known as secp160r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS7: Ecc = Ecc::new(57, /* SECP160R1 */ 160);

/// Represents the wap-wsg-idm-ecid-wtls8 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS8: Ecc = Ecc::new(73, 112);

/// Represents the wap-wsg-idm-ecid-wtls9 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS9: Ecc = Ecc::new(74, 160);

/// Represents the wap-wsg-idm-ecid-wtls10 curve as specified in
/// [WAP-WTLS curves]. Also known as K-233 and sect233k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS10: Ecc = Ecc::new(39, /* K233 */ 233);

/// Represents the wap-wsg-idm-ecid-wtls11 curve as specified in
/// [WAP-WTLS curves]. Also known as B-233 and sect233r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS11: Ecc = Ecc::new(2, /* B233 */ 233);

/// Represents the wap-wsg-idm-ecid-wtls12 curve as specified in
/// [WAP-WTLS curves]. Also known as P-224 and secp224r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS12: Ecc = Ecc::new(41, /* P224 */ 224);

/// Represents the X25519 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X25519: Ecc = Ecc::new(75, 256);

/// Represents the X448 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X448: Ecc = Ecc::new(76, 448);

/// Generic instance that represents a choice of f = 224 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_224: Ecc = Ecc::new(65531, 224);

/// Generic instance that represents a choice of f = 256 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_256: Ecc = Ecc::new(65532, 256);

/// Generic instance that represents a choice of f = 384 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_384: Ecc = Ecc::new(65533, 384);

/// Generic instance that represents a choice of f = 512 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_512: Ecc = Ecc::new(65534, 512);

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static ECC_NOT_SUPPORTED: Ecc = Ecc::new(u16::MAX, u16::MAX);
