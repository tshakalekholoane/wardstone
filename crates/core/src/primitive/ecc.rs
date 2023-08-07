//! Elliptic curve primitive and some common instances.
use core::fmt;
use std::ffi::CStr;
use std::hash::{Hash, Hasher};

use crate::primitive::{Primitive, Security};

/// Represents an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size (the size
/// of n, where n is the order of the base point G).
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Ecc {
  pub id: u16,
  pub f: u16,
  pub name: &'static CStr,
}

impl Ecc {
  pub const fn new(id: u16, f: u16, name: &'static [u8]) -> Self {
    Self {
      id,
      f,
      name: unsafe { CStr::from_bytes_with_nul_unchecked(name) },
    }
  }
}

impl Hash for Ecc {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.id.hash(state);
    self.f.hash(state);
  }
}

impl Primitive for Ecc {
  /// Returns the security level of an elliptic curve key (which is
  /// approximately len(n)/2).
  fn security(&self) -> Security {
    self.f >> 1
  }
}

impl fmt::Display for Ecc {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.name.to_string_lossy())
  }
}

impl PartialEq for Ecc {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id && self.f == other.f
  }
}

impl Eq for Ecc {}

/// Represents the Weierstrass curve B-163 over a prime field. Also
/// known as sect163r2.
#[no_mangle]
pub static B163: Ecc = Ecc::new(1, 163, b"nistb163\0");

/// Represents the Weierstrass curve B-223 over a prime field. Also
/// known as sect233r1 and wap-wsg-idm-ecid-wtls11.
#[no_mangle]
pub static B233: Ecc = Ecc::new(2, 233, b"nistb223\0");

/// Represents the Weierstrass curve B-283 over a prime field. Also
/// known as sect283r1.
#[no_mangle]
pub static B283: Ecc = Ecc::new(3, 283, b"nistb283\0");

/// Represents the Weierstrass curve B-409 over a prime field. Also
/// known as sect409r1.
#[no_mangle]
pub static B409: Ecc = Ecc::new(4, 409, b"nistb409\0");

/// Represents the Weierstrass curve B-571 over a prime field. Also
/// known as sect571r1.
#[no_mangle]
pub static B571: Ecc = Ecc::new(5, 571, b"nistb571\0");

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP160R1: Ecc = Ecc::new(6, 160, b"brainpoolP160r1\0");

/// Represents the curve brainpoolP160t1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP160T1: Ecc = Ecc::new(7, 160, b"brainpoolP160t1\0");

/// Represents the curve brainpoolP192r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP192R1: Ecc = Ecc::new(8, 192, b"brainpoolP192r1\0");

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP192T1: Ecc = Ecc::new(9, 192, b"brainpoolP192t1\0");

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224R1: Ecc = Ecc::new(10, 224, b"brainpoolP224r1\0");

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224T1: Ecc = Ecc::new(11, 224, b"brainpoolP224t1\0");

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256R1: Ecc = Ecc::new(12, 256, b"brainpoolP256r1\0");

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256T1: Ecc = Ecc::new(13, 256, b"brainpoolP256t1\0");

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320R1: Ecc = Ecc::new(14, 320, b"brainpoolP320r1\0");

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320T1: Ecc = Ecc::new(15, 320, b"brainpoolP320t1\0");

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384R1: Ecc = Ecc::new(16, 384, b"brainpoolP384r1\0");

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384T1: Ecc = Ecc::new(17, 384, b"brainpoolP384t1\0");

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512R1: Ecc = Ecc::new(18, 512, b"brainpoolP512r1\0");

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512T1: Ecc = Ecc::new(19, 512, b"brainpoolp512t1\0");

/// Represents the c2pnb163v1 curve as specified in ANSI x9.62. Also
/// known as wap-wsg-idm-ecid-wtls5.
#[no_mangle]
pub static C2PNB163V1: Ecc = Ecc::new(20, 163, b"c2pnb163v1\0");

/// Represents the c2pnb163v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB163V2: Ecc = Ecc::new(21, 163, b"c2pnb163v2\0");

/// Represents the c2pnb163v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB163V3: Ecc = Ecc::new(22, 163, b"c2pnb163v3\0");

/// Represents the c2pnb176v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB176V1: Ecc = Ecc::new(23, 176, b"c2pnb176v1\0");

/// Represents the c2pnb208w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB208W1: Ecc = Ecc::new(24, 208, b"c2pnb208w1\0");

/// Represents the c2pnb272w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB272W1: Ecc = Ecc::new(25, 272, b"c2pnb272w1\0");

/// Represents the c2pnb304w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB304W1: Ecc = Ecc::new(26, 304, b"c2pnb304w1\0");

/// Represents the c2pnb368w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB368W1: Ecc = Ecc::new(27, 368, b"c2pnb368w1\0");
/// Represents the c2tnb191v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V1: Ecc = Ecc::new(28, 191, b"c2tnb191v1\0");

/// Represents the c2tnb191v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V2: Ecc = Ecc::new(29, 191, b"c2tnb191v2\0");

/// Represents the c2tnb191v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V3: Ecc = Ecc::new(30, 191, b"c2tnb191v3\0");

/// Represents the c2tnb239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V1: Ecc = Ecc::new(31, 239, b"c2tnb239v1\0");

/// Represents the c2tnb239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V2: Ecc = Ecc::new(32, 239, b"c2tnb239v2\0");

/// Represents the c2tnb239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V3: Ecc = Ecc::new(33, 239, b"c2tnb239v3\0");

/// Represents the c2tnb359v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB359V1: Ecc = Ecc::new(34, 359, b"c2tnb359v1\0");

/// Represents the c2tnb431r1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB431R1: Ecc = Ecc::new(35, 359, b"c2tnb431r1\0");

/// Represents the Ed25519 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static ED25519: Ecc = Ecc::new(36, 256, b"ed25519\0");

/// Represents the Ed448 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static ED448: Ecc = Ecc::new(37, 448, b"ed448\0");

/// Represents the Weierstrass curve K-163 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls3.
#[no_mangle]
pub static K163: Ecc = Ecc::new(38, 192, b"nistk163\0");

/// Represents the Weierstrass curve K-223 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls10.
#[no_mangle]
pub static K233: Ecc = Ecc::new(39, 192, b"nistk233\0");

/// Represents the Weierstrass curve K-283 over a prime field. Also
/// known as sect283k1.
#[no_mangle]
pub static K283: Ecc = Ecc::new(40, 192, b"nistk283\0");

/// Represents the Weierstrass curve K-409 over a prime field.
#[no_mangle]
pub static K409: Ecc = Ecc::new(41, 409, b"nistk409\0");

/// Represents the Weierstrass curve K-571 over a prime field.
#[no_mangle]
pub static K571: Ecc = Ecc::new(42, 571, b"nistk571\0");

/// Represents the Weierstrass curve P-192 over a prime field. Also
/// known as prime192v1 and secp192r1.
#[no_mangle]
pub static P192: Ecc = Ecc::new(43, 192, b"nistp192\0");

/// Represents the Weierstrass curve P-224 over a prime field. Also
/// known as secp224r1.
#[no_mangle]
pub static P224: Ecc = Ecc::new(44, 224, b"nistp224\0");

/// Represents the Weierstrass curve P-256 over a prime field. Also
/// known as secp256r1.
#[no_mangle]
pub static P256: Ecc = Ecc::new(45, 256, b"nistp256\0");

/// Represents the Weierstrass curve P-384 over a prime field. Also
/// known as secp384r1.
#[no_mangle]
pub static P384: Ecc = Ecc::new(46, 384, b"nistp384\0");

/// Represents the Weierstrass curve P-521 over a prime field. Also
/// known as secp521r1.
#[no_mangle]
pub static P521: Ecc = Ecc::new(47, 521, b"nistp521\0");

/// Represents the prime192v1 curve as specified in ANSI x9.62. Also
/// known as secp192r1 and P-192.
#[no_mangle]
pub static PRIME192V1: Ecc = Ecc::new(43 /* P192 */, 192, b"prime192v1\0");

/// Represents the prime192v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME192V2: Ecc = Ecc::new(48, 192, b"prime192v2\0");

/// Represents the prime192v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME192V3: Ecc = Ecc::new(49, 192, b"prime192v3\0");

/// Represents the prime239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V1: Ecc = Ecc::new(50, 239, b"prime239v1\0");

/// Represents the prime239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V2: Ecc = Ecc::new(51, 239, b"prime239v2\0");

/// Represents the prime239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V3: Ecc = Ecc::new(52, 239, b"prime239v3\0");

/// Represents the prime256v1 curve as specified in ANSI x9.62. Also
/// known as P-256 and secp256r1.
#[no_mangle]
pub static PRIME256V1: Ecc = Ecc::new(45, /* P256 */ 256, b"prime256v1\0");

/// Represents the secp112r1 curve as defined in [SEC 2]. Also known
/// as wap-wsg-idm-ecid-wtls6.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP112R1: Ecc = Ecc::new(53, 112, b"secp112r1\0");

/// Represents the secp112r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP112R2: Ecc = Ecc::new(54, 112, b"secp112r2\0");

/// Represents the secp128r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP128R1: Ecc = Ecc::new(55, 128, b"secp128r1\0");

/// Represents the secp128r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP128R2: Ecc = Ecc::new(56, 128, b"secp128r2\0");

/// Represents the secp160r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls7.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160R1: Ecc = Ecc::new(57, 160, b"secp160r1\0");

/// Represents the secp160k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160K1: Ecc = Ecc::new(58, 160, b"secp160k1\0");

/// Represents the secp160r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160R2: Ecc = Ecc::new(59, 160, b"secp160r2\0");

/// Represents the secp192r1 curve as defined in [SEC 2]. Also known as
/// prime192v1 and P-192.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP192R1: Ecc = Ecc::new(43, /* P192 */ 193, b"secp192r1\0");

/// Represents the secp192k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP192K1: Ecc = Ecc::new(60, 192, b"secp192k1\0");

/// Represents the secp224r1 curve as defined in [SEC 2]. Also known as
/// P-224 and wap-wsg-idm-ecid-wtls12.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP224R1: Ecc = Ecc::new(44, /* SECP224R1 */ 224, b"secp224r1\0");

/// Represents the secp224k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP224K1: Ecc = Ecc::new(61, 224, b"secp224k1\0");

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256K1: Ecc = Ecc::new(62, 256, b"secp256k1\0");

/// Represents the secp256r1 curve as defined in [SEC 2]. Also known as
/// prime256v1 and P-256.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256R1: Ecc = Ecc::new(45, /* P256 */ 256, b"secp256r1\0");

/// Represents the secp384r1 curve as defined in [SEC 2]. Also known as
/// P-384.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP384R1: Ecc = Ecc::new(46, /* P384 */ 384, b"secp384r1\0");

/// Represents the secp521r1 curve as defined in [SEC 2]. Also known as
/// P-521.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP521R1: Ecc = Ecc::new(47, /* P521 */ 521, b"secp521r1\0");

/// Represents the sect113r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls4.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT113R1: Ecc = Ecc::new(63, 113, b"sect113r1\0");

/// Represents the sect113r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT113R2: Ecc = Ecc::new(64, 113, b"sect113r2\0");

/// Represents the sect131r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT131R1: Ecc = Ecc::new(65, 131, b"sect131r1\0");

/// Represents the sect131r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT131R2: Ecc = Ecc::new(66, 131, b"sect131r2\0");

/// Represents the sect163k1 curve as defined in [SEC 2]. Also known as
/// K-163 and wap-wsg-idm-ecid-wtls3.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163K1: Ecc = Ecc::new(38, /* K163 */ 163, b"sect163k1\0");

/// Represents the sect163r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163R1: Ecc = Ecc::new(67, 163, b"sect163r1\0");

/// Represents the sect163r2 curve as defined in [SEC 2]. Also known as
/// B-163.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163R2: Ecc = Ecc::new(1, /* B163 */ 163, b"sect163r2\0");

/// Represents the sect193r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT193R1: Ecc = Ecc::new(68, 193, b"sect193r1\0");

/// Represents the sect193r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT193R2: Ecc = Ecc::new(69, 193, b"sect193r2\0");

/// Represents the sect233k1 curve as defined in [SEC 2]. Also known as
/// K-233 and wap-wsg-idm-ecid-wtls10.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT233K1: Ecc = Ecc::new(39, /* K233 */ 233, b"sect233k1\0");

/// Represents the sect233r1 curve as defined in [SEC 2]. Also known as
/// B-233 and wap-wsg-idm-ecid-wtls11.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT233R1: Ecc = Ecc::new(2, /* B233 */ 233, b"sect233r1\0");

/// Represents the sect239k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT239K1: Ecc = Ecc::new(70, 239, b"sect239k1\0");

/// Represents the sect283r1 curve as defined in [SEC 2]. Also known as
/// B-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT283R1: Ecc = Ecc::new(3, /* B283 */ 283, b"sect283r1\0");

/// Represents the sect283k1 curve as defined in [SEC 2]. Also known as
/// K-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT283K1: Ecc = Ecc::new(40, /* K283 */ 283, b"sect283k1\0");

/// Represents the sect409k1 curve as defined in [SEC 2]. Also known as
/// K-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT409K1: Ecc = Ecc::new(41, /* K409 */ 409, b"sect409k1\0");

/// Represents the sect409r1 curve as defined in [SEC 2]. Also known as
/// B-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT409R1: Ecc = Ecc::new(4, /* B409 */ 409, b"sect409r1\0");

/// Represents the sect571k1 curve as defined in [SEC 2]. Also known as
/// K-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT571K1: Ecc = Ecc::new(42, /* K571 */ 571, b"sect571k1\0");

/// Represents the sect571r1 curve as defined in [SEC 2]. Also known as
/// B-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT571R1: Ecc = Ecc::new(5, /* B571 */ 571, b"sect571r1\0");

/// Represents the SM2 digital signature algorithm as defined in
/// draft-shen-sm2-ecdsa-02.
///
/// [draft-shen-sm2-ecdsa-02]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02
#[no_mangle]
pub static SM2: Ecc = Ecc::new(71, 256, b"SM2\0");

/// Represents the wap-wsg-idm-ecid-wtls1 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS1: Ecc = Ecc::new(72, 113, b"wap-wsg-idm-ecid-wtls1\0");

/// Represents the wap-wsg-idm-ecid-wtls3 curve as specified in
/// [WAP-WTLS curves]. Also known as sect163k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS3: Ecc =
  Ecc::new(38, /* K163 */ 163, b"wap-wsg-idm-ecid-wtls3\0");

/// Represents the wap-wsg-idm-ecid-wtls4 curve as specified in
/// [WAP-WTLS curves]. Also known as sect113r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS4: Ecc =
  Ecc::new(63, /* SECT113R1 */ 113, b"wap-wsg-idm-ecid-wtls4\0");

/// Represents the wap-wsg-idm-ecid-wtls5 curve as specified in
/// [WAP-WTLS curves]. Also known as c2pnb163v1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS5: Ecc =
  Ecc::new(30, /* C2PNB163V1 */ 163, b"wap-wsg-idm-ecid-wtls5\0");

/// Represents the wap-wsg-idm-ecid-wtls6 curve as specified in
/// [WAP-WTLS curves]. Also known as secp112r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS6: Ecc =
  Ecc::new(53, /* SECP112R1 */ 112, b"wap-wsg-idm-ecid-wtls6\0");

/// Represents the wap-wsg-idm-ecid-wtls7 curve as specified in
/// [WAP-WTLS curves]. Also known as secp160r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS7: Ecc =
  Ecc::new(57, /* SECP160R1 */ 160, b"wap-wsg-idm-ecid-wtls7\0");

/// Represents the wap-wsg-idm-ecid-wtls8 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS8: Ecc = Ecc::new(73, 112, b"wap-wsg-idm-ecid-wtls8\0");

/// Represents the wap-wsg-idm-ecid-wtls9 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS9: Ecc = Ecc::new(74, 160, b"wap-wsg-idm-ecid-wtls9\0");

/// Represents the wap-wsg-idm-ecid-wtls10 curve as specified in
/// [WAP-WTLS curves]. Also known as K-233 and sect233k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS10: Ecc =
  Ecc::new(39, /* K233 */ 233, b"wap-wsg-idm-ecid-wtls10\0");

/// Represents the wap-wsg-idm-ecid-wtls11 curve as specified in
/// [WAP-WTLS curves]. Also known as B-233 and sect233r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS11: Ecc =
  Ecc::new(2, /* B233 */ 233, b"wap-wsg-idm-ecid-wtls11\0");

/// Represents the wap-wsg-idm-ecid-wtls12 curve as specified in
/// [WAP-WTLS curves]. Also known as P-224 and secp224r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS12: Ecc =
  Ecc::new(41, /* P224 */ 224, b"wap-wsg-idm-ecid-wtls12\0");

/// Represents the X25519 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X25519: Ecc = Ecc::new(75, 256, b"x25519\0");

/// Represents the X448 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X448: Ecc = Ecc::new(76, 448, b"x448\0");

/// Generic instance that represents a choice of f = 224 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_224: Ecc = Ecc::new(65531, 224, b"any secure 224-bit elliptic curve\0");

/// Generic instance that represents a choice of f = 256 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_256: Ecc = Ecc::new(65532, 256, b"any secure 256-bit elliptic curve\0");

/// Generic instance that represents a choice of f = 384 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_384: Ecc = Ecc::new(65533, 384, b"any secure 384-bit elliptic curve\0");

/// Generic instance that represents a choice of f = 512 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_512: Ecc = Ecc::new(65534, 512, b"any secure 512-bit elliptic curve\0");

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static ECC_NOT_SUPPORTED: Ecc = Ecc::new(u16::MAX, u16::MAX, b"not supported\0");
