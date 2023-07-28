//! Elliptic curve primitive and some common instances.
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
pub static B163: Ecc = Ecc { id: 1, f: 163 };

/// Represents the Weierstrass curve B-223 over a prime field. Also
/// known as sect233r1 and wap-wsg-idm-ecid-wtls11.
#[no_mangle]
pub static B233: Ecc = Ecc { id: 2, f: 233 };

/// Represents the Weierstrass curve B-283 over a prime field. Also
/// known as sect283r1.
#[no_mangle]
pub static B283: Ecc = Ecc { id: 3, f: 283 };

/// Represents the Weierstrass curve B-409 over a prime field. Also
/// known as sect409r1.
#[no_mangle]
pub static B409: Ecc = Ecc { id: 4, f: 409 };

/// Represents the Weierstrass curve B-571 over a prime field. Also
/// known as sect571r1.
#[no_mangle]
pub static B571: Ecc = Ecc { id: 5, f: 571 };

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP160R1: Ecc = Ecc { id: 6, f: 160 };

/// Represents the curve brainpoolP160t1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP160T1: Ecc = Ecc { id: 7, f: 160 };

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP192R1: Ecc = Ecc { id: 8, f: 192 };

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP192T1: Ecc = Ecc { id: 9, f: 192 };

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224R1: Ecc = Ecc { id: 10, f: 224 };

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224T1: Ecc = Ecc { id: 11, f: 224 };

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256R1: Ecc = Ecc { id: 12, f: 256 };

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256T1: Ecc = Ecc { id: 13, f: 256 };

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320R1: Ecc = Ecc { id: 14, f: 320 };

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320T1: Ecc = Ecc { id: 15, f: 320 };

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384R1: Ecc = Ecc { id: 16, f: 384 };

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384T1: Ecc = Ecc { id: 17, f: 384 };

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512R1: Ecc = Ecc { id: 18, f: 512 };

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512T1: Ecc = Ecc { id: 19, f: 512 };

/// Represents the c2pnb163v1 curve as specified in ANSI x9.62. Also
/// known as wap-wsg-idm-ecid-wtls5.
#[no_mangle]
pub static C2PNB163V1: Ecc = Ecc { id: 20, f: 163 };

/// Represents the c2pnb163v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB163V2: Ecc = Ecc { id: 21, f: 163 };

/// Represents the c2pnb163v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB163V3: Ecc = Ecc { id: 22, f: 163 };

/// Represents the c2pnb176v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB176V1: Ecc = Ecc { id: 23, f: 176 };

/// Represents the c2pnb208w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB208W1: Ecc = Ecc { id: 24, f: 208 };

/// Represents the c2pnb272w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB272W1: Ecc = Ecc { id: 25, f: 272 };

/// Represents the c2pnb304w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB304W1: Ecc = Ecc { id: 26, f: 304 };

/// Represents the c2pnb368w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2PNB368W1: Ecc = Ecc { id: 27, f: 368 };
/// Represents the c2tnb191v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V1: Ecc = Ecc { id: 28, f: 191 };

/// Represents the c2tnb191v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V2: Ecc = Ecc { id: 29, f: 191 };

/// Represents the c2tnb191v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB191V3: Ecc = Ecc { id: 30, f: 191 };

/// Represents the c2tnb239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V1: Ecc = Ecc { id: 31, f: 239 };

/// Represents the c2tnb239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V2: Ecc = Ecc { id: 32, f: 239 };

/// Represents the c2tnb239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB239V3: Ecc = Ecc { id: 33, f: 239 };

/// Represents the c2tnb359v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB359V1: Ecc = Ecc { id: 34, f: 359 };

/// Represents the c2tnb431r1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static C2TNB431R1: Ecc = Ecc { id: 35, f: 359 };

/// Represents the Ed25519 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static ED25519: Ecc = Ecc { id: 36, f: 256 };

/// Represents the Ed448 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static ED448: Ecc = Ecc { id: 37, f: 448 };

/// Represents the Weierstrass curve K-163 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls3.
#[no_mangle]
pub static K163: Ecc = Ecc { id: 38, f: 192 };

/// Represents the Weierstrass curve K-223 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls10.
#[no_mangle]
pub static K233: Ecc = Ecc { id: 39, f: 192 };

/// Represents the Weierstrass curve K-283 over a prime field. Also
/// known as sect283k1.
#[no_mangle]
pub static K283: Ecc = Ecc { id: 40, f: 192 };

/// Represents the Weierstrass curve K-409 over a prime field.
#[no_mangle]
pub static K409: Ecc = Ecc { id: 41, f: 409 };

/// Represents the Weierstrass curve K-571 over a prime field.
#[no_mangle]
pub static K571: Ecc = Ecc { id: 42, f: 571 };

/// Represents the Weierstrass curve P-192 over a prime field. Also
/// known as prime192v1 and secp192r1.
#[no_mangle]
pub static P192: Ecc = Ecc { id: 43, f: 192 };

/// Represents the Weierstrass curve P-224 over a prime field. Also
/// known as secp224r1.
#[no_mangle]
pub static P224: Ecc = Ecc { id: 44, f: 224 };

/// Represents the Weierstrass curve P-256 over a prime field. Also
/// known as secp256r1.
#[no_mangle]
pub static P256: Ecc = Ecc { id: 45, f: 256 };

/// Represents the Weierstrass curve P-384 over a prime field. Also
/// known as secp384r1.
#[no_mangle]
pub static P384: Ecc = Ecc { id: 46, f: 384 };

/// Represents the Weierstrass curve P-521 over a prime field. Also
/// known as secp521r1.
#[no_mangle]
pub static P521: Ecc = Ecc { id: 47, f: 521 };

/// Represents the prime192v1 curve as specified in ANSI x9.62. Also
/// known as secp192r1 and P-192.
#[no_mangle]
pub static PRIME192V1: Ecc = P192;

/// Represents the prime192v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME192V2: Ecc = Ecc { id: 48, f: 192 };

/// Represents the prime192v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME192V3: Ecc = Ecc { id: 49, f: 192 };

/// Represents the prime239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V1: Ecc = Ecc { id: 50, f: 239 };

/// Represents the prime239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V2: Ecc = Ecc { id: 51, f: 239 };

/// Represents the prime239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static PRIME239V3: Ecc = Ecc { id: 52, f: 239 };

/// Represents the prime256v1 curve as specified in ANSI x9.62. Also
/// known as P-256 and secp256r1.
#[no_mangle]
pub static PRIME256V1: Ecc = P256;

/// Represents the secp112r1 curve as defined in [SEC 2]. Also known
/// as wap-wsg-idm-ecid-wtls6.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP112R1: Ecc = Ecc { id: 53, f: 112 };

/// Represents the secp112r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP112R2: Ecc = Ecc { id: 54, f: 112 };

/// Represents the secp128r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP128R1: Ecc = Ecc { id: 55, f: 128 };

/// Represents the secp128r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP128R2: Ecc = Ecc { id: 56, f: 128 };

/// Represents the secp160r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls7.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160R1: Ecc = Ecc { id: 57, f: 160 };

/// Represents the secp160k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160K1: Ecc = Ecc { id: 58, f: 160 };

/// Represents the secp160r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECP160R2: Ecc = Ecc { id: 59, f: 160 };

/// Represents the secp192r1 curve as defined in [SEC 2]. Also known as
/// prime192v1 and P-192.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP192R1: Ecc = P192;

/// Represents the secp192k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP192K1: Ecc = Ecc { id: 60, f: 192 };

/// Represents the secp224r1 curve as defined in [SEC 2]. Also known as
/// P-224 and wap-wsg-idm-ecid-wtls12.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP224R1: Ecc = P224;

/// Represents the secp224k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP224K1: Ecc = Ecc { id: 61, f: 224 };

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256K1: Ecc = Ecc { id: 62, f: 256 };

/// Represents the secp256r1 curve as defined in [SEC 2]. Also known as
/// prime256v1 and P-256.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256R1: Ecc = P256;

/// Represents the secp384r1 curve as defined in [SEC 2]. Also known as
/// P-384.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP384R1: Ecc = P384;

/// Represents the secp521r1 curve as defined in [SEC 2]. Also known as
/// P-521.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP521R1: Ecc = P521;

/// Represents the sect113r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls4.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT113R1: Ecc = Ecc { id: 63, f: 113 };

/// Represents the sect113r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT113R2: Ecc = Ecc { id: 64, f: 113 };

/// Represents the sect131r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT131R1: Ecc = Ecc { id: 65, f: 131 };

/// Represents the sect131r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static SECT131R2: Ecc = Ecc { id: 66, f: 131 };

/// Represents the sect163k1 curve as defined in [SEC 2]. Also known as
/// K-163 and wap-wsg-idm-ecid-wtls3.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163K1: Ecc = K163;

/// Represents the sect163r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163R1: Ecc = Ecc { id: 67, f: 163 };

/// Represents the sect163r2 curve as defined in [SEC 2]. Also known as
/// B-163.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT163R2: Ecc = B163;

/// Represents the sect193r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT193R1: Ecc = Ecc { id: 68, f: 193 };

/// Represents the sect193r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT193R2: Ecc = Ecc { id: 69, f: 193 };

/// Represents the sect233k1 curve as defined in [SEC 2]. Also known as
/// K-233 and wap-wsg-idm-ecid-wtls10.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT233K1: Ecc = K233;

/// Represents the sect233r1 curve as defined in [SEC 2]. Also known as
/// B-233 and wap-wsg-idm-ecid-wtls11.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT233R1: Ecc = B233;

/// Represents the sect239k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT239K1: Ecc = Ecc { id: 70, f: 239 };

/// Represents the sect283r1 curve as defined in [SEC 2]. Also known as
/// B-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT283R1: Ecc = B283;

/// Represents the sect283k1 curve as defined in [SEC 2]. Also known as
/// K-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT283K1: Ecc = K283;

/// Represents the sect409k1 curve as defined in [SEC 2]. Also known as
/// K-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT409K1: Ecc = K409;

/// Represents the sect409r1 curve as defined in [SEC 2]. Also known as
/// B-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT409R1: Ecc = B409;

/// Represents the sect571k1 curve as defined in [SEC 2]. Also known as
/// K-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT571K1: Ecc = K571;

/// Represents the sect571r1 curve as defined in [SEC 2]. Also known as
/// B-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECT571R1: Ecc = B571;

/// Represents the SM2 digital signature algorithm as defined in
/// draft-shen-sm2-ecdsa-02.
///
/// [draft-shen-sm2-ecdsa-02]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02
#[no_mangle]
pub static SM2: Ecc = Ecc { id: 71, f: 256 };

/// Represents the wap-wsg-idm-ecid-wtls1 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS1: Ecc = Ecc { id: 72, f: 113 };

/// Represents the wap-wsg-idm-ecid-wtls3 curve as specified in
/// [WAP-WTLS curves]. Also known as sect163k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS3: Ecc = K163;

/// Represents the wap-wsg-idm-ecid-wtls4 curve as specified in
/// [WAP-WTLS curves]. Also known as sect113r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS4: Ecc = SECT113R1;

/// Represents the wap-wsg-idm-ecid-wtls5 curve as specified in
/// [WAP-WTLS curves]. Also known as c2pnb163v1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS5: Ecc = C2PNB163V1;

/// Represents the wap-wsg-idm-ecid-wtls6 curve as specified in
/// [WAP-WTLS curves]. Also known as secp112r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS6: Ecc = SECP112R1;

/// Represents the wap-wsg-idm-ecid-wtls7 curve as specified in
/// [WAP-WTLS curves]. Also known as secp160r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS7: Ecc = SECP160R1;

/// Represents the wap-wsg-idm-ecid-wtls8 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS8: Ecc = Ecc { id: 73, f: 112 };

/// Represents the wap-wsg-idm-ecid-wtls9 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS9: Ecc = Ecc { id: 74, f: 160 };

/// Represents the wap-wsg-idm-ecid-wtls10 curve as specified in
/// [WAP-WTLS curves]. Also known as K-233 and sect233k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS10: Ecc = K233;

/// Represents the wap-wsg-idm-ecid-wtls11 curve as specified in
/// [WAP-WTLS curves]. Also known as B-233 and sect233r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS11: Ecc = B233;

/// Represents the wap-wsg-idm-ecid-wtls12 curve as specified in
/// [WAP-WTLS curves]. Also known as P-224 and secp224r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WAP_WSG_IDM_ECID_WTLS12: Ecc = P224;

/// Represents the X25519 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X25519: Ecc = Ecc { id: 75, f: 256 };

/// Represents the X448 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X448: Ecc = Ecc { id: 76, f: 448 };

/// Generic instance that represents a choice of f = 224 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_224: Ecc = Ecc { id: 65531, f: 224 };

/// Generic instance that represents a choice of f = 256 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_256: Ecc = Ecc { id: 65532, f: 256 };

/// Generic instance that represents a choice of f = 384 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_384: Ecc = Ecc { id: 65533, f: 384 };

/// Generic instance that represents a choice of f = 512 for an elliptic
/// curve primitive.
#[no_mangle]
pub static ECC_512: Ecc = Ecc { id: 65534, f: 512 };

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static ECC_NOT_SUPPORTED: Ecc = Ecc {
  id: u16::MAX,
  f: u16::MAX,
};
