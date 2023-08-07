//! Specifies a set of commonly used elliptic curve cryptography
//! instances.
use wardstone_core::primitive::ecc::*;

/// Represents the Weierstrass curve B-163 over a prime field. Also
/// known as sect163r2.
#[no_mangle]
pub static WS_B163: Ecc = B163;

/// Represents the Weierstrass curve B-223 over a prime field. Also
/// known as sect233r1 and wap-wsg-idm-ecid-wtls11.
#[no_mangle]
pub static WS_B233: Ecc = B233;

/// Represents the Weierstrass curve B-283 over a prime field. Also
/// known as sect283r1.
#[no_mangle]
pub static WS_B283: Ecc = B283;

/// Represents the Weierstrass curve B-409 over a prime field. Also
/// known as sect409r1.
#[no_mangle]
pub static WS_B409: Ecc = B409;

/// Represents the Weierstrass curve B-571 over a prime field. Also
/// known as sect571r1.
#[no_mangle]
pub static WS_B571: Ecc = B571;

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP160R1: Ecc = BRAINPOOLP160R1;

/// Represents the curve brainpoolP160t1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP160T1: Ecc = BRAINPOOLP160T1;

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP192R1: Ecc = BRAINPOOLP192R1;

/// Represents the curve brainpoolP160r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP192T1: Ecc = BRAINPOOLP192T1;

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP224R1: Ecc = BRAINPOOLP224R1;

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP224T1: Ecc = BRAINPOOLP224T1;

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP256R1: Ecc = BRAINPOOLP256R1;

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP256T1: Ecc = BRAINPOOLP256T1;

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP320R1: Ecc = BRAINPOOLP320R1;

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP320T1: Ecc = BRAINPOOLP320T1;

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP384R1: Ecc = BRAINPOOLP384R1;

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP384T1: Ecc = BRAINPOOLP384T1;

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP512R1: Ecc = BRAINPOOLP512R1;

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP512T1: Ecc = BRAINPOOLP512T1;

/// Represents the c2pnb163v1 curve as specified in ANSI x9.62. Also
/// known as wap-wsg-idm-ecid-wtls5.
#[no_mangle]
pub static WS_C2PNB163V1: Ecc = C2PNB163V1;

/// Represents the c2pnb163v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB163V2: Ecc = C2PNB163V2;

/// Represents the c2pnb163v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB163V3: Ecc = C2PNB163V3;

/// Represents the c2pnb176v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB176V1: Ecc = C2PNB176V1;

/// Represents the c2pnb208w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB208W1: Ecc = C2PNB208W1;

/// Represents the c2pnb272w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB272W1: Ecc = C2PNB272W1;

/// Represents the c2pnb304w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB304W1: Ecc = C2PNB304W1;

/// Represents the c2pnb368w1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2PNB368W1: Ecc = C2PNB368W1;
/// Represents the c2tnb191v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB191V1: Ecc = C2TNB191V1;

/// Represents the c2tnb191v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB191V2: Ecc = C2TNB191V2;

/// Represents the c2tnb191v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB191V3: Ecc = C2TNB191V3;

/// Represents the c2tnb239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB239V1: Ecc = C2TNB239V1;

/// Represents the c2tnb239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB239V2: Ecc = C2TNB239V2;

/// Represents the c2tnb239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB239V3: Ecc = C2TNB239V3;

/// Represents the c2tnb359v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB359V1: Ecc = C2TNB359V1;

/// Represents the c2tnb431r1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_C2TNB431R1: Ecc = C2TNB431R1;

/// Represents the Ed25519 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static WS_ED25519: Ecc = ED25519;

/// Represents the Ed448 signature algorithm as specified in the paper
/// [High-speed high-security signatures].
///
/// [High-speed high-security signatures]: https://eprint.iacr.org/2011/368
#[no_mangle]
pub static WS_ED448: Ecc = ED448;

/// Represents the Weierstrass curve K-163 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls3.
#[no_mangle]
pub static WS_K163: Ecc = K163;

/// Represents the Weierstrass curve K-223 over a prime field. Also
/// known as wap-wsg-idm-ecid-wtls10.
#[no_mangle]
pub static WS_K233: Ecc = K233;

/// Represents the Weierstrass curve K-409 over a prime field.
#[no_mangle]
pub static WS_K409: Ecc = K409;

/// Represents the Weierstrass curve K-571 over a prime field.
#[no_mangle]
pub static WS_K571: Ecc = K571;

/// Represents the Weierstrass curve P-192 over a prime field. Also
/// known as prime192v1 and secp192r1.
#[no_mangle]
pub static WS_P192: Ecc = P192;

/// Represents the Weierstrass curve P-224 over a prime field. Also
/// known as secp224r1.
#[no_mangle]
pub static WS_P224: Ecc = P224;

/// Represents the Weierstrass curve P-256 over a prime field. Also
/// known as secp256r1.
#[no_mangle]
pub static WS_P256: Ecc = P256;

/// Represents the Weierstrass curve P-384 over a prime field. Also
/// known as secp384r1.
#[no_mangle]
pub static WS_P384: Ecc = P384;

/// Represents the Weierstrass curve P-521 over a prime field. Also
/// known as secp521r1.
#[no_mangle]
pub static WS_P521: Ecc = P521;

/// Represents the prime192v1 curve as specified in ANSI x9.62. Also
/// known as secp192r1 and P-192.
#[no_mangle]
pub static WS_PRIME192V1: Ecc = PRIME192V1;

/// Represents the prime192v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_PRIME192V2: Ecc = PRIME192V2;

/// Represents the prime192v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_PRIME192V3: Ecc = PRIME192V3;

/// Represents the prime239v1 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_PRIME239V1: Ecc = PRIME239V1;

/// Represents the prime239v2 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_PRIME239V2: Ecc = PRIME239V2;

/// Represents the prime239v3 curve as specified in ANSI x9.62.
#[no_mangle]
pub static WS_PRIME239V3: Ecc = PRIME239V3;

/// Represents the prime256v1 curve as specified in ANSI x9.62. Also
/// known as P-256 and secp256r1.
#[no_mangle]
pub static WS_PRIME256V1: Ecc = PRIME256V1;

/// Represents the secp112r1 curve as defined in [SEC 2]. Also known
/// as wap-wsg-idm-ecid-wtls6.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECP112R1: Ecc = SECP112R1;

/// Represents the secp112r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECP112R2: Ecc = SECP112R2;

/// Represents the secp128r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECP128R1: Ecc = SECP128R1;

/// Represents the secp128r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECP128R2: Ecc = SECP128R2;

/// Represents the secp160r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls7.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECP160R1: Ecc = SECP160R1;

/// Represents the secp160r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECP160R2: Ecc = SECP160R2;

/// Represents the secp192r1 curve as defined in [SEC 2]. Also known as
/// prime192v1 and P-192.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP192R1: Ecc = SECP192R1;

/// Represents the secp192k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP192K1: Ecc = SECP192K1;

/// Represents the secp224r1 curve as defined in [SEC 2]. Also known as
/// P-224 and wap-wsg-idm-ecid-wtls12.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP224R1: Ecc = SECP224R1;

/// Represents the secp224k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP224K1: Ecc = SECP224K1;

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP256K1: Ecc = SECP256K1;

/// Represents the secp256r1 curve as defined in [SEC 2]. Also known as
/// prime256v1 and P-256.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP256R1: Ecc = SECP256R1;

/// Represents the secp384r1 curve as defined in [SEC 2]. Also known as
/// P-384.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP384R1: Ecc = SECP384R1;

/// Represents the secp521r1 curve as defined in [SEC 2]. Also known as
/// P-521.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP521R1: Ecc = SECP521R1;

/// Represents the sect113r1 curve as defined in [SEC 2]. Also known as
/// wap-wsg-idm-ecid-wtls4.
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECT113R1: Ecc = SECT113R1;

/// Represents the sect113r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECT113R2: Ecc = SECT113R2;

/// Represents the sect131r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECT131R1: Ecc = SECT131R1;

/// Represents the sect131r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/SEC2-Ver-1.0.pdf
#[no_mangle]
pub static WS_SECT131R2: Ecc = SECT131R2;

/// Represents the sect163k1 curve as defined in [SEC 2]. Also known as
/// K-163 and wap-wsg-idm-ecid-wtls3.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT163K1: Ecc = SECT163K1;

/// Represents the sect163r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT163R1: Ecc = SECT163R1;

/// Represents the sect163r2 curve as defined in [SEC 2]. Also known as
/// B-163.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT163R2: Ecc = SECT163R2;

/// Represents the sect193r1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT193R1: Ecc = SECT193R1;

/// Represents the sect193r2 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT193R2: Ecc = SECT193R2;

/// Represents the sect233k1 curve as defined in [SEC 2]. Also known as
/// K-233 and wap-wsg-idm-ecid-wtls10.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT233K1: Ecc = SECT233K1;

/// Represents the sect233r1 curve as defined in [SEC 2]. Also known as
/// B-233 and wap-wsg-idm-ecid-wtls11.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT233R1: Ecc = SECT233R1;

/// Represents the sect239k1 curve as defined in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT239K1: Ecc = SECT239K1;

/// Represents the sect283r1 curve as defined in [SEC 2]. Also known as
/// B-283.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT283R1: Ecc = SECT283R1;

/// Represents the sect409k1 curve as defined in [SEC 2]. Also known as
/// K-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT409K1: Ecc = SECT409K1;

/// Represents the sect409r1 curve as defined in [SEC 2]. Also known as
/// B-409.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT409R1: Ecc = SECT409R1;

/// Represents the sect571k1 curve as defined in [SEC 2]. Also known as
/// K-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT571K1: Ecc = SECT571K1;

/// Represents the sect571r1 curve as defined in [SEC 2]. Also known as
/// B-571.
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECT571R1: Ecc = SECT571R1;

/// Represents the SM2 digital signature algorithm as defined in
/// draft-shen-sm2-ecdsa-02.
///
/// [draft-shen-sm2-ecdsa-02]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02
#[no_mangle]
pub static WS_SM2: Ecc = SM2;

/// Represents the wap-wsg-idm-ecid-wtls1 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS1: Ecc = WAP_WSG_IDM_ECID_WTLS1;

/// Represents the wap-wsg-idm-ecid-wtls3 curve as specified in
/// [WAP-WTLS curves]. Also known as sect163k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS3: Ecc = WAP_WSG_IDM_ECID_WTLS3;

/// Represents the wap-wsg-idm-ecid-wtls4 curve as specified in
/// [WAP-WTLS curves]. Also known as sect113r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS4: Ecc = WAP_WSG_IDM_ECID_WTLS4;

/// Represents the wap-wsg-idm-ecid-wtls5 curve as specified in
/// [WAP-WTLS curves]. Also known as c2pnb163v1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS5: Ecc = WAP_WSG_IDM_ECID_WTLS5;

/// Represents the wap-wsg-idm-ecid-wtls6 curve as specified in
/// [WAP-WTLS curves]. Also known as secp112r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS6: Ecc = WAP_WSG_IDM_ECID_WTLS6;

/// Represents the wap-wsg-idm-ecid-wtls7 curve as specified in
/// [WAP-WTLS curves]. Also known as secp160r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS7: Ecc = WAP_WSG_IDM_ECID_WTLS7;

/// Represents the wap-wsg-idm-ecid-wtls8 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS8: Ecc = WAP_WSG_IDM_ECID_WTLS8;

/// Represents the wap-wsg-idm-ecid-wtls9 curve as specified in
/// [WAP-WTLS curves].
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS9: Ecc = WAP_WSG_IDM_ECID_WTLS9;

/// Represents the wap-wsg-idm-ecid-wtls10 curve as specified in
/// [WAP-WTLS curves]. Also known as K-233 and sect233k1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS10: Ecc = WAP_WSG_IDM_ECID_WTLS10;

/// Represents the wap-wsg-idm-ecid-wtls11 curve as specified in
/// [WAP-WTLS curves]. Also known as B-233 and sect233r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS11: Ecc = WAP_WSG_IDM_ECID_WTLS11;

/// Represents the wap-wsg-idm-ecid-wtls12 curve as specified in
/// [WAP-WTLS curves]. Also known as P-224 and secp224r1.
///
/// [WAP-WTLS curves]: https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf
#[no_mangle]
pub static WS_WAP_WSG_IDM_ECID_WTLS12: Ecc = WAP_WSG_IDM_ECID_WTLS12;

/// Represents the X25519 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static WS_X25519: Ecc = X25519;

/// Represents the X448 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static WS_X448: Ecc = X448;

/// Generic instance that represents a choice of f = 224 for an elliptic
/// curve primitive.
#[no_mangle]
pub static WS_ECC_224: Ecc = ECC_224;

/// Generic instance that represents a choice of f = 256 for an elliptic
/// curve primitive.
#[no_mangle]
pub static WS_ECC_256: Ecc = ECC_256;

/// Generic instance that represents a choice of f = 384 for an elliptic
/// curve primitive.
#[no_mangle]
pub static WS_ECC_384: Ecc = ECC_384;

/// Generic instance that represents a choice of f = 512 for an elliptic
/// curve primitive.
#[no_mangle]
pub static WS_ECC_512: Ecc = ECC_512;

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static WS_ECC_NOT_SUPPORTED: Ecc = ECC_NOT_SUPPORTED;
