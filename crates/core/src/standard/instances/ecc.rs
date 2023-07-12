//! Specifies a set of commonly used elliptic curve cryptography
//! primitives.
use crate::primitive::ecc::Ecc;

/// Represents the Weierstrass curve P-224 over a prime field. Also
/// known as secp224r1.
#[no_mangle]
pub static P224: Ecc = Ecc { id: 1, f: 224 };

/// Represents the Weierstrass curve P-256 over a prime field. Also
/// known as secp256r1.
#[no_mangle]
pub static P256: Ecc = Ecc { id: 2, f: 256 };

/// Represents the Weierstrass curve P-384 over a prime field. Also
/// known as secp384r1.
#[no_mangle]
pub static P384: Ecc = Ecc { id: 3, f: 384 };

/// Represents the Weierstrass curve P-521 over a prime field. Also
/// known as secp521r1.
#[no_mangle]
pub static P521: Ecc = Ecc { id: 4, f: 521 };

/// Represents the Weierstrass curve W-25519 over a prime field.
#[no_mangle]
pub static W25519: Ecc = Ecc { id: 5, f: 256 };

/// Represents the Weierstrass curve W-488 over a prime field.
#[no_mangle]
pub static W448: Ecc = Ecc { id: 6, f: 448 };

/// Represents the Montgomery curve Curve25519 over a prime field.
#[no_mangle]
pub static CURVE25519: Ecc = Ecc { id: 7, f: 256 };

/// Represents the Montgomery curve Curve488 over a prime field.
#[no_mangle]
pub static CURVE448: Ecc = Ecc { id: 8, f: 448 };

/// Represents the twisted Edwards curve Edwards25519 over a prime
/// field.
#[no_mangle]
pub static EDWARDS25519: Ecc = Ecc { id: 9, f: 256 };

/// Represents the twisted Edwards curve Edwards488 over a prime field.
#[no_mangle]
pub static EDWARDS448: Ecc = Ecc { id: 10, f: 448 };

/// Represents the Edwards curve E448 over a prime field.
#[no_mangle]
pub static E448: Ecc = Ecc { id: 11, f: 448 };

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP224R1: Ecc = Ecc { id: 12, f: 224 };

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP256R1: Ecc = Ecc { id: 13, f: 256 };

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP320R1: Ecc = Ecc { id: 14, f: 320 };

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP384R1: Ecc = Ecc { id: 15, f: 384 };

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static BRAINPOOLP512R1: Ecc = Ecc { id: 16, f: 512 };

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256K1: Ecc = Ecc { id: 17, f: 256 };

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
