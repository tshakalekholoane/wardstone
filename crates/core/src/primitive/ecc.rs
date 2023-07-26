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

#[no_mangle]

#[no_mangle]

#[no_mangle]

#[no_mangle]

#[no_mangle]

#[no_mangle]

#[no_mangle]

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

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static SECP256K1: Ecc = Ecc { id: 17, f: 256 };

/// Represents the X25519 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X25519: Ecc = Ecc { id: 73, f: 256 };

/// Represents the X448 algorithm as it appears in [RFC 7748].
///
/// [RFC 7748]: https://datatracker.ietf.org/doc/html/rfc7748
#[no_mangle]
pub static X448: Ecc = Ecc { id: 74, f: 448 };

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
