//! Specifies a set of commonly used elliptic curve cryptography
//! instances.

use wardstone_core::ecc::Ecc;
use wardstone_core::primitives::ecc::*;

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

/// Represents the Weierstrass curve W-25519 over a prime field.
#[no_mangle]
pub static WS_W25519: Ecc = W25519;

/// Represents the Weierstrass curve W-488 over a prime field.
#[no_mangle]
pub static WS_W448: Ecc = W448;

/// Represents the Montgomery curve Curve25519 over a prime field.
#[no_mangle]
pub static WS_CURVE25519: Ecc = CURVE25519;

/// Represents the Montgomery curve Curve488 over a prime field.
#[no_mangle]
pub static WS_CURVE448: Ecc = CURVE448;

/// Represents the twisted Edwards curve Edwards25519 over a prime
/// field.
#[no_mangle]
pub static WS_EDWARDS25519: Ecc = EDWARDS25519;

/// Represents the twisted Edwards curve Edwards488 over a prime field.
#[no_mangle]
pub static WS_EDWARDS448: Ecc = EDWARDS448;

/// Represents the Edwards curve E448 over a prime field.
#[no_mangle]
pub static WS_E448: Ecc = E448;

/// Represents the curve brainpoolP224r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP224R1: Ecc = BRAINPOOLP224R1;

/// Represents the curve brainpoolP256r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP256R1: Ecc = BRAINPOOLP256R1;

/// Represents the curve brainpoolP320r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP320R1: Ecc = BRAINPOOLP320R1;

/// Represents the curve brainpoolP384r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP384R1: Ecc = BRAINPOOLP384R1;

/// Represents the curve brainpoolP512r1 specified in [RFC 5639].
///
/// [RFC 5639]: https://datatracker.ietf.org/doc/rfc5639
#[no_mangle]
pub static WS_BRAINPOOLP512R1: Ecc = BRAINPOOLP512R1;

/// Represents the curve secp256k1 specified in [SEC 2].
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
#[no_mangle]
pub static WS_SECP256K1: Ecc = SECP256K1;

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
