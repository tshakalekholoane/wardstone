//! Validate cryptographic primitives against the Commercial National
//! Security Algorithm Suites.
//!
//! For more information, see [press release].
//!
//! # Safety
//!
//! This module contains functions that use raw pointers as arguments
//! for reading and writing data. However, this is only for the C API
//! that is exposed to interact with safe Rust equivalents. The C API is
//! essentially a wrapper around the Rust function to maintain
//! consistency with existing conventions.
//!
//! Checks against null dereferences are made in which the function will
//! return `-1` if the argument is required.
//!
//! [press release]: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF

use std::ffi::c_int;

use crate::context::Context;
use crate::primitives::ecc::*;
use crate::standards;

// Exclusive use of CNSA 2.0 by this date.
const CUTOFF_YEAR: u16 = 2030;

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment.
///
/// If the key is not compliant then `Err` will contain the recommended
/// primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended primitive with the
/// desired security level.
///
/// # Example
///
/// The following illustrates a call to validate a non-compliant key.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::ecc::{P256, P384};
/// use wardstone::standards::cnsa;
///
/// let ctx = Context::default();
/// assert_eq!(cnsa::validate_ecc(&ctx, &P256), Err(P384));
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  if ctx.year() > CUTOFF_YEAR {
    return Err(ECC_NOT_SUPPORTED);
  }

  if *key == P384 {
    Ok(P384)
  } else {
    Err(P384)
  }
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment.
///
/// If the key is not compliant then `ws_ecc*` will contain the
/// recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `ws_ecc*` will also hold the recommended primitive with the
/// desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_cnsa_validate_ecc(
  ctx: *const Context,
  key: *const Ecc,
  alternative: *mut Ecc,
) -> c_int {
  standards::c_call(validate_ecc, ctx, key, alternative)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(p224, validate_ecc, &P224, Err(P384));
  test_case!(p256, validate_ecc, &P256, Err(P384));
  test_case!(p384, validate_ecc, &P384, Ok(P384));
  test_case!(p521, validate_ecc, &P521, Err(P384));
  test_case!(w25519, validate_ecc, &W25519, Err(P384));
  test_case!(w448, validate_ecc, &W448, Err(P384));
  test_case!(curve25519, validate_ecc, &Curve25519, Err(P384));
  test_case!(curve488, validate_ecc, &Curve448, Err(P384));
  test_case!(edwards25519, validate_ecc, &Edwards25519, Err(P384));
  test_case!(edwards448, validate_ecc, &Edwards448, Err(P384));
  test_case!(e448, validate_ecc, &E448, Err(P384));
  test_case!(brainpoolp224r1, validate_ecc, &brainpoolP224r1, Err(P384));
  test_case!(brainpoolp256r1, validate_ecc, &brainpoolP256r1, Err(P384));
  test_case!(brainpoolp320r1, validate_ecc, &brainpoolP320r1, Err(P384));
  test_case!(brainpoolp384r1, validate_ecc, &brainpoolP384r1, Err(P384));
  test_case!(brainpoolp512r1, validate_ecc, &brainpoolP512r1, Err(P384));
  test_case!(secp256k1_, validate_ecc, &secp256k1, Err(P384));
}
