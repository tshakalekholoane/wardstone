//! Validate cryptographic primitives against the [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report].
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
//! [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report]: https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf

use std::ffi::c_int;

use crate::context::Context;
use crate::primitives::ecc::*;
use crate::standards;

// "Thus the key take home message is that decision makers now make
// plans and preparations for the phasing out of what we term legacy
// mechanisms over a period of say 5-10 years." (2018, p. 12). See p. 11
// about the criteria made to distinguish between the different
// categories of legacy algorithms.
const CUTOFF_YEAR: u16 = 2023;

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size according
/// to page 47 of the report.
///
/// If the key is not compliant then `Err` will contain the recommended
/// primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended primitive with the
/// desired security level.
///
/// **Note:** This will return a generic structure that specifies key
/// sizes.
///
/// # Example
///
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::ecc::{P224, ECC_256};
/// use wardstone::standards::ecrypt;
///
/// let ctx = Context::default();
/// assert_eq!(ecrypt::validate_ecc(&ctx, &P224), Ok(ECC_256));
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  let security = ctx.security().max(key.f >> 1);
  match security {
    ..=79 => Err(ECC_256),
    80..=127 => {
      if ctx.year() > CUTOFF_YEAR {
        Err(ECC_256)
      } else {
        Ok(ECC_256)
      }
    },
    128..=191 => Ok(ECC_256),
    192..=255 => Ok(ECC_384),
    256.. => Ok(ECC_512),
  }
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size according
/// to page 47 of the report.
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
/// **Note:** This will return a generic structure that specifies key
/// sizes.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_ecrypt_validate_ecc(
  ctx: *const Context,
  key: *const Ecc,
  alternative: *mut Ecc,
) -> c_int {
  standards::c_call(validate_ecc, ctx, key, alternative)
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(p224, validate_ecc, &P224, Ok(ECC_256));
  test_case!(p256, validate_ecc, &P256, Ok(ECC_256));
  test_case!(p384, validate_ecc, &P384, Ok(ECC_384));
  test_case!(p521, validate_ecc, &P521, Ok(ECC_512));
  test_case!(w25519, validate_ecc, &W25519, Ok(ECC_256));
  test_case!(w448, validate_ecc, &W448, Ok(ECC_384));
  test_case!(curve25519, validate_ecc, &Curve25519, Ok(ECC_256));
  test_case!(curve488, validate_ecc, &Curve448, Ok(ECC_384));
  test_case!(edwards25519, validate_ecc, &Edwards25519, Ok(ECC_256));
  test_case!(edwards448, validate_ecc, &Edwards448, Ok(ECC_384));
  test_case!(e448, validate_ecc, &E448, Ok(ECC_384));
  test_case!(brainpoolp224r1, validate_ecc, &brainpoolP224r1, Ok(ECC_256));
  test_case!(brainpoolp256r1, validate_ecc, &brainpoolP256r1, Ok(ECC_256));
  test_case!(brainpoolp320r1, validate_ecc, &brainpoolP320r1, Ok(ECC_256));
  test_case!(brainpoolp384r1, validate_ecc, &brainpoolP384r1, Ok(ECC_384));
  test_case!(brainpoolp512r1, validate_ecc, &brainpoolP512r1, Ok(ECC_512));
  test_case!(secp256k1_, validate_ecc, &secp256k1, Ok(ECC_256));
}
