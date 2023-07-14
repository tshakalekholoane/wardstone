//! A mock standard with a minimum security requirement of at least
//! 256-bits.
//!
//! This is the level of security estimated to be enough to resist an
//! attack using Grover's algorithm enabled by quantum computers which
//! as of writing does not appear to be a practical concern. However,
//! bumping the security parameter may not be enough for some signature
//! schemes such as those that use elliptic curves.
use std::ffi::c_int;

use wardstone_core::context::Context;
use wardstone_core::primitive::ecc::Ecc;
use wardstone_core::primitive::ffc::Ffc;
use wardstone_core::primitive::hash::Hash;
use wardstone_core::primitive::ifc::Ifc;
use wardstone_core::primitive::symmetric::Symmetric;
use wardstone_core::standard::testing::strong::Strong;
use wardstone_core::standard::Standard;

use crate::utilities;

/// Validate an elliptic curve cryptography primitive.
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
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_strong_validate_ecc(
  ctx: *const Context,
  key: *const Ecc,
  alternative: *mut Ecc,
) -> c_int {
  utilities::c_call(Strong::validate_ecc, ctx, key, alternative)
}

/// Validates a finite field cryptography primitive.
///
/// If the key is not compliant then `struct ws_ffc*` will point to the
/// recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `struct ws_ffc` will also point to the recommended primitive
/// with the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_strong_validate_ffc(
  ctx: *const Context,
  key: *const Ffc,
  alternative: *mut Ffc,
) -> c_int {
  utilities::c_call(Strong::validate_ffc, ctx, key, alternative)
}

/// Validates an integer factorisation cryptography primitive the
/// most common of which is the RSA signature algorithm.
///
/// If the key is not compliant then `ws_ifc*` will point to the
/// recommended key size that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `ws_ifc*` will also point to the recommended key size with
/// the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
//
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_strong_validate_ifc(
  ctx: *const Context,
  key: *const Ifc,
  alternative: *mut Ifc,
) -> c_int {
  utilities::c_call(Strong::validate_ifc, ctx, key, alternative)
}

/// Validates a hash function.
///
/// If the hash function is not compliant then
/// `struct ws_hash* alternative` will point to the recommended
/// primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `struct ws_hash*` will also point to the recommended
/// primitive with the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// **Note:** that this means an alternative might be suggested for a
/// compliant hash functions with a similar security level in which a
/// switch to the recommended primitive would likely be unwarranted. For
/// example, when evaluating compliance for the `SHA3-256`, a
/// recommendation to use `SHA256` will be made but this likely
/// unnecessary.
///
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_strong_validate_hash(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  utilities::c_call(Strong::validate_hash, ctx, hash, alternative)
}

/// Validates a symmetric key primitive.
///
/// If the key is not compliant then `struct ws_symmetric* alternative`
/// will point to the recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `struct ws_symmetric*` will also point to the recommended
/// primitive with the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_strong_validate_symmetric(
  ctx: *const Context,
  key: *const Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  utilities::c_call(Strong::validate_symmetric, ctx, key, alternative)
}
