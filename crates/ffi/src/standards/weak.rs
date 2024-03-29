//! A mock standard with a minimum security requirement of at least
//! 64-bits.
//!
//! **Caution:** This might return recommendations for primitives that
//! are considered unsafe when used in some applications such as MD5 and
//! SHA1. For secure applications use any of the other standards defined
//! in this crate.
use std::ffi::c_int;

use wardstone_core::context::Context;
use wardstone_core::primitive::ecc::Ecc;
use wardstone_core::primitive::ffc::Ffc;
use wardstone_core::primitive::hash::Hash;
use wardstone_core::primitive::ifc::Ifc;
use wardstone_core::primitive::symmetric::Symmetric;
use wardstone_core::standard::testing::weak::Weak;
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
pub unsafe extern "C" fn ws_weak_validate_ecc(
  ctx: Context,
  key: Ecc,
  alternative: *mut Ecc,
) -> c_int {
  utilities::c_call(Weak::validate_ecc, ctx, key, alternative)
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
pub unsafe extern "C" fn ws_weak_validate_ffc(
  ctx: Context,
  key: Ffc,
  alternative: *mut Ffc,
) -> c_int {
  utilities::c_call(Weak::validate_ffc, ctx, key, alternative)
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
pub unsafe extern "C" fn ws_weak_validate_ifc(
  ctx: Context,
  key: Ifc,
  alternative: *mut Ifc,
) -> c_int {
  utilities::c_call(Weak::validate_ifc, ctx, key, alternative)
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
pub unsafe extern "C" fn ws_weak_validate_hash(
  ctx: Context,
  hash: Hash,
  alternative: *mut Hash,
) -> c_int {
  utilities::c_call(Weak::validate_hash, ctx, hash, alternative)
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
pub unsafe extern "C" fn ws_weak_validate_symmetric(
  ctx: Context,
  key: Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  utilities::c_call(Weak::validate_symmetric, ctx, key, alternative)
}
