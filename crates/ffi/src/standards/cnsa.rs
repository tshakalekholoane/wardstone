//! Validate cryptographic primitives against the Commercial National
//! Security Algorithm Suites, [CNSA 1.0] and [CNSA 2.0].
//!
//! [CNSA 1.0]: https://media.defense.gov/2021/Sep/27/2002862527/-1/-1/0/CNSS%20WORKSHEET.PDF
//! [CNSA 2.0]: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
use std::ffi::c_int;

use wardstone_core::context::Context;
use wardstone_core::primitive::ecc::Ecc;
use wardstone_core::primitive::ffc::Ffc;
use wardstone_core::primitive::hash::Hash;
use wardstone_core::primitive::ifc::Ifc;
use wardstone_core::primitive::symmetric::Symmetric;
use wardstone_core::standard::cnsa::Cnsa;
use wardstone_core::standard::Standard;

use crate::utilities;

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
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_cnsa_validate_ecc(
  ctx: Context,
  key: Ecc,
  alternative: *mut Ecc,
) -> c_int {
  utilities::c_call(Cnsa::validate_ecc, ctx, key, alternative)
}

/// Validates a finite field cryptography primitive function.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV which can also be implemented as such.
///
/// This primitive is not supported by either version of the CNSA
/// guidance.
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
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_cnsa_validate_ffc(
  ctx: Context,
  key: Ffc,
  alternative: *mut Ffc,
) -> c_int {
  utilities::c_call(Cnsa::validate_ffc, ctx, key, alternative)
}

/// Validates a hash function.
///
/// Unlike other functions in this module, there is no distinction in
/// security based on the application. As such this module does not have
/// a corresponding `validate_hash_based` function. All hash function
/// and hash based application are assessed by this single function.
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
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_cnsa_validate_hash(
  ctx: Context,
  hash: Hash,
  alternative: *mut Hash,
) -> c_int {
  utilities::c_call(Cnsa::validate_hash, ctx, hash, alternative)
}

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm.
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
pub unsafe extern "C" fn ws_cnsa_validate_ifc(
  ctx: Context,
  key: Ifc,
  alternative: *mut Ifc,
) -> c_int {
  utilities::c_call(Cnsa::validate_ifc, ctx, key, alternative)
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
pub unsafe extern "C" fn ws_cnsa_validate_symmetric(
  ctx: Context,
  key: Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  utilities::c_call(Cnsa::validate_symmetric, ctx, key, alternative)
}
