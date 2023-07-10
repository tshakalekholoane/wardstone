//! Validate cryptographic primitives against the [ECRYPT-CSA D5.4
//! Algorithms, Key Size and Protocols Report].
//!
//! [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report]: https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf
use std::ffi::c_int;

use wardstone_core::context::Context;
use wardstone_core::ecc::Ecc;
use wardstone_core::ffc::Ffc;
use wardstone_core::hash::Hash;
use wardstone_core::ifc::Ifc;
use wardstone_core::standards::ecrypt;
use wardstone_core::symmetric::Symmetric;

use crate::standards;

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
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_ecrypt_validate_ecc(
  ctx: *const Context,
  key: *const Ecc,
  alternative: *mut Ecc,
) -> c_int {
  standards::c_call(ecrypt::validate_ecc, ctx, key, alternative)
}

/// Validates a finite field cryptography primitive according to page 47
/// of the report.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman.
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
/// **Note:** The choice of security specified in the `Context` is
/// restricted to the values 160, 224, 256, 384, and 512.
///
/// # Safety
///
/// See crate documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_ecrypt_validate_ffc(
  ctx: *const Context,
  key: *const Ffc,
  alternative: *mut Ffc,
) -> c_int {
  standards::c_call(ecrypt::validate_ffc, ctx, key, alternative)
}

/// Validates a hash function according to pages 40-43 of the report.
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
pub unsafe extern "C" fn ws_ecrypt_validate_hash(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  standards::c_call(ecrypt::validate_hash, ctx, hash, alternative)
}

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm according to pages
/// 47-48.
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
pub unsafe extern "C" fn ws_ecrypt_validate_ifc(
  ctx: *const Context,
  key: *const Ifc,
  alternative: *mut Ifc,
) -> c_int {
  standards::c_call(ecrypt::validate_ifc, ctx, key, alternative)
}

/// Validates a symmetric key primitive according to pages 37 to 40 of
/// the report.
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
pub unsafe extern "C" fn ws_ecrypt_validate_symmetric(
  ctx: *const Context,
  key: *const Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  standards::c_call(ecrypt::validate_symmetric, ctx, key, alternative)
}
