//! Specifies a integer factorisation cryptography primitive and a set
//! of commonly used instances.
use wardstone_core::primitive::ifc::*;

/// An identifier for custom RSA with PKCS #1 v1.5 padding keys.
///
/// This for use in creating custom keys in that can be used in
/// standards that make a distinction between RSA padding schemes.
#[no_mangle]
pub static WS_ID_RSA_PKCS1: u16 = ID_RSA_PKCS1;

/// An identifier for custom RSA with PSS encoding keys.
///
/// This for use in creating custom keys in that can be used in
/// standards that make a distinction between RSA padding schemes.
#[no_mangle]
pub static WS_ID_RSA_PSS: u16 = ID_RSA_PSS;

/// 1024-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_1024: Ifc = RSA_PKCS1_1024;

/// 1536-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_1536: Ifc = RSA_PKCS1_1536;

/// 2048-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_2048: Ifc = RSA_PKCS1_2048;

/// 3072-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_3072: Ifc = RSA_PKCS1_3072;

/// 4096-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_4096: Ifc = RSA_PKCS1_4096;

/// 7680-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_7680: Ifc = RSA_PKCS1_7680;

/// 8192-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_8192: Ifc = RSA_PKCS1_8192;

/// 15360-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PKCS1_15360: Ifc = RSA_PKCS1_15360;

/// 1024-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_1024: Ifc = RSA_PSS_1024;

/// 1280-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_1280: Ifc = RSA_PSS_1280;

/// 1536-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_1536: Ifc = RSA_PSS_1536;

/// 2048-bit RSA with PSS encoding as defined in RFC 8446..
#[no_mangle]
pub static WS_RSA_PSS_2048: Ifc = RSA_PSS_2048;

/// 3072-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_3072: Ifc = RSA_PSS_3072;

/// 4096-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_4096: Ifc = RSA_PSS_4096;

/// 7680-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_7680: Ifc = RSA_PSS_7680;

/// 7680-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_8192: Ifc = RSA_PSS_8192;

/// 15360-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static WS_RSA_PSS_15360: Ifc = RSA_PSS_15360;

/// Placeholder for use in where this primitive is not allowed.
#[no_mangle]
pub static WS_IFC_NOT_ALLOWED: Ifc = IFC_NOT_ALLOWED;
