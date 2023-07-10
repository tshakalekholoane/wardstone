//! Specifies a integer factorisation cryptography primitive and a set
//! of commonly used instances.
use wardstone_core::ifc::Ifc;
use wardstone_core::primitives::ifc::*;

/// Generic instance that represents a choice of k = 1024 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_1024: Ifc = IFC_1024;

/// Generic instance that represents a choice of k = 1280 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_1280: Ifc = IFC_1280;

/// Generic instance that represents a choice of k = 1536 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_1536: Ifc = IFC_1536;

/// Generic instance that represents a choice of k = 2048 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_2048: Ifc = IFC_2048;

/// Generic instance that represents a choice of k = 3072 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_3072: Ifc = IFC_3072;

/// Generic instance that represents a choice of k = 4096 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_4096: Ifc = IFC_4096;

/// Generic instance that represents a choice of k = 7680 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_7680: Ifc = IFC_7680;

/// Generic instance that represents a choice of k = 8192 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_8192: Ifc = IFC_8192;

/// Generic instance that represents a choice of k = 15360 for an
/// integer factorisation cryptography primitive.
#[no_mangle]
pub static WS_IFC_15360: Ifc = IFC_15360;

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static WS_IFC_NOT_SUPPORTED: Ifc = IFC_NOT_SUPPORTED;
