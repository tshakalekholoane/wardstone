//! Specifies set of commonly used integer factorisation cryptography
//! primitives.
use crate::ifc::Ifc;

/// Generic instance that represents a choice of k = 1024 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1024: Ifc = Ifc { k: 1024 };

/// Generic instance that represents a choice of k = 1280 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1280: Ifc = Ifc { k: 1280 };

/// Generic instance that represents a choice of k = 1536 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1536: Ifc = Ifc { k: 1536 };

/// Generic instance that represents a choice of k = 2048 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_2048: Ifc = Ifc { k: 2048 };

/// Generic instance that represents a choice of k = 3072 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_3072: Ifc = Ifc { k: 3072 };

/// Generic instance that represents a choice of k = 4096 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_4096: Ifc = Ifc { k: 4096 };

/// Generic instance that represents a choice of k = 7680 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_7680: Ifc = Ifc { k: 7680 };

/// Generic instance that represents a choice of k = 8192 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_8192: Ifc = Ifc { k: 8192 };

/// Generic instance that represents a choice of k = 15360 for an
/// integer factorisation cryptography primitive.
#[no_mangle]
pub static IFC_15360: Ifc = Ifc { k: 15360 };

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static IFC_NOT_SUPPORTED: Ifc = Ifc { k: u16::MAX };
