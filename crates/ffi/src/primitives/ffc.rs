//! Specifies a set of commonly used finite field cryptography
//! instances.
use wardstone_core::primitive::ffc::*;

/// Generic instance that represents a choice of L = 1024 and N = 160
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_FFC_1024_160: Ffc = FFC_1024_160;

/// Generic instance that represents a choice of L = 2048 and N = 224
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_FFC_2048_224: Ffc = FFC_2048_224;

/// Generic instance that represents a choice of L = 2048 and N = 256
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_FFC_2048_256: Ffc = FFC_2048_256;

/// Generic instance that represents a choice of L = 3072 and N = 256
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_FFC_3072_256: Ffc = FFC_3072_256;

/// Generic instance that represents a choice of L = 7680 and N = 384
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_FFC_7680_384: Ffc = FFC_7680_384;

/// Generic instance that represents a choice of L = 15360 and N = 512
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_FFC_15360_512: Ffc = FFC_15360_512;

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static WS_FFC_NOT_SUPPORTED: Ffc = FFC_NOT_SUPPORTED;
