//! Specifies a set of commonly used finite field cryptography
//! instances.
use wardstone_core::primitive::ffc::*;

/// Generic instance that represents a choice of L = 1024 and N = 160
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_DSA_1024_160: Ffc = DSA_1024_160;

/// Generic instance that represents a choice of L = 2048 and N = 224
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_DSA_2048_224: Ffc = DSA_2048_224;

/// Generic instance that represents a choice of L = 2048 and N = 256
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_DSA_2048_256: Ffc = DSA_2048_256;

/// Generic instance that represents a choice of L = 3072 and N = 256
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_DSA_3072_256: Ffc = DSA_3072_256;

/// Generic instance that represents a choice of L = 7680 and N = 384
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_DSA_7680_384: Ffc = DSA_7680_384;

/// Generic instance that represents a choice of L = 15360 and N = 512
/// for a finite field cryptography primitive.
#[no_mangle]
pub static WS_DSA_15360_512: Ffc = DSA_15360_512;

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static WS_FFC_NOT_SUPPORTED: Ffc = FFC_NOT_SUPPORTED;
