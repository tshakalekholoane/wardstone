/// Represents a finite field cryptography primitive used to implement
/// discrete logarithm cryptography.
///
/// The choices l and n represents the bit lengths of the prime modulus
/// p and the prime divisor q.
///
/// Some of the primitives that fall under this category include
/// signature algorithms such as DSA and key establishment algorithms
/// such as Diffie-Hellman and MQV.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ffc {
  pub l: u16,
  pub n: u16,
}

/// Represents a choice of L = 1024 and N = 160 for a finite field
/// cryptography primitive.
#[no_mangle]
pub static FFC_1024_160: Ffc = Ffc { l: 1024, n: 160 };

/// Represents a choice of L = 2048 and N = 224 for a finite field
/// cryptography primitive.
#[no_mangle]
pub static FFC_2048_224: Ffc = Ffc { l: 2048, n: 224 };

/// Represents a choice of L = 2048 and N = 256 for a finite field
/// cryptography primitive.
#[no_mangle]
pub static FFC_2048_256: Ffc = Ffc { l: 2048, n: 256 };

/// Represents a choice of L = 3072 and N = 256 for a finite field
/// cryptography primitive.
#[no_mangle]
pub static FFC_3072_256: Ffc = Ffc { l: 3072, n: 256 };

/// Represents a choice of L = 7680 and N = 384 for a finite field
/// cryptography primitive.
#[no_mangle]
pub static FFC_7680_384: Ffc = Ffc { l: 7680, n: 384 };

/// Represents a choice of L = 15360 and N = 512 for a finite field
/// cryptography primitive.
#[no_mangle]
pub static FFC_15360_512: Ffc = Ffc { l: 15360, n: 512 };

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static FFC_NOT_SUPPORTED: Ffc = Ffc {
  l: u16::MAX,
  n: u16::MAX,
};
