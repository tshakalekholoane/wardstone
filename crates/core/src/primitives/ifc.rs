//! Specifies a integer factorisation cryptography primitive and a set
//! of commonly used instances.

/// Represents an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ifc {
  pub k: u16,
}

impl Ifc {
  /// Returns the approximate security provided by the key size `k`
  /// expressed as an inclusive range.
  pub fn security(&self) -> std::ops::RangeInclusive<u16> {
    match self.k {
      ..=1023 => 0..=79,
      1024..=2047 => 80..=111,
      2048..=3071 => 112..=127,
      3072..=7679 => 128..=191,
      7680..=15359 => 192..=255,
      15360.. => 256..=u16::MAX,
    }
  }
}

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
