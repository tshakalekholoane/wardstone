//! Integer factorisation primitive and some common instances.
use core::fmt;
use std::ffi::CStr;
use std::hash::{Hash, Hasher};

use crate::primitive::{Primitive, Security};

/// Represents an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Ifc {
  pub id: u16,
  pub k: u16,
  pub name: &'static CStr,
}

impl Ifc {
  pub const fn new(id: u16, k: u16, name: &'static [u8]) -> Self {
    Self {
      id,
      k,
      name: unsafe { CStr::from_bytes_with_nul_unchecked(name) },
    }
  }
}

impl Hash for Ifc {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.id.hash(state);
    self.k.hash(state);
  }
}

impl Primitive for Ifc {
  /// Returns the approximate *minimum* security provided by a key of
  /// the size `k`.
  fn security(&self) -> Security {
    match self.k {
      ..=1023 => 0,
      1024..=2047 => 80,
      2048..=3071 => 112,
      3072..=7679 => 128,
      7680..=15359 => 192,
      15360.. => 256,
    }
  }
}

impl fmt::Display for Ifc {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.name.to_string_lossy())
  }
}

impl PartialEq for Ifc {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id && self.k == other.k
  }
}

impl Eq for Ifc {}

/// Generic instance that represents a choice of k = 1024 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1024: Ifc = Ifc::new(
  65526,
  1024,
  b"any secure 1024-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 1280 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1280: Ifc = Ifc::new(
  65527,
  1280,
  b"any secure 1280-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 1536 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1536: Ifc = Ifc::new(
  65528,
  1536,
  b"any secure 1536-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 2048 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_2048: Ifc = Ifc::new(
  65529,
  2048,
  b"any secure 2048-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 3072 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_3072: Ifc = Ifc::new(
  65530,
  3072,
  b"any secure 3072-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 4096 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_4096: Ifc = Ifc::new(
  65531,
  4096,
  b"any secure 4096-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 7680 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_7680: Ifc = Ifc::new(
  65532,
  7680,
  b"any secure 7680-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 8192 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_8192: Ifc = Ifc::new(
  65533,
  8192,
  b"any secure 8192-bit integer factorisation primitive\0",
);

/// Generic instance that represents a choice of k = 15360 for an
/// integer factorisation cryptography primitive.
#[no_mangle]
pub static IFC_15360: Ifc = Ifc::new(
  65534,
  15360,
  b"any secure 15360-bit integer factorisation primitive\0",
);

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static IFC_NOT_SUPPORTED: Ifc = Ifc::new(u16::MAX, u16::MAX, b"not supported\0");
