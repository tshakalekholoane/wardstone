//! Integer factorisation primitive and some common instances.
use std::fmt::{self, Display, Formatter};

use crate::primitive::{Primitive, Security};

/// Represents an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ifc {
  pub id: u16,
  pub k: u16,
}

impl Ifc {
  pub const fn new(id: u16, k: u16) -> Self {
    Self { id, k }
  }
}

impl Display for Ifc {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if self.id == ID_RSA_PKCS1 || matches!(self.id, 1..=8) {
      write!(f, "rsa_pkcs1_{}", self.k)
    } else if self.id == ID_RSA_PSS || matches!(self.id, 9..=17) {
      write!(f, "rsa_pss_{}", self.k)
    } else if self.id == u16::MAX {
      write!(f, "not allowed")
    } else {
      write!(f, "unrecognised")
    }
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

/// An identifier for custom RSA with PKCS #1 v1.5 padding keys.
///
/// This for use in creating custom keys in that can be used in
/// standards that make a distinction between RSA padding schemes.
#[no_mangle]
pub static ID_RSA_PKCS1: u16 = 65533;

/// An identifier for custom RSA with PSS encoding keys.
///
/// This for use in creating custom keys in that can be used in
/// standards that make a distinction between RSA padding schemes.
#[no_mangle]
pub static ID_RSA_PSS: u16 = 65534;

/// 1024-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_1024: Ifc = Ifc::new(1, 1024);

/// 1536-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_1536: Ifc = Ifc::new(2, 1536);

/// 2048-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_2048: Ifc = Ifc::new(3, 2048);

/// 3072-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_3072: Ifc = Ifc::new(4, 3072);

/// 4096-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_4096: Ifc = Ifc::new(5, 4096);

/// 7680-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_7680: Ifc = Ifc::new(6, 7680);

/// 8192-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_8192: Ifc = Ifc::new(7, 8192);

/// 15360-bit RSA with PKCS #1 v1.5 padding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PKCS1_15360: Ifc = Ifc::new(8, 15360);

/// 1024-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_1024: Ifc = Ifc::new(9, 1024);

/// 1280-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_1280: Ifc = Ifc::new(10, 1280);

/// 1536-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_1536: Ifc = Ifc::new(11, 1536);

/// 2048-bit RSA with PSS encoding as defined in RFC 8446..
#[no_mangle]
pub static RSA_PSS_2048: Ifc = Ifc::new(12, 2048);

/// 3072-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_3072: Ifc = Ifc::new(13, 3072);

/// 4096-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_4096: Ifc = Ifc::new(14, 4096);

/// 7680-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_7680: Ifc = Ifc::new(15, 7680);

/// 7680-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_8192: Ifc = Ifc::new(16, 8192);

/// 15360-bit RSA with PSS encoding as defined in RFC 8446.
#[no_mangle]
pub static RSA_PSS_15360: Ifc = Ifc::new(17, 15360);

/// Placeholder for use in where this primitive is not allowed.
#[no_mangle]
pub static IFC_NOT_ALLOWED: Ifc = Ifc::new(u16::MAX, u16::MAX);
