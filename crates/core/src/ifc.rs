//! Integer factorisation primitive.

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
