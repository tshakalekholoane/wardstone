//! Specifies the context in which a cryptographic primitive will be
//! assessed against.

/// Represents the context in which a cryptographic primitive will be
/// assessed against such as the year and minimum security required by
/// the user.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
  security: u16,
  year: u16,
}

impl Context {
  // NOTE: This does not imply that the minimum security level is 0 but
  // rather that it will default to the minimum security level specified
  // in the standard.
  const DEFAULT_SECURITY: u16 = 0;
  const DEFAULT_YEAR: u16 = 2023;

  /// Creates a new context.
  ///
  /// `security` denotes the minimum security required. If this is set
  /// to `0` then it will default to using the minimum security outlined
  /// in the standard. `year` is the year one expects the primitive to
  /// remain secure.
  pub fn new(security: u16, year: u16) -> Self {
    Self { security, year }
  }

  pub fn security(&self) -> u16 {
    self.security
  }

  pub fn year(&self) -> u16 {
    self.year
  }
}

impl Default for Context {
  /// Creates a context which will default to the year 2023 and will use
  /// the minimum security defined by the standard.
  fn default() -> Self {
    Self::new(Self::DEFAULT_SECURITY, Self::DEFAULT_YEAR)
  }
}
