//! Testing utilities.

/// Expands a unit test for an elliptic curve primitive.
#[macro_export]
macro_rules! test_ecc {
  ($name:ident, $standard:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($standard::validate_ecc(ctx, $input), $want);
    }
  };
}

/// Expands a unit test for finite field primitive.
#[macro_export]
macro_rules! test_ffc {
  ($name:ident, $standard:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($standard::validate_ffc(ctx, $input), $want);
    }
  };
}

/// Expands a unit test an integer factorisation primitive.
#[macro_export]
macro_rules! test_ifc {
  ($name:ident, $standard:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($standard::validate_ifc(ctx, $input), $want);
    }
  };
}

/// Expands a unit test for a hash function primitive.
#[macro_export]
macro_rules! test_hash {
  ($name:ident, $standard:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($standard::validate_hash(ctx, $input), $want);
    }
  };
}

/// Expands a unit test for a hash function based primitive.
#[macro_export]
macro_rules! test_hash_based {
  ($name:ident, $standard:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($standard::validate_hash_based(ctx, $input), $want);
    }
  };
}

/// Expands a unit test for a symmetric key primitive.
#[macro_export]
macro_rules! test_symmetric {
  ($name:ident, $standard:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($standard::validate_symmetric(ctx, $input), $want);
    }
  };
}
