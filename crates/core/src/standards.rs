//! Submodules that validate cryptographic primitives according to
//! selected standards and research publications.
pub mod bsi;
pub mod cnsa;
pub mod ecrypt;
pub mod lenstra;
pub mod nist;

/// Internal macro used to reduce verbosity in unit tests.
#[doc(hidden)]
#[macro_export]
macro_rules! test_case {
  ($name:ident, $func:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      use $crate::context::Context;
      let ctx = Context::default();
      assert_eq!($func(&ctx, $input), $want);
    }
  };
}
