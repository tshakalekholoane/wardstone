pub mod bsi;
pub mod cnsa;
pub mod lenstra;
pub mod nist;

use std::ffi::c_int;

use crate::context::Context;

#[macro_export]
macro_rules! test_case {
  ($name:ident, $func:ident, $input:expr, $want:expr) => {
    #[test]
    fn $name() {
      let ctx = Context::default();
      assert_eq!($func(&ctx, $input), $want);
    }
  };
}

// This function abstracts a call to a Rust function `f` and returns a
// result following C error handling conventions.
unsafe fn c_call<T>(
  f: fn(&Context, &T) -> Result<T, T>,
  ctx: *const Context,
  primitive: *const T,
  alternative: *mut T,
) -> c_int {
  if ctx.is_null() || primitive.is_null() {
    return -1;
  }

  let (recommendation, is_compliant) = match f(ctx.as_ref().unwrap(), primitive.as_ref().unwrap()) {
    Ok(recommendation) => (recommendation, true),
    Err(recommendation) => (recommendation, false),
  };

  if !alternative.is_null() {
    *alternative = recommendation;
  }

  is_compliant as c_int
}
