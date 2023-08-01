use std::ffi::c_int;

use wardstone_core::context::Context;

/// A utility function that abstracts a call to a Rust function `f` and
/// returns a result following C error handling conventions.
pub(crate) unsafe fn c_call<T: Clone>(
  f: fn(&Context, &T) -> Result<&'static T, &'static T>,
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
    *alternative = recommendation.clone();
  }

  is_compliant as c_int
}
