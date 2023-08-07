use std::ffi::c_int;

use wardstone_core::context::Context;

/// A utility function that abstracts a call to a Rust function `f` and
/// returns a result following C error handling conventions.
pub(crate) unsafe fn c_call<T>(
  f: fn(Context, T) -> Result<T, T>,
  ctx: Context,
  primitive: T,
  alternative: *mut T,
) -> c_int {
  let (recommendation, is_compliant) = match f(ctx, primitive) {
    Ok(recommendation) => (recommendation, true),
    Err(recommendation) => (recommendation, false),
  };

  if !alternative.is_null() {
    *alternative = recommendation;
  }

  is_compliant as c_int
}
