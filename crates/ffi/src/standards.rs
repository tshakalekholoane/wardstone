//! Submodules that validate cryptographic primitives according to
//! selected standards and research publications.
//!
//! # Safety
//!
//! This module contains functions that use raw pointers as arguments
//! for reading and writing data. However, this is only for the C API
//! that is exposed to interact with safe Rust equivalents. The C API is
//! essentially a wrapper around the Rust function to maintain
//! consistency with existing conventions.
//!
//! Checks against null dereferences are made in which the function will
//! return `-1` if the argument is required.pub mod bsi;
pub mod bsi;
pub mod cnsa;
pub mod ecrypt;
pub mod lenstra;
pub mod nist;
use std::ffi::c_int;

use wardstone_core::context::Context;

// A utility function that abstracts a call to a Rust function `f` and
// returns a result following C error handling conventions.
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
