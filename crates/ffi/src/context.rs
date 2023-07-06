//! Specifies the context in which a cryptographic primitive will be
//! assessed against.
use wardstone_core::context::Context;

/// Creates a context which will default to the year 2023 and will use
/// the minimum security defined by the standard.
#[no_mangle]
pub extern "C" fn ws_context_default() -> Context {
  Context::default()
}
