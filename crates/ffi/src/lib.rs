//! # Wardstone FFI
//!
//! The `wardstone_ffi` library contains a subset of the
//! `wardstone_core` functionality. It's main purpose is to expose a C
//! API that can be used to interface with other programming languages
//! that support it.
//!
//! It uses [`cbindgen`] to generate C/C++ headers and dynamic and
//! static libraries that can be found in the `target` directory after
//! building the crate.
//!
//! The following is a C example that illustrates how this API can be
//! used from other programming languages:
//!
//! ```c
//! #include "wardstone.h"
//! #include <assert.h>
//! #include <stdbool.h>
//! #include <stdint.h>
//! #include <string.h>
//!
//! int main(void) {
//!   struct ws_hash got;
//!   struct ws_hash want = SHA224;
//!   struct ws_context ctx = context_default();
//!   assert(ws_nist_validate_hash(&ctx, &SHA1, &got) == false && "SHA1 should fail");
//!   assert(got.id == want.id && "unexpected hash function recommendation");
//!   assert(ws_nist_validate_hash(&ctx, &SHA256, NULL) == true && "SHA256 should pass");
//!   assert(ws_nist_validate_hash(NULL, NULL, NULL) == -1 && "null pointer should err");
//! }
//! ```
//!
//! [`cbindgen`]: https://github.com/mozilla/cbindgen
pub mod context;
pub mod standards;
