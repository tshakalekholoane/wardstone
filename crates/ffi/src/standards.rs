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
pub mod weak;
