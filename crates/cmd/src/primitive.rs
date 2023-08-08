//! Bridge types.
//!
//! Provides ways to map types between multiple crates. For example, the
//! types in `wardstone_core` do not have string representations because
//! it is difficult to bridge wide types safely. It also provides a
//! mapping between OpenSSL types and those used here to enable seamless
//! parsing of keys generated using that library.
pub mod asymmetric;
pub mod hash_func;
