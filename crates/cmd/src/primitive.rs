//! Bridge types.
//!
//! Some types cannot go in the core crate because it has to stay
//! compatible with C. This crate holds convenience types that bridge
//! those types into more ergonomic ones used here.
pub mod asymmetric;
