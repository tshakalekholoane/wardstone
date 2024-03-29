# Wardstone Core

![Continuous Integration](https://github.com/tshakalekholoane/wardstone/actions/workflows/ci.yaml/badge.svg)

The `wardstone_core` library contains logic to assess cryptographic primitives against various standards and research publications.

For example, if one wanted to assess whether the [SHA-256](https://doi.org/10.6028/NIST.FIPS.180-4) hash function is valid based on the [guidance made by the NSA](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF), they would execute the following lines of code.

```rust
use wardstone_core::context::Context;
use wardstone_core::primitive::hash::{SHA256, SHA384};
use wardstone_core::standard::cnsa::Cnsa;
use wardstone_core::standard::Standard;

let ctx = Context::default();
assert_eq!(Cnsa::validate_hash(ctx, SHA256), Err(SHA384));
```

Since the NSA no longer recommends the use of the SHA-256 algorithm, an alternative, the SHA-384 hash function, is suggested as the value contained in the returned result `Err` based on the `Context` which the user can customise to specify parameters such as the year in which they expect the primitive to stay secure according to estimates about cryptanalytic progress and the minimum overall security that they might require for their use case.
