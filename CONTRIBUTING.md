# Guidelines

## Contributing Test Cases for Validating X.509 Certificates

The easiest way to contribute test cases is to run the [`generate_certificates.py`](./scripts/generate_certificates.py) script and file a pull request with the changes if it was able to generate new test certificates that were not already [present in the repository](./crates/cmd/src/testing/certificates/).

Additionally, run the following command where the input is the newly generated certificate. The error message will contain an object identifier which will be used to identify the primitives used in the certificate where `$new_certificate` represents the newly generated certificate.

```bash
wardstone x509 --guide bsi --path ./crates/cmd/src/testing/certificates/$new_certificate
```

This should be enough but if you want to go further, you can lookup the object identifier in a registry such as the [Object Identifier (OID) Repository](https://oid-rep.orange-labs.fr) and update the tables in [`certificate.rs`](./crates/cmd/src/key/certificate.rs) along with the instances in the [`core`](./crates/core/src/primitive/) crate.
