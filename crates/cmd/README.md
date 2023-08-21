# `wardstone`

A tool to scan cryptographic keys and certificates against recognized standards and research publications, verifying their compliance.

```
Assess cryptographic keys for compliance

Usage: wardstone <COMMAND>

Commands:
  x509  Check an X.509 public key certificate for compliance
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Installation

### Building from Source

This can be done using `cargo` and the resulting binary will be located in the root directory's `target/release/` folder.

```shell
cargo build --release 
```

On some operating systems you may need to download the development branch of the OpenSSL library i.e., `libssl-dev` on Ubuntu or `openssl-dev` on Fedora.
