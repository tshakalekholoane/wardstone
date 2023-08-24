//! A command-line application to scan cryptographic keys for
//! compliance.
//!
//! ```text
//! A tool to scan cryptographic keys and certificates against recognized
//! standards and research publications, verifying their compliance.
//!
//!
//! Usage: wardstone <COMMAND>
//!
//! Commands:
//!   ssh   Check an SSH public key for compliance
//!   x509  Check X.509 public key certificates for compliance
//!   help  Print this message or the help of the given subcommand(s)
//!
//! Options:
//!   -h, --help     Print help
//!   -V, --version  Print version
//! ```
pub mod key;
pub mod report;
