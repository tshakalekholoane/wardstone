use std::path::PathBuf;

use clap::{Parser, Subcommand};
use wardstone::assess::{self, Guide};

/// Assess cryptographic keys for compliance.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Options {
  #[command(subcommand)]
  subcommands: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
  /// Check an X.509 public key certificate for compliance.
  X509 {
    /// The certificate as a DER or PEM encoded file.
    #[arg(short, long, value_name = "FILE")]
    path: PathBuf,
    /// Guide to assess the certificate against.
    #[arg(short, long, value_enum)]
    guide: Guide,
  },
}

fn main() {
  let options = Options::parse();
  match &options.subcommands {
    Subcommands::X509 { guide, path } => assess::x509(path, guide),
  }
}
