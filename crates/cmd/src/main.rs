use std::path::PathBuf;

use clap::{Parser, Subcommand};
use wardstone::assess::{self, Guide};
use wardstone_core::context::Context;

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
    /// Guide to assess the certificate against.
    #[arg(short, long, value_enum)]
    guide: Guide,
    // TODO: Make positional argument to enable concurrent processing.
    /// The certificate as a DER or PEM encoded file.
    #[arg(short, long)]
    path: PathBuf,
    /// Verbose output.
    #[arg(short, long)]
    verbose: bool,
  },
}

fn main() -> Result<(), ()> {
  // TODO: Allow the user to set context variables.
  let ctx = Context::default();
  let options = Options::parse();
  match &options.subcommands {
    Subcommands::X509 {
      guide,
      path: certificate,
      verbose,
    } => assess::x509(&ctx, certificate, guide, verbose),
  }
}
