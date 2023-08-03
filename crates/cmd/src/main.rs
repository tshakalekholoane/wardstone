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
    /// The certificate as a DER or PEM encoded file.
    #[arg(short, long)]
    path: PathBuf,
    /// Verbose output.
    #[arg(short, long)]
    verbose: bool,
  },
}

impl Subcommands {
  pub fn run(&self, ctx: &Context) -> Result<(), ()> {
    match self {
      Self::X509 {
        guide,
        path,
        verbose,
      } => assess::x509(ctx, path, guide, verbose),
    }
  }
}

fn main() -> Result<(), ()> {
  let ctx = Context::default();
  let options = Options::parse();
  options.subcommands.run(&ctx)
}
