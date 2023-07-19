use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Assess cryptographic keys for compliance.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Options {
  #[command(subcommand)]
  subcommands: Subcommands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Guide {
  /// The BSI TR-02102 series of technical guidelines.
  Bsi,
}

#[derive(Subcommand)]
enum Subcommands {
  /// Check an X.509 public key certificate for compliance.
  X509 {
    /// Guide to assess the certificate against.
    #[arg(short, long, value_enum)]
    guide: Guide,
    /// The certificate as a DER or PEM encoded file.
    #[arg(short, long, value_name = "FILE")]
    certificate: PathBuf,
  },
}

fn main() {
  let options = Options::parse();
  match &options.subcommands {
    Subcommands::X509 { guide, certificate } => {
      println!(
        "debug: assess the X.509 certificate at {:?} for {:?} compliance",
        certificate, guide
      );
    },
  }
}
