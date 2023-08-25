use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use wardstone::key::certificate::Certificate;
use wardstone::key::ssh::Ssh;
use wardstone::key::Key;
use wardstone::report::{Audit, Exit, Report, Verbosity};
use wardstone_core::context::Context;
use wardstone_core::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;
use wardstone_core::primitive::Security;
use wardstone_core::standard::bsi::Bsi;
use wardstone_core::standard::cnsa::Cnsa;
use wardstone_core::standard::ecrypt::Ecrypt;
use wardstone_core::standard::lenstra::Lenstra;
use wardstone_core::standard::nist::Nist;
use wardstone_core::standard::testing::strong::Strong;
use wardstone_core::standard::testing::weak::Weak;
use wardstone_core::standard::Standard;

// Having this type in the core crate would reduce the amount of case
// analysis done to find the function to execute but this would run
// counter to the ability of users to create their own first-class
// guides/standards.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Guide {
  /// BSI TR-02102 series of technical guidelines.
  Bsi,
  /// Commercial National Security Algorithm Suites, CNSA 1.0 and
  /// CNSA 2.0.
  Cnsa,
  /// ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report.
  Ecrypt,
  /// Key Lengths, Arjen K. Lenstra, The Handbook of Information
  /// Security, 06/2004.
  Lenstra,
  /// NIST Special Publication 800-57 Part 1 Revision 5 standard.
  Nist,
  /// Mock standard with a minimum security requirement of at least
  /// 256-bits.
  Strong,
  /// Mock standard with a minimum security requirement of at least
  /// 64-bits.
  Weak,
}

impl Guide {
  fn validate_hash_function(&self, ctx: Context, hash: Hash) -> Result<Hash, Hash> {
    match self {
      Self::Bsi => Bsi::validate_hash(ctx, hash),
      Self::Cnsa => Cnsa::validate_hash(ctx, hash),
      Self::Ecrypt => Ecrypt::validate_hash(ctx, hash),
      Self::Lenstra => Ecrypt::validate_hash(ctx, hash),
      Self::Nist => Nist::validate_hash(ctx, hash),
      Self::Strong => Strong::validate_hash(ctx, hash),
      Self::Weak => Weak::validate_hash(ctx, hash),
    }
  }

  fn validate_signature_algorithm(
    &self,
    ctx: Context,
    key: Asymmetric,
  ) -> Result<Asymmetric, Asymmetric> {
    match self {
      Self::Bsi => Bsi::validate_asymmetric(ctx, key),
      Self::Cnsa => Cnsa::validate_asymmetric(ctx, key),
      Self::Ecrypt => Ecrypt::validate_asymmetric(ctx, key),
      Self::Lenstra => Lenstra::validate_asymmetric(ctx, key),
      Self::Nist => Nist::validate_asymmetric(ctx, key),
      Self::Strong => Strong::validate_asymmetric(ctx, key),
      Self::Weak => Weak::validate_asymmetric(ctx, key),
    }
  }
}

/// Assess cryptographic keys for compliance.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Options {
  #[command(subcommand)]
  subcommands: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
  /// Check an SSH public key for compliance.
  Ssh {
    /// Guide to assess the key against.
    #[arg(short, long, value_enum)]
    guide: Guide,
    /// JSON formatted output.
    #[arg(short, long)]
    json: bool,
    /// Do not print output.
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
    /// The minimum security level required.
    ///
    /// If a sufficiently low value is used then the application will
    /// default to the minimum security specified by the standard.
    #[arg(short, long, default_value_t = 0)]
    security: Security,
    /// Verbose output.
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,
    /// The year in which a recommendation is expected to be valid.
    ///
    /// Note that this does not necessarily mean that a primitive will
    /// be deemed insecure beyond this point. Indeed, recommendations
    /// are usually done with a longer horizon in mind. For example,
    /// setting this value to 2023, one would expect any passing
    /// primitive to be secure for the next 5 to 7 years,
    /// conservatively, subject to cryptanalytic developments.
    #[arg(short, long, default_value_t = 2023)]
    year: u16,
    /// The paths to the public key file(s).
    #[clap(value_name = "FILE")]
    files: Vec<PathBuf>,
  },
  /// Check X.509 public key certificates for compliance.
  X509 {
    /// Guide to assess the certificate against.
    #[arg(short, long, value_enum)]
    guide: Guide,
    /// JSON formatted output.
    #[arg(short, long)]
    json: bool,
    /// Do not print output.
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
    /// The minimum security level required.
    ///
    /// If a sufficiently low value is used then the application will
    /// default to the minimum security specified by the standard.
    #[arg(short, long, default_value_t = 0)]
    security: Security,
    /// Verbose output.
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,
    /// The year in which a recommendation is expected to be valid.
    ///
    /// Note that this does not necessarily mean that a primitive will
    /// be deemed insecure beyond this point. Indeed, recommendations
    /// are usually done with a longer horizon in mind. For example,
    /// setting this value to 2023, one would expect any passing
    /// primitive to be secure for the next 5 to 7 years,
    /// conservatively, subject to cryptanalytic developments.
    #[arg(short, long, default_value_t = 2023)]
    year: u16,
    /// The certificates as DER or PEM encoded files.
    #[clap(value_name = "FILE")]
    files: Vec<PathBuf>,
  },
}

impl Subcommands {
  fn assess<T: Key>(
    ctx: Context,
    paths: &Vec<PathBuf>,
    guide: Guide,
    json: bool,
    verbosity: Verbosity,
  ) -> Exit {
    let mut report = Report::new(verbosity, json);
    for path in paths {
      let key = match T::from_file(path) {
        Ok(got) => got,
        Err(err) => return Exit::Failure(err),
      };
      let hash_function = key.hash_function();
      let signature_algorithm = key.signature_algorithm();
      let mut audit = Audit::new(path, hash_function, signature_algorithm);
      if let Some(got) = hash_function {
        match guide.validate_hash_function(ctx, got) {
          Ok(want) => audit.compliant_hash_function(want),
          Err(want) => audit.noncompliant_hash_function(want),
        }
      }
      match guide.validate_signature_algorithm(ctx, signature_algorithm) {
        Ok(want) => audit.compliant_signature(want),
        Err(want) => audit.noncompliant_signature(want),
      }
      report.push(audit);
    }
    Exit::Success(report)
  }

  pub fn run(&self) -> Exit {
    match self {
      Self::Ssh {
        guide,
        json,
        quiet,
        verbose,
        files,
        security,
        year,
      } => {
        let ctx = Context::new(*security, *year);
        let verbosity = Verbosity::from_flags(*verbose, *quiet);
        Self::assess::<Ssh>(ctx, files, *guide, *json, verbosity)
      },
      Self::X509 {
        guide,
        json,
        quiet,
        verbose,
        files,
        security,
        year,
      } => {
        let ctx = Context::new(*security, *year);
        let verbosity = Verbosity::from_flags(*verbose, *quiet);
        Self::assess::<Certificate>(ctx, files, *guide, *json, verbosity)
      },
    }
  }
}

fn main() -> Exit {
  let options = Options::parse();
  options.subcommands.run()
}
