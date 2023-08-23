mod report;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Termination};
use clap::{Parser, Subcommand, ValueEnum};
use report::{Audit, FailedAudit, PassedAudit, Report, ReportFormat};
use std::path::PathBuf;
use wardstone::key::certificate::Certificate;
use wardstone::key::ssh::Ssh;
use wardstone::key::Key;
use wardstone_core::context::Context;
use wardstone_core::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;
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
pub enum Guide {
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Verbosity {
  Quiet,
  Normal,
  Verbose,
}

impl Verbosity {
  pub(crate) fn is_quiet(&self) -> bool {
    self == &Verbosity::Quiet
  }

  pub(crate) fn is_verbose(&self) -> bool {
    self == &Verbosity::Verbose
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
    /// The path to the public key file.
    #[arg(short, long)]
    path: PathBuf,
    /// Verbose output.
    #[arg(short, long)]
    verbose: bool,
  },
  /// Check X.509 public key certificates for compliance.
  X509 {
    /// Guide to assess the certificate against.
    #[arg(short, long, value_enum)]
    guide: Guide,
    /// The certificates as DER or PEM encoded files.
    #[clap(value_name = "FILE")]
    paths: Vec<PathBuf>,
    /// Verbose output.
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,
    /// Quiet output: Hide all but errors/failed paths.
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
    #[arg(long)]
    /// Use JSON-format for output
    json: bool,
  },
}

impl Subcommands {
  fn x509(
    ctx: Context,
    paths: &Vec<PathBuf>,
    guide: Guide,
    format: ReportFormat,
    verbosity: Verbosity,
  ) -> Report {
    let mut report = Report::new(format, verbosity);
    for path in paths {
      let mut checked = Audit::new(path.to_path_buf());
      let certificate = match Certificate::from_file(path) {
        Ok(cert) => cert,
        Err(err) => {
          checked.push(Err(FailedAudit::ReadError(err)));
          continue;
        },
      };

  fn audit<T: Key>(ctx: Context, path: &Path, guide: Guide, verbose: bool) -> Status {
    let key = match T::from_file(path) {
      Ok(got) => got,
      Err(err) => {
        eprintln!("{}", err);
        return Status::Fail(path.to_path_buf());
      },
    };


      if let Some(got) = certificate.hash_function() {
        match guide.validate_hash_function(ctx, got) {
          Ok(want) => checked.push(Ok(PassedAudit::Hash(got, want))),
          Err(want) => checked.push(Err(FailedAudit::NoncompliantHash(got, want))),
        }
      }
      let got = certificate.signature_algorithm();
      match guide.validate_signature_algorithm(ctx, got) {
        Ok(want) => checked.push(Ok(PassedAudit::SigAlg(got, want))),
        Err(want) => checked.push(Err(FailedAudit::NoncompliantSignatureAlg(got, want))),
    if let Some(got) = key.hash_function() {
      match guide.validate_hash_function(ctx, got) {
        Ok(want) => {
          if verbose {
            println!("hash function: got {}, want: {}", got, want)
          }
        },
        Err(want) => {
          pass = Status::Fail(path.to_path_buf());
          eprintln!("hash function: got {}, want: {}", got, want);
        },
      }
      report.push(checked);
    let got = key.signature_algorithm();
    match guide.validate_signature_algorithm(ctx, got) {
      Ok(want) => {
        if verbose {
          println!("signature algorithm: got {}, want: {}", got, want)
        }
      },
      Err(want) => {
        pass = Status::Fail(path.to_path_buf());
        eprintln!("signature algorithm: got {}, want: {}", got, want);
      },
    }
    report
  }

  pub fn run(&self, ctx: Context) -> Report {
    match self {
      Self::Ssh {
        guide,
        path,
        verbose,
      } => Self::audit::<Ssh>(ctx, path, *guide, *verbose),
      Self::X509 {
        guide,
        paths,
        verbose,
        quiet,
        json,
      } => {
        let verbosity = if *quiet {
          Verbosity::Quiet
        } else if *verbose {
          Verbosity::Verbose
        } else {
          Verbosity::Normal
        };
        let format = if *json {
          ReportFormat::Json
        } else {
          ReportFormat::Human
        };
        Self::x509(ctx, paths, *guide, format, verbosity)
      },
      } => Self::audit::<Certificate>(ctx, path, *guide, *verbose),
    }
  }
}

fn main() -> Report {
  let ctx = Context::default();
  let options = Options::parse();
  options.subcommands.run(ctx)
}
