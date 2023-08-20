mod report;
use clap::{Parser, Subcommand, ValueEnum};
use report::{Audit, FailedAudit, PassedAudit, Report, ReportFormat};
use std::path::PathBuf;
use wardstone::key::certificate::Certificate;
use wardstone::primitive::asymmetric::Asymmetric;
use wardstone_core::context::Context;
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
    asymmetric: Asymmetric,
  ) -> Result<Asymmetric, Asymmetric> {
    match self {
      Self::Bsi => match asymmetric {
        Asymmetric::Ecc(ecc) => Bsi::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Bsi::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
      Self::Cnsa => match asymmetric {
        Asymmetric::Ecc(ecc) => Cnsa::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Cnsa::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
      Self::Ecrypt => match asymmetric {
        Asymmetric::Ecc(ecc) => Ecrypt::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Ecrypt::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
      Self::Lenstra => match asymmetric {
        Asymmetric::Ecc(ecc) => Lenstra::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Lenstra::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
      Self::Nist => match asymmetric {
        Asymmetric::Ecc(ecc) => Nist::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Nist::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
      Self::Strong => match asymmetric {
        Asymmetric::Ecc(ecc) => Strong::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Strong::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
      Self::Weak => match asymmetric {
        Asymmetric::Ecc(ecc) => Weak::validate_ecc(ctx, ecc)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc(ifc) => Weak::validate_ifc(ctx, ifc)
          .map(Into::into)
          .map_err(Into::into),
      },
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

    #[arg(short, long, value_enum, default_value_t=ReportFormat::Human)]
    /// Which format the output will be in
    format: ReportFormat,
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
      }

      report.push(checked);
    }
    report
  }

  pub fn run(&self, ctx: Context) -> Report {
    match self {
      Self::X509 {
        guide,
        paths,
        verbose,
        quiet,
        format,
      } => {
        let verbosity = if *quiet {
          Verbosity::Quiet
        } else if *verbose {
          Verbosity::Verbose
        } else {
          Verbosity::Normal
        };
        Self::x509(ctx, paths, *guide, *format, verbosity)
      },
    }
  }
}

fn main() -> Report {
  let ctx = Context::default();
  let options = Options::parse();
  options.subcommands.run(ctx)
}
