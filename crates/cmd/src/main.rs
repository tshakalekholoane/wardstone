use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Termination};

use clap::{Parser, Subcommand, ValueEnum};
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

pub enum Status {
  Ok(PathBuf),
  Fail(PathBuf),
}

impl Termination for Status {
  fn report(self) -> ExitCode {
    match self {
      Self::Ok(_) => {
        println!("{}", &self);
        ExitCode::SUCCESS
      },
      Self::Fail(_) => {
        eprintln!("{}", &self);
        ExitCode::FAILURE
      },
    }
  }
}

impl fmt::Display for Status {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self {
      Self::Ok(path) => write!(f, "ok: {}", path.display()),
      Self::Fail(path) => write!(f, "fail: {}", path.display()),
    }
  }
}

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
  fn audit<T: Key>(ctx: Context, path: &Path, guide: Guide, verbose: bool) -> Status {
    let key = match T::from_file(path) {
      Ok(got) => got,
      Err(err) => {
        eprintln!("{}", err);
        return Status::Fail(path.to_path_buf());
      },
    };

    let mut pass = Status::Ok(path.to_path_buf());

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
    }

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

    pass
  }

  pub fn run(&self, ctx: Context) -> Status {
    match self {
      Self::Ssh {
        guide,
        path,
        verbose,
      } => Self::audit::<Ssh>(ctx, path, *guide, *verbose),
      Self::X509 {
        guide,
        path,
        verbose,
      } => Self::audit::<Certificate>(ctx, path, *guide, *verbose),
    }
  }
}

fn main() -> Status {
  let ctx = Context::default();
  let options = Options::parse();
  options.subcommands.run(ctx)
}
