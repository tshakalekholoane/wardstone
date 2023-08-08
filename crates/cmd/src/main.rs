use std::fmt;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};

use clap::{Parser, Subcommand, ValueEnum};
use wardstone::key::certificate::Certificate;
use wardstone::primitive::asymmetric::Asymmetric;
use wardstone::primitive::hash_func::HashFunc;
use wardstone_core::context::Context;
use wardstone_core::standard::bsi::Bsi;
use wardstone_core::standard::cnsa::Cnsa;
use wardstone_core::standard::Standard;

pub enum Status {
  Ok(PathBuf),
  Fail(PathBuf),
}

impl Termination for Status {
  fn report(self) -> std::process::ExitCode {
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

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Guide {
  /// The BSI TR-02102 series of technical guidelines.
  Bsi,
  Cnsa,
}

impl Guide {
  fn validate_hash_function(&self, ctx: Context, hash: &HashFunc) -> Result<HashFunc, HashFunc> {
    let hash = hash.func;
    match self {
      Self::Bsi => Bsi::validate_hash(ctx, hash)
        .map(Into::into)
        .map_err(Into::into),
      Self::Cnsa => Cnsa::validate_hash(ctx, hash)
        .map(Into::into)
        .map_err(Into::into),
    }
  }

  fn validate_signature_algorithm(
    &self,
    ctx: Context,
    algorithm: &Asymmetric,
  ) -> Result<Asymmetric, Asymmetric> {
    match self {
      Self::Bsi => match algorithm {
        Asymmetric::Ecc { algorithm, .. } => Bsi::validate_ecc(ctx, *algorithm)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc { .. } => todo!(),
      },
      Self::Cnsa => match algorithm {
        Asymmetric::Ecc { algorithm, .. } => Cnsa::validate_ecc(ctx, *algorithm)
          .map(Into::into)
          .map_err(Into::into),
        Asymmetric::Ifc { .. } => todo!(),
      },
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
  fn x509(ctx: Context, path: &PathBuf, guide: Guide, verbose: bool) -> Status {
    let certificate = match Certificate::from_pem_file(path) {
      Ok(got) => got,
      Err(err) => {
        eprintln!("{}", err);
        return Status::Fail(path.to_path_buf());
      },
    };

    let mut pass = Status::Ok(path.to_path_buf());

    if let Some(got) = certificate.extract_hash_function() {
      match guide.validate_hash_function(ctx, &got) {
        Ok(want) => {
          if verbose {
            println!("hash function: got: {}, want: {}", got, want)
          }
        },
        Err(want) => {
          pass = Status::Fail(path.to_path_buf());
          eprintln!("hash function: got: {}, want: {}", got, want);
        },
      }
    }

    if let Some(got) = certificate.extract_signature_algorithm() {
      match guide.validate_signature_algorithm(ctx, &got) {
        Ok(want) => {
          if verbose {
            println!("signature algorithm: got: {}, want: {}", got, want)
          }
        },
        Err(want) => {
          pass = Status::Fail(path.to_path_buf());
          eprintln!("signature algorithm: got: {}, want: {}", got, want);
        },
      }
    }

    pass
  }

  pub fn run(&self, ctx: Context) -> Status {
    match self {
      Self::X509 {
        guide,
        path,
        verbose,
      } => Self::x509(ctx, path, *guide, *verbose),
    }
  }
}

fn main() -> Status {
  let ctx = Context::default();
  let options = Options::parse();
  options.subcommands.run(ctx)
}
