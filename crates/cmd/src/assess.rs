use std::path::PathBuf;

use clap::ValueEnum;
use wardstone_core::context::Context;
use wardstone_core::primitive::hash::*;
use wardstone_core::standard::bsi::Bsi;
use wardstone_core::standard::cnsa::Cnsa;
use wardstone_core::standard::Standard;

use crate::adapter::SignatureAlgorithm;
use crate::key::certificate::Certificate;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Guide {
  /// The BSI TR-02102 series of technical guidelines.
  Bsi,
  Cnsa,
}

impl Guide {
  fn validate_hash_function(
    &self,
    ctx: &Context,
    hash: &Hash,
  ) -> Result<&'static Hash, &'static Hash> {
    match self {
      Self::Bsi => Bsi::validate_hash(ctx, hash),
      Self::Cnsa => Cnsa::validate_hash(ctx, hash),
    }
  }

  fn validate_signature_algorithm(
    &self,
    ctx: &Context,
    algorithm: &SignatureAlgorithm,
  ) -> Result<SignatureAlgorithm, SignatureAlgorithm> {
    match self {
      Self::Bsi => match algorithm {
        SignatureAlgorithm::Ecc(instance) => match Bsi::validate_ecc(ctx, instance) {
          Ok(instance) => Ok(SignatureAlgorithm::Ecc(instance)),
          Err(instance) => Err(SignatureAlgorithm::Ecc(instance)),
        },
        SignatureAlgorithm::Ifc(instance) => match Bsi::validate_ifc(ctx, instance) {
          Ok(instance) => Ok(SignatureAlgorithm::Ifc(instance)),
          Err(instance) => Err(SignatureAlgorithm::Ifc(instance)),
        },
      },
      Self::Cnsa => match algorithm {
        SignatureAlgorithm::Ecc(instance) => match Cnsa::validate_ecc(ctx, instance) {
          Ok(instance) => Ok(SignatureAlgorithm::Ecc(instance)),
          Err(instance) => Err(SignatureAlgorithm::Ecc(instance)),
        },
        SignatureAlgorithm::Ifc(instance) => match Cnsa::validate_ifc(ctx, instance) {
          Ok(instance) => Ok(SignatureAlgorithm::Ifc(instance)),
          Err(instance) => Err(SignatureAlgorithm::Ifc(instance)),
        },
      },
    }
  }
}

pub fn x509(ctx: &Context, path: &PathBuf, guide: &Guide, verbose: &bool) -> Result<(), ()> {
  let mut pass = Ok(());
  let certificate = Certificate::from_pem_file(path);
  let got = certificate.extract_hash_function();
  match guide.validate_hash_function(ctx, got) {
    Ok(want) => {
      if *verbose {
        println!("hash function: got: {}, want: {}", got, want)
      }
    },
    Err(want) => {
      pass = Err(());
      println!("hash function: got: {}, want: {}", got, want);
    },
  }

  let got = certificate.extract_signature_algorithm();
  match guide.validate_signature_algorithm(ctx, got) {
    Ok(want) => {
      if *verbose {
        println!("signature algorithm: got: {}, want: {}", got, want)
      }
    },
    Err(want) => {
      pass = Err(());
      println!("signature algorithm: got: {}, want: {}", got, want);
    },
  }
  // TODO: The following could probably be done as an error.
  match pass {
    Err(_) => println!("fail: {}", path.display()),
    Ok(_) => println!("ok: {}", path.display()),
  };
  pass
}
