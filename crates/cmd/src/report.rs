use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Termination};

use serde::Serialize;
use serde_json::json;
use wardstone_core::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;

use crate::key::Error;

pub enum Exit {
  Success(Report),
  Failure(Error),
}

impl Termination for Exit {
  fn report(self) -> ExitCode {
    match self {
      Exit::Success(report) => report.report(),
      Exit::Failure(err) => {
        eprintln!("{}", err);
        ExitCode::FAILURE
      },
    }
  }
}

/// Output verbosity level.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
  Quiet,
  Normal,
  Verbose,
}

impl Verbosity {
  pub fn from_flags(verbose: bool, quiet: bool) -> Verbosity {
    if quiet {
      Self::Quiet
    } else if verbose {
      Self::Verbose
    } else {
      Self::Normal
    }
  }

  pub fn is_quiet(self) -> bool {
    self == Verbosity::Quiet
  }

  pub fn is_verbose(self) -> bool {
    self == Verbosity::Verbose
  }
}

/// Represents an audit of a single key.
#[derive(Serialize)]
pub struct Audit {
  passed: bool,
  path: PathBuf,
  #[serde(skip_serializing_if = "Option::is_none")]
  got_hash_function: Option<Hash>,
  #[serde(skip_serializing_if = "Option::is_none")]
  want_hash_function: Option<Hash>,
  got_signature: Asymmetric,
  want_signature: Asymmetric,
}

impl Audit {
  pub fn new(path: &Path, hash: Option<Hash>, signature: Asymmetric) -> Self {
    Self {
      passed: true,
      path: path.to_path_buf(),
      got_hash_function: hash,
      want_hash_function: None,
      got_signature: signature,
      want_signature: signature,
    }
  }

  pub fn noncompliant_hash_function(&mut self, want: Hash) {
    self.passed = false;
    self.want_hash_function = Some(want);
  }

  pub fn compliant_hash_function(&mut self, want: Hash) {
    self.want_hash_function = Some(want);
  }

  pub fn noncompliant_signature(&mut self, want: Asymmetric) {
    self.passed = false;
    self.want_signature = want;
  }

  pub fn compliant_signature(&mut self, want: Asymmetric) {
    self.want_signature = want;
  }
}

impl Display for Audit {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    let mut s = String::new();
    if let (Some(got), Some(want)) = (self.got_hash_function, self.want_hash_function) {
      s.push_str(format!("hash function: got {}, want: {}\n", got, want).as_str());
    }
    s.push_str(
      format!(
        "signature algorithm: got {}, want: {}\n",
        self.got_signature, self.want_signature
      )
      .as_str(),
    );
    if self.passed {
      s.push_str(format!("ok: {}", self.path.display()).as_str());
    } else {
      s.push_str(format!("fail: {}", self.path.display()).as_str());
    }
    write!(f, "{s}")
  }
}

/// Status report of a series of key audits.
pub struct Report {
  audits: Vec<Audit>,
  verbosity: Verbosity,
  json: bool,
}

impl Report {
  pub fn new(verbosity: Verbosity, json: bool) -> Self {
    Self {
      audits: Vec::new(),
      verbosity,
      json,
    }
  }

  pub fn push(&mut self, audit: Audit) {
    self.audits.push(audit);
  }

  pub fn to_json_string(&self) -> String {
    let mut v = Vec::new();
    for audit in self.audits.iter() {
      if audit.passed {
        if self.verbosity.is_verbose() {
          v.push(audit)
        }
      } else {
        v.push(audit)
      }
    }
    // Partition by compliance status.
    let (mut v, failed): (Vec<_>, Vec<_>) = v.into_iter().partition(|a| a.passed);
    v.extend::<Vec<&Audit>>(failed);
    json!({ "report": &v }).to_string()
  }
}

impl Display for Report {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    // Partition by compliance status.
    let (mut v, failed): (Vec<_>, Vec<_>) = self.audits.iter().partition(|a| a.passed);
    v.extend::<Vec<&Audit>>(failed);
    let mut s = String::new();
    for audit in v.iter() {
      if audit.passed {
        if self.verbosity.is_verbose() {
          s.push_str(format!("{}\n", audit).as_str());
        }
      } else {
        s.push_str(format!("{}\n", audit).as_str())
      }
    }
    write!(f, "{}", s)
  }
}

impl Termination for Report {
  fn report(self) -> ExitCode {
    let (failed, _): (Vec<_>, Vec<_>) = self.audits.iter().partition(|audit| !audit.passed);
    if !self.verbosity.is_quiet() {
      let repr = if self.json {
        self.to_json_string()
      } else {
        format!("{}", self)
      };
      print!("{}", repr)
    }
    if failed.is_empty() {
      ExitCode::SUCCESS
    } else {
      ExitCode::FAILURE
    }
  }
}
