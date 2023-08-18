use std::path::PathBuf;
use std::process::{ExitCode, Termination};

use wardstone::key;
use wardstone::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;

use crate::Verbosity;

const INDENT: &str = "         ";

pub(crate) enum GoodPath {
  Hash(Hash, Hash),
  SigAlg(Asymmetric, Asymmetric),
}

impl GoodPath {
  fn display(&self, form: ReportFormat) -> String {
    match form {
      ReportFormat::HumanReadable => match self {
        GoodPath::Hash(got, want) => {
          format!("{INDENT}OK hash function(got: {got}, want: {want})")
        },
        GoodPath::SigAlg(got, want) => {
          format!("{INDENT}OK signature algorithm(got: {got}, want: {want})")
        },
      },
    }
  }
}

pub(crate) enum BadPath {
  ReadError(key::Error),
  MismatchedHash(Hash, Hash),
  MismatchedSigAlg(Asymmetric, Asymmetric),
}

impl BadPath {
  fn display(&self, form: ReportFormat) -> String {
    match form {
      ReportFormat::HumanReadable => match self {
        BadPath::ReadError(e) => format!("{e}"),
        BadPath::MismatchedHash(got, want) => {
          format!("{INDENT}FAILED hash function(got: {got}, want: {want})")
        },
        BadPath::MismatchedSigAlg(got, want) => {
          format!("{INDENT}FAILED signature algorithm(got: {got}, want: {want})")
        },
      },
    }
  }
}

type CheckResult = Result<GoodPath, BadPath>;

pub(crate) struct CheckedPath {
  path: PathBuf,
  results: Vec<CheckResult>,
}

impl CheckedPath {
  pub(crate) fn new(path: PathBuf) -> Self {
    Self {
      path,
      results: vec![],
    }
  }

  pub(crate) fn push(&mut self, res: CheckResult) {
    self.results.push(res)
  }

  pub(crate) fn is_err(&self) -> bool {
    self.results.iter().any(|r| r.is_err())
  }
}

impl CheckedPath {
  fn display(&self, form: ReportFormat, verbosity: Verbosity) -> String {
    let mut results = vec![];
    let mut is_err = false;
    for r in &self.results {
      match r {
        Ok(r) => {
          if verbosity == Verbosity::Verbose {
            results.push(r.display(form));
          }
        },
        Err(r) => {
          is_err = true;
          results.push(r.display(form));
        },
      }
    }

    let mut f = String::new();
    match form {
      ReportFormat::HumanReadable => {
        if is_err {
          f += "[FAIL]: ";
        } else {
          f += "[PASS]: ";
        }
        f += &format!("{}", self.path.display());
        if !results.is_empty() {
          f += "\n";
          f += &results.join("\n");
        }
      },
    }
    f
  }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ReportFormat {
  HumanReadable,
  // JSON,
}

pub(crate) struct Report {
  results: Vec<CheckedPath>,
  verbosity: Verbosity,
  form: ReportFormat,
}

impl Report {
  pub(crate) fn new(form: ReportFormat, verbosity: Verbosity) -> Self {
    Self {
      results: Vec::new(),
      verbosity,
      form,
    }
  }

  pub(crate) fn push(&mut self, path: CheckedPath) {
    self.results.push(path);
  }
}

impl Termination for Report {
  fn report(self) -> ExitCode {
    // Sort by result-state
    let (failed, ok): (Vec<_>, Vec<_>) = self.results.iter().partition(|r| r.is_err());

    if self.verbosity != Verbosity::Quiet {
      for res in ok {
        println!("{}", res.display(self.form, self.verbosity));
      }
    }

    for res in &failed {
      eprintln!("{}", res.display(self.form, self.verbosity));
    }

    if failed.is_empty() {
      ExitCode::SUCCESS
    } else {
      ExitCode::FAILURE
    }
  }
}
