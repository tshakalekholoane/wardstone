use clap::ValueEnum;
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
  fn display(&self, format: ReportFormat) -> String {
    match format {
      ReportFormat::Human => match self {
        GoodPath::Hash(got, want) => {
          format!("{INDENT}OK hash function(got: {got}, want: {want})")
        },
        GoodPath::SigAlg(got, want) => {
          format!("{INDENT}OK signature algorithm(got: {got}, want: {want})")
        },
      },
      ReportFormat::JSON => match self {
        GoodPath::Hash(got, want) => {
          format!(r#""hash_function": {{ "passed": true, "got": "{got}", "want": "{want}" }}"#)
        },
        GoodPath::SigAlg(got, want) => {
          format!(
            r#""signature_algorithm": {{ "passed": true, "got": "{got}", "want": "{want}" }}"#
          )
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
      ReportFormat::Human => match self {
        BadPath::ReadError(e) => format!("{e}"),
        BadPath::MismatchedHash(got, want) => {
          format!("{INDENT}FAILED hash function(got: {got}, want: {want})")
        },
        BadPath::MismatchedSigAlg(got, want) => {
          format!("{INDENT}FAILED signature algorithm(got: {got}, want: {want})")
        },
      },
      ReportFormat::JSON => match self {
        BadPath::ReadError(e) => format!(r#"{INDENT}"error": "{e}""#),
        BadPath::MismatchedHash(got, want) => {
          format!(r#""hash_function": {{ "passed": false, "got": "{got}", "want": "{want}" }}"#)
        },
        BadPath::MismatchedSigAlg(got, want) => {
          format!(
            r#""signature_algorithm": {{ "passed": false, "got": "{got}", "want": "{want}" }}"#
          )
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
  fn display(&self, format: ReportFormat, verbosity: Verbosity) -> String {
    let mut results = vec![];
    let mut is_err = false;
    for r in &self.results {
      match r {
        Ok(r) => {
          if verbosity == Verbosity::Verbose {
            results.push(r.display(format));
          }
        },
        Err(r) => {
          is_err = true;
          results.push(r.display(format));
        },
      }
    }

    let mut f;
    match format {
      ReportFormat::Human => {
        if is_err {
          f = format!("[FAIL]: {}", self.path.display());
        } else {
          f = format!("[PASS]: {}", self.path.display());
        }
        if !results.is_empty() {
          f += "\n";
          f += &results.join("\n");
        }
      },
      ReportFormat::JSON => {
        let path = format!(r#""path": "{}""#, self.path.display());
        let status = format!(r#""passed": {:?}"#, !is_err);
        results.insert(0, path);
        results.insert(1, status);
        f = format!("{{ {} }}", results.join(", "));
      },
    }
    f
  }
}

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
pub(crate) enum ReportFormat {
  /// Output in human readable format
  Human,
  /// Output in JSON format
  JSON,
}

pub(crate) struct Report {
  results: Vec<CheckedPath>,
  verbosity: Verbosity,
  format: ReportFormat,
}

impl Report {
  pub(crate) fn new(format: ReportFormat, verbosity: Verbosity) -> Self {
    Self {
      results: Vec::new(),
      verbosity,
      format,
    }
  }

  pub(crate) fn push(&mut self, path: CheckedPath) {
    self.results.push(path);
  }
}

impl Termination for Report {
  fn report(self) -> ExitCode {
    // Sort by result-state
    let (failed, mut ok): (Vec<_>, Vec<_>) = self.results.iter().partition(|r| r.is_err());

    match self.format {
      ReportFormat::Human => {
        if self.verbosity != Verbosity::Quiet {
          for res in ok {
            println!("{}", res.display(self.format, self.verbosity));
          }
        }

        for res in &failed {
          eprintln!("{}", res.display(self.format, self.verbosity));
        }
      },
      ReportFormat::JSON => {
        if self.verbosity == Verbosity::Quiet {
          ok.clear()
        };
        let json: Vec<_> = ok
          .iter()
          .chain(failed.iter())
          .map(|r| r.display(self.format, self.verbosity))
          .collect();
        println!("[{}]", json.join(", "));
      },
    }

    if failed.is_empty() {
      ExitCode::SUCCESS
    } else {
      ExitCode::FAILURE
    }
  }
}
