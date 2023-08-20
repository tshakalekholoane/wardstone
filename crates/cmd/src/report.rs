use clap::ValueEnum;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};
use wardstone::key;
use wardstone::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;

use crate::Verbosity;

const INDENT: &str = "         ";

#[derive(Debug)]
pub(crate) enum PassedAudit {
  Hash(Hash, Hash),
  SigAlg(Asymmetric, Asymmetric),
}

impl PassedAudit {
  fn display(&self, format: ReportFormat) -> String {
    match format {
      ReportFormat::Human => match self {
        PassedAudit::Hash(got, want) => {
          format!("{INDENT}OK hash function(got: {got}, want: {want})")
        },
        PassedAudit::SigAlg(got, want) => {
          format!("{INDENT}OK signature algorithm(got: {got}, want: {want})")
        },
      },
      ReportFormat::Json => match self {
        PassedAudit::Hash(got, want) => {
          format!(r#""hash_function": {{ "passed": true, "got": "{got}", "want": "{want}" }}"#)
        },
        PassedAudit::SigAlg(got, want) => {
          format!(
            r#""signature_algorithm": {{ "passed": true, "got": "{got}", "want": "{want}" }}"#
          )
        },
      },
    }
  }
}

#[derive(Debug)]
pub(crate) enum FailedAudit {
  ReadError(key::Error),
  NoncompliantHash(Hash, Hash),
  NoncompliantSignatureAlg(Asymmetric, Asymmetric),
}

impl FailedAudit {
  fn display(&self, form: ReportFormat) -> String {
    match form {
      ReportFormat::Human => match self {
        FailedAudit::ReadError(e) => format!("{e}"),
        FailedAudit::NoncompliantHash(got, want) => {
          format!("{INDENT}FAILED hash function(got: {got}, want: {want})")
        },
        FailedAudit::NoncompliantSignatureAlg(got, want) => {
          format!("{INDENT}FAILED signature algorithm(got: {got}, want: {want})")
        },
      },
      ReportFormat::Json => match self {
        FailedAudit::ReadError(e) => format!(r#"{INDENT}"error": "{e}""#),
        FailedAudit::NoncompliantHash(got, want) => {
          format!(r#""hash_function": {{ "passed": false, "got": "{got}", "want": "{want}" }}"#)
        },
        FailedAudit::NoncompliantSignatureAlg(got, want) => {
          format!(
            r#""signature_algorithm": {{ "passed": false, "got": "{got}", "want": "{want}" }}"#
          )
        },
      },
    }
  }
}

type AuditResult = Result<PassedAudit, FailedAudit>;

#[derive(Debug)]
pub(crate) struct Audit {
  path: PathBuf,
  results: Vec<AuditResult>,
}

impl Audit {
  pub(crate) fn new(path: PathBuf) -> Self {
    Self {
      path,
      results: vec![],
    }
  }

  pub(crate) fn push(&mut self, res: AuditResult) {
    self.results.push(res)
  }

  pub(crate) fn is_err(&self) -> bool {
    self.results.iter().any(|r| r.is_err())
  }
}

impl Audit {
  fn display(&self, format: ReportFormat, verbosity: Verbosity) -> String {
    let mut results = vec![];
    let mut is_err = false;
    for r in &self.results {
      match r {
        Ok(r) => {
          if verbosity.is_verbose() {
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
      ReportFormat::Json => {
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
  Json,
}

#[derive(Debug)]
pub(crate) struct Report {
  results: Vec<Audit>,
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

  pub(crate) fn push(&mut self, path: Audit) {
    self.results.push(path);
  }
}

impl Termination for Report {
  fn report(self) -> ExitCode {
    // Sort by result-state
    let (failed, mut ok): (Vec<_>, Vec<_>) = self.results.iter().partition(|r| r.is_err());

    match self.format {
      ReportFormat::Human => {
        if !self.verbosity.is_quiet() {
          for res in ok {
            println!("{}", res.display(self.format, self.verbosity));
          }
        }

        for res in &failed {
          eprintln!("{}", res.display(self.format, self.verbosity));
        }
      },
      ReportFormat::Json => {
        if self.verbosity.is_quiet() {
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
