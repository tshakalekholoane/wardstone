use std::fmt;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};

use wardstone::key;
use wardstone::primitive::asymmetric::Asymmetric;
use wardstone_core::primitive::hash::Hash;

const INDENT: &str = "         ";

pub enum GoodPath {
  Hash(Hash, Hash),
  SigAlg(Asymmetric, Asymmetric),
}

impl fmt::Display for GoodPath {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      GoodPath::Hash(got, want) => {
        write!(f, "{INDENT}OK hash function(got: {got}, want: {want})")
      },
      GoodPath::SigAlg(got, want) => {
        write!(
          f,
          "{INDENT}OK signature algorithm(got: {got}, want: {want})"
        )
      },
    }
  }
}

pub enum BadPath {
  ReadError(key::Error),
  MismatchedHash(Hash, Hash),
  MismatchedSigAlg(Asymmetric, Asymmetric),
}

impl fmt::Display for BadPath {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      BadPath::ReadError(e) => write!(f, "{e}"),
      BadPath::MismatchedHash(got, want) => {
        write!(f, "{INDENT}FAILED hash function(got: {got}, want: {want})")
      },
      BadPath::MismatchedSigAlg(got, want) => {
        write!(
          f,
          "{INDENT}FAILED signature algorithm(got: {got}, want: {want})"
        )
      },
    }
  }
}

type CheckResult = Result<GoodPath, BadPath>;

pub struct CheckedPath {
  path: PathBuf,
  results: Vec<CheckResult>,
}

impl CheckedPath {
  pub fn new(path: PathBuf) -> Self {
    Self {
      path,
      results: vec![],
    }
  }

  pub fn push(&mut self, res: CheckResult) {
    self.results.push(res)
  }

  pub fn is_err(&self) -> bool {
    self.results.iter().any(|r| r.is_err())
  }
}

impl fmt::Display for CheckedPath {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut results = vec![];
    let mut is_err = false;
    for r in &self.results {
      match r {
        Ok(r) => {
          let report = format!("{r}"); // May be empty, depending on verbosity
          if !report.is_empty() {
            results.push(report);
          }
        },
        Err(r) => {
          is_err = true;
          results.push(format!("{r}"));
        },
      }
    }

    if is_err {
      write!(f, "[FAIL]: ")?;
    } else {
      write!(f, "[PASS]: ")?;
    }
    write!(f, "{}", self.path.display())?;
    if !results.is_empty() {
      writeln!(f)?;
      write!(f, "{}", results.join("\n"))?;
    }
    Ok(())
  }
}

pub struct Report(Vec<CheckedPath>);

impl Report {
  pub fn new() -> Self {
    Self(Vec::new())
  }

  pub fn push(&mut self, path: CheckedPath) {
    self.0.push(path);
  }
}

impl Termination for Report {
  fn report(self) -> ExitCode {
    // Sort by result-state
    let (failed, ok): (Vec<_>, Vec<_>) = self.0.iter().partition(|r| r.is_err());

    for res in ok {
      println!("{res}");
    }

    for res in &failed {
      eprintln!("{res}");
    }

    if failed.is_empty() {
      ExitCode::SUCCESS
    } else {
      ExitCode::FAILURE
    }
  }
}
