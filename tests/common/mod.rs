//! Loaders for the golden fixtures under `tests/fixtures`.

#![allow(dead_code)]

pub mod harness;
pub mod http;
pub mod process;
pub mod release;
pub mod stream;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Reads a text fixture; a `.gz` file is decompressed.
pub fn read_text(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    if path.extension().is_some_and(|extension| extension == "gz") {
        let mut text = String::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_string(&mut text)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));

        return text;
    }

    String::from_utf8(bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// One query line: `input checktype [querytype]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub input: String,
    pub check_type: String,
    pub query_type: String,
}

impl Query {
    pub fn parse(line: &str) -> Query {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert!(
            fields.len() == 2 || fields.len() == 3,
            "bad query line {line:?}"
        );

        Query {
            input: fields[0].to_string(),
            check_type: fields[1].to_string(),
            query_type: fields.get(2).unwrap_or(&fields[1]).to_string(),
        }
    }

    /// The query as written in the fixtures.
    pub fn key(&self) -> String {
        if self.check_type == self.query_type {
            format!("{} {}", self.input, self.check_type)
        } else {
            format!("{} {} {}", self.input, self.check_type, self.query_type)
        }
    }
}

/// An expected outcome: `pass -` or `block ANSWER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub blocked: bool,
    pub answer: String,
}

impl Outcome {
    pub fn parse(decision: &str, answer: &str) -> Outcome {
        match decision {
            "pass" => {
                return Outcome {
                    blocked: false,
                    answer: String::new(),
                };
            }
            "block" => {}
            _ => panic!("bad decision {decision:?}"),
        }

        Outcome {
            blocked: true,
            answer: answer.to_string(),
        }
    }
}

/// A line of an oracle output file.
#[derive(Debug, Clone)]
pub struct Expected {
    pub query: Query,
    pub outcome: Outcome,
}

pub fn parse_expected(text: &str) -> Vec<Expected> {
    let mut expected = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        let count = fields.len();
        assert!(count == 4 || count == 5, "bad expected line {line:?}");
        expected.push(Expected {
            query: Query::parse(&fields[..count - 2].join(" ")),
            outcome: Outcome::parse(fields[count - 2], fields[count - 1]),
        });
    }

    expected
}

/// A matcher case: lists, queries and the expected oracle output.
#[derive(Debug, Default)]
pub struct Case {
    pub name: String,
    pub main: Vec<String>,
    pub user: String,
    pub allow: Vec<String>,
    /// The scripted upstream answers of a full-flow case.
    pub upstream: String,
    pub queries: Vec<Query>,
    /// Queries where picoguard is expected to differ from the oracle, with its outcome.
    pub deviations: Vec<(Query, Outcome)>,
    pub expected: Vec<Expected>,
}

pub fn parse_case(name: &str, text: &str) -> Case {
    let mut case = Case {
        name: name.to_string(),
        ..Case::default()
    };
    let mut section = "";
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');
        match trimmed {
            "[main]" => {
                case.main.push(String::new());
                section = "main";
                continue;
            }
            "[allow]" => {
                case.allow.push(String::new());
                section = "allow";
                continue;
            }
            "[user]" | "[queries]" | "[deviations]" | "[upstream]" => {
                section = &trimmed[1..trimmed.len() - 1];
                continue;
            }
            _ => {}
        }

        match section {
            "main" => {
                case.main.last_mut().unwrap().push_str(line);
            }
            "allow" => {
                case.allow.last_mut().unwrap().push_str(line);
            }
            "user" => {
                case.user.push_str(line);
            }
            "upstream" => {
                case.upstream.push_str(line);
            }
            "queries" => {
                let query = trimmed.trim();
                if !query.is_empty() && !query.starts_with('#') {
                    case.queries.push(Query::parse(query));
                }
            }
            "deviations" => {
                let deviation = trimmed.trim();
                if deviation.is_empty() || deviation.starts_with('#') {
                    continue;
                }

                let (query, outcome) = deviation.split_once("=>").expect("deviation needs =>");
                let outcome: Vec<&str> = outcome.split_whitespace().collect();
                case.deviations.push((
                    Query::parse(query.trim()),
                    Outcome::parse(outcome[0], outcome[1]),
                ));
            }
            _ => {}
        }
    }

    case
}

/// Every `tests/fixtures/golden/cases/*.case` with its `.expected` file.
pub fn load_cases() -> Vec<Case> {
    let dir = fixtures_dir().join("golden/cases");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "case")
        })
        .collect();
    paths.sort();

    paths
        .iter()
        .map(|path| {
            let name = path.file_stem().unwrap().to_string_lossy().to_string();
            let mut case = parse_case(&name, &read_text(path));
            case.expected = parse_expected(&read_text(&path.with_extension("expected")));

            case
        })
        .collect()
}

/// The three real lists of the benchmark, in order, and the sampled queries with their
/// expected output.
pub struct RealLists {
    pub lists: Vec<String>,
    pub expected: Vec<Expected>,
}

pub const REAL_LISTS: [&str; 3] = ["adguard-dns", "hagezi-pro", "hagezi-tif-mini"];

pub fn load_real() -> RealLists {
    let dir = fixtures_dir();
    RealLists {
        lists: REAL_LISTS
            .iter()
            .map(|name| read_text(&dir.join(format!("lists/{name}.txt.gz"))))
            .collect(),
        expected: parse_expected(&read_text(&dir.join("golden/real/expected.txt"))),
    }
}

/// The full-flow case: lists, user rules, allowlists, the scripted upstream and the queries.
pub fn load_flow_case() -> Case {
    let path = fixtures_dir().join("golden/flow/flow.case");

    parse_case("flow", &read_text(&path))
}
