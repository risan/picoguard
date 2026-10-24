//! The engine the process starts with, built from the config before the first query.
//!
//! This is the plain boot path: local `path` lists, `rules` and `allowlists` are read and
//! compiled right here, one after the other. Lists with a `url` are skipped until the list
//! scheduler (S4.3) downloads and loads them.

use std::fs::File;
use std::sync::Arc;

use super::engine::{CompiledList, Engine};
use super::parse::ListFormat;
use crate::config::{Config, ListConfig};

/// Never fails: a list that cannot be read is skipped with a warning, so a typo in one path
/// does not take the DNS service down.
pub fn engine_from_config(config: &Config) -> Engine {
    let mut main = Vec::new();
    if !config.rules.is_empty() {
        let text = config.rules.join("\n");
        let (list, _) = CompiledList::from_text(ListFormat::Adblock, &text);
        log::info!("user rules: {} rules", list.rule_count());
        main.push(Arc::new(list));
    }

    main.extend(config.lists.iter().filter_map(|list| load("list", list)));
    let allow = config
        .allowlists
        .iter()
        .filter_map(|list| load("allowlist", list))
        .collect();

    Engine::new(main, allow)
}

fn load(kind: &str, list: &ListConfig) -> Option<Arc<CompiledList>> {
    let label = list
        .name
        .clone()
        .or_else(|| list.url.clone())
        .or_else(|| list.path.as_ref().map(|path| path.display().to_string()))
        .unwrap_or_default();
    let Some(path) = &list.path else {
        log::warn!("{kind} {label}: downloading is not built yet, skipped");

        return None;
    };

    let file = match File::open(path) {
        Ok(file) => file,

        Err(error) => {
            log::warn!("{kind} {label}: cannot read {}: {error}", path.display());

            return None;
        }
    };

    match CompiledList::from_reader(list.format, list.max_rules as usize, file) {
        Ok((compiled, summary)) => {
            log::info!(
                "{kind} {label}: {} rules ({} slow), format {:?}",
                compiled.rule_count(),
                compiled.slow_rule_count(),
                summary.format
            );

            Some(Arc::new(compiled))
        }

        Err(error) => {
            log::warn!("{kind} {label}: cannot read {}: {error}", path.display());

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::engine::{Decision, TYPE_A};
    use crate::test_dir::TestDir;

    fn blocked(engine: &Engine, name: &str) -> bool {
        matches!(engine.check(name, TYPE_A, false), Decision::Block { .. })
    }

    fn write(dir: &TestDir, name: &str, text: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();

        path
    }

    fn path_list(path: std::path::PathBuf) -> ListConfig {
        ListConfig {
            path: Some(path),
            ..ListConfig::default()
        }
    }

    #[test]
    fn rules_local_lists_and_allowlists_make_one_engine() {
        let dir = TestDir::new("boot");
        let list = write(
            &dir,
            "block.txt",
            "||list.example^\n||both.example^\n||allowed.example^\n",
        );
        let allow = write(&dir, "allow.txt", "||allowed.example^\n");
        let config = Config {
            rules: vec![
                "||user.example^".to_string(),
                "@@||both.example^".to_string(),
            ],
            lists: vec![path_list(list)],
            allowlists: vec![path_list(allow)],
            ..Config::default()
        };

        let engine = engine_from_config(&config);

        assert!(blocked(&engine, "user.example"));
        assert!(blocked(&engine, "sub.list.example"));
        assert!(!blocked(&engine, "both.example"));
        assert!(!blocked(&engine, "allowed.example"));
        assert!(!blocked(&engine, "other.example"));
    }

    #[test]
    fn url_lists_and_unreadable_files_are_skipped() {
        let dir = TestDir::new("boot-skip");
        let config = Config {
            lists: vec![
                ListConfig {
                    url: Some("https://lists.example/block.txt".to_string()),
                    ..ListConfig::default()
                },
                path_list(dir.path().join("missing.txt")),
                path_list(write(&dir, "ok.txt", "||ok.example^\n")),
            ],
            ..Config::default()
        };

        let engine = engine_from_config(&config);

        assert!(blocked(&engine, "ok.example"));
    }

    #[test]
    fn the_format_and_rule_cap_of_a_list_are_honoured() {
        let dir = TestDir::new("boot-format");
        let hosts = ListConfig {
            format: ListFormat::Hosts,
            max_rules: 1,
            ..path_list(write(
                &dir,
                "hosts.txt",
                "0.0.0.0 a.example\n0.0.0.0 b.example\n",
            ))
        };
        let config = Config {
            lists: vec![hosts],
            ..Config::default()
        };

        let engine = engine_from_config(&config);

        assert!(blocked(&engine, "a.example"));
        assert!(!blocked(&engine, "b.example"));
    }
}
