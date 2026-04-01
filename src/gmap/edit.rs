#![allow(dead_code)]

use std::path::Path;

use super::{GmapPath, Policy, parse_rule_line, parse_str};

pub fn upsert_policy(path: &Path, rule_path: &str, policy: Policy) -> anyhow::Result<()> {
    let contents = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };
    let (updated, has_comments) = if contents.is_empty() {
        (String::new(), false)
    } else {
        let has_comments = contains_comments_or_blanks(&contents);
        (contents, has_comments)
    };

    if has_comments {
        let updated = upsert_preserving_lines(&updated, rule_path, policy)?;
        write_file(path, &updated)?;
        return Ok(());
    }

    let mut rules = parse_str(&updated)?;
    upsert_rule(&mut rules, rule_path, policy)?;
    rules.sort_by(|a, b| canonical_key(&a.path).cmp(&canonical_key(&b.path)));
    let rendered = render_rules(&rules);
    write_file(path, &rendered)?;
    Ok(())
}

fn upsert_rule(
    rules: &mut Vec<super::GmapRule>,
    rule_path: &str,
    policy: Policy,
) -> anyhow::Result<()> {
    let parsed_path = super::parse_path(rule_path, 0)?;
    if let Some(existing) = rules.iter_mut().find(|rule| rule.path == parsed_path) {
        existing.policy = policy;
    } else {
        rules.push(super::GmapRule {
            path: parsed_path,
            policy,
            line: rules.len() + 1,
        });
    }
    Ok(())
}

fn upsert_preserving_lines(
    contents: &str,
    rule_path: &str,
    policy: Policy,
) -> anyhow::Result<String> {
    let mut lines: Vec<String> = contents.split('\n').map(|line| line.to_string()).collect();
    let mut updated = false;
    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let rule = parse_rule_line(trimmed, 0)?;
        if rule.path.to_string() == rule_path {
            *line = format!("{} = {}", rule_path, policy_string(&policy));
            updated = true;
            break;
        }
    }
    if !updated {
        if !lines.is_empty() && !lines.last().map(|line| line.is_empty()).unwrap_or(true) {
            lines.push(String::new());
        }
        lines.push(format!("{} = {}", rule_path, policy_string(&policy)));
    }
    let mut output = lines.join("\n");
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(output)
}

fn render_rules(rules: &[super::GmapRule]) -> String {
    let mut output = String::new();
    for rule in rules {
        output.push_str(&format!(
            "{} = {}\n",
            rule.path,
            policy_string(&rule.policy)
        ));
    }
    output
}

fn policy_string(policy: &Policy) -> &'static str {
    match policy {
        Policy::Public => "public",
        Policy::Forbidden => "forbidden",
    }
}

fn canonical_key(path: &GmapPath) -> (u8, String, String, String) {
    let (rank, pack, flow, node) = match (&path.pack, &path.flow, &path.node) {
        (None, None, None) => (0, String::new(), String::new(), String::new()),
        (Some(pack), None, None) => (2, pack.clone(), String::new(), String::new()),
        (Some(pack), Some(flow), None) if flow == "_" => {
            (1, pack.clone(), String::new(), String::new())
        }
        (Some(pack), Some(flow), None) => (3, pack.clone(), flow.clone(), String::new()),
        (Some(pack), Some(flow), Some(node)) => (4, pack.clone(), flow.clone(), node.clone()),
        _ => (0, String::new(), String::new(), String::new()),
    };
    (rank, pack, flow, node)
}

fn contains_comments_or_blanks(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.is_empty() || trimmed.starts_with('#')
    })
}

fn write_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn upsert_policy_creates_and_sorts_plain_rule_files() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("tenant.gmap");

        upsert_policy(&path, "pack/flow", Policy::Public).expect("insert");
        upsert_policy(&path, "_", Policy::Forbidden).expect("insert wildcard");
        upsert_policy(&path, "pack", Policy::Forbidden).expect("insert pack");

        assert_eq!(
            std::fs::read_to_string(&path).expect("read gmap"),
            "_ = forbidden\npack = forbidden\npack/flow = public\n"
        );
    }

    #[test]
    fn upsert_policy_preserves_comments_and_updates_existing_lines() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("tenant.gmap");
        std::fs::write(
            &path,
            "# comment\n\npack/flow = forbidden\npack/other = public\n",
        )
        .expect("seed file");

        upsert_policy(&path, "pack/flow", Policy::Public).expect("update");
        upsert_policy(&path, "pack/new", Policy::Forbidden).expect("append");

        assert_eq!(
            std::fs::read_to_string(&path).expect("read gmap"),
            "# comment\n\npack/flow = public\npack/other = public\n\npack/new = forbidden\n"
        );
    }

    #[test]
    fn helpers_cover_rendering_and_comment_detection() {
        assert!(contains_comments_or_blanks("# comment\npack = public\n"));
        assert!(!contains_comments_or_blanks(
            "pack = public\npack/flow = forbidden\n"
        ));
        assert_eq!(policy_string(&Policy::Public), "public");
        assert_eq!(policy_string(&Policy::Forbidden), "forbidden");

        let rendered = render_rules(&[super::super::GmapRule {
            path: GmapPath {
                pack: Some("pack".to_string()),
                flow: Some("flow".to_string()),
                node: None,
            },
            policy: Policy::Public,
            line: 1,
        }]);
        assert_eq!(rendered, "pack/flow = public\n");
    }
}
