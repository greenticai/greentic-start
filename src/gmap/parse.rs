#![allow(dead_code)]

use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Policy {
    Public,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmapPath {
    pub pack: Option<String>,
    pub flow: Option<String>,
    pub node: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmapRule {
    pub path: GmapPath,
    pub policy: Policy,
    pub line: usize,
}

pub fn parse_file(path: &Path) -> anyhow::Result<Vec<GmapRule>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(path)?;
    parse_str(&contents)
}

pub fn parse_str(contents: &str) -> anyhow::Result<Vec<GmapRule>> {
    let mut rules = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rule = parse_rule_line(line, idx + 1)?;
        rules.push(rule);
    }
    Ok(rules)
}

pub fn parse_rule_line(line: &str, line_number: usize) -> anyhow::Result<GmapRule> {
    let mut parts = line.splitn(2, '=');
    let raw_path = parts
        .next()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Invalid rule line {}: missing path", line_number))?;
    let raw_policy = parts
        .next()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Invalid rule line {}: missing policy", line_number))?;

    let path = parse_path(raw_path, line_number)?;
    let policy = parse_policy(raw_policy, line_number)?;
    Ok(GmapRule {
        path,
        policy,
        line: line_number,
    })
}

pub fn parse_path(raw: &str, line_number: usize) -> anyhow::Result<GmapPath> {
    if raw == "_" {
        return Ok(GmapPath {
            pack: None,
            flow: None,
            node: None,
        });
    }
    let mut segments = raw.split('/').filter(|seg| !seg.is_empty());
    let Some(pack) = segments.next() else {
        return Err(anyhow::anyhow!(
            "Invalid path on line {}: empty path",
            line_number
        ));
    };
    let flow = segments.next();
    let node = segments.next();
    if segments.next().is_some() {
        return Err(anyhow::anyhow!(
            "Invalid path on line {}: too many segments",
            line_number
        ));
    }
    Ok(GmapPath {
        pack: Some(pack.to_string()),
        flow: flow.map(str::to_string),
        node: node.map(str::to_string),
    })
}

pub fn parse_policy(raw: &str, line_number: usize) -> anyhow::Result<Policy> {
    match raw {
        "public" => Ok(Policy::Public),
        "forbidden" => Ok(Policy::Forbidden),
        other => Err(anyhow::anyhow!(
            "Invalid policy on line {}: {}",
            line_number,
            other
        )),
    }
}

impl std::fmt::Display for GmapPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.pack, &self.flow, &self.node) {
            (None, None, None) => write!(formatter, "_"),
            (Some(pack), None, None) => write!(formatter, "{pack}"),
            (Some(pack), Some(flow), None) => write!(formatter, "{pack}/{flow}"),
            (Some(pack), Some(flow), Some(node)) => write!(formatter, "{pack}/{flow}/{node}"),
            _ => write!(formatter, "_"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_file_missing_returns_empty_and_parse_str_skips_comments() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("missing.gmap");
        assert!(parse_file(&missing).expect("missing file").is_empty());

        let rules = parse_str(
            r#"
            # comment

            _ = forbidden
            pack/flow = public
            "#,
        )
        .expect("parse");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].line, 4);
        assert_eq!(rules[1].path.flow.as_deref(), Some("flow"));
    }

    #[test]
    fn parse_rule_line_and_path_support_wildcard_and_segments() {
        let rule = parse_rule_line("pack/flow/node = public", 7).expect("rule");
        assert_eq!(rule.path.pack.as_deref(), Some("pack"));
        assert_eq!(rule.path.flow.as_deref(), Some("flow"));
        assert_eq!(rule.path.node.as_deref(), Some("node"));
        assert_eq!(rule.policy, Policy::Public);
        assert_eq!(rule.line, 7);

        let wildcard = parse_path("_", 1).expect("wildcard");
        assert_eq!(
            wildcard,
            GmapPath {
                pack: None,
                flow: None,
                node: None
            }
        );
    }

    #[test]
    fn parse_errors_are_reported_for_invalid_lines_paths_and_policies() {
        assert!(
            parse_rule_line("= public", 2)
                .expect_err("missing path")
                .to_string()
                .contains("missing path")
        );
        assert!(
            parse_rule_line("pack =", 3)
                .expect_err("missing policy")
                .to_string()
                .contains("missing policy")
        );
        assert!(
            parse_path("a/b/c/d", 4)
                .expect_err("too many segments")
                .to_string()
                .contains("too many segments")
        );
        assert!(
            parse_policy("private", 5)
                .expect_err("invalid policy")
                .to_string()
                .contains("Invalid policy")
        );
    }

    #[test]
    fn gmap_path_display_renders_supported_shapes() {
        assert_eq!(
            GmapPath {
                pack: None,
                flow: None,
                node: None
            }
            .to_string(),
            "_"
        );
        assert_eq!(
            GmapPath {
                pack: Some("pack".to_string()),
                flow: None,
                node: None
            }
            .to_string(),
            "pack"
        );
        assert_eq!(
            GmapPath {
                pack: Some("pack".to_string()),
                flow: Some("flow".to_string()),
                node: Some("node".to_string())
            }
            .to_string(),
            "pack/flow/node"
        );
    }
}
