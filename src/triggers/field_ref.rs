//! Field references (contract §6.7): where an idempotency key or a session key
//! is read from. Deliberately not JSONPath — three forms, each unambiguous:
//!
//! - `header:<name>` — request header, case-insensitive;
//! - `query:<name>` — query parameter;
//! - `body.<seg>(.<seg>)*` — `<seg>` is an object key or `[<n>]`.
//!
//! A reference resolving to a string or a number yields its string form;
//! anything else (object, array, null, missing) does not resolve.

use anyhow::{Result, bail};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FieldRef {
    Header(String),
    Query(String),
    Body(Vec<Seg>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Key(String),
    Index(usize),
}

/// What a reference is resolved against.
pub(crate) struct RequestView<'a> {
    pub headers: &'a [(String, String)],
    pub query: &'a [(String, String)],
    pub body: Option<&'a Value>,
}

impl FieldRef {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if let Some(name) = raw.strip_prefix("header:") {
            if name.is_empty() {
                bail!("field reference `{raw}` names no header");
            }
            return Ok(FieldRef::Header(name.to_ascii_lowercase()));
        }
        if let Some(name) = raw.strip_prefix("query:") {
            if name.is_empty() {
                bail!("field reference `{raw}` names no query parameter");
            }
            return Ok(FieldRef::Query(name.to_string()));
        }
        let Some(path) = raw.strip_prefix("body.") else {
            bail!("field reference `{raw}` must start with `header:`, `query:` or `body.`");
        };
        let mut segs = Vec::new();
        for part in path.split('.') {
            // `items[0]` and `[0]` both split into a key and index segments.
            let (key, mut rest) = match part.find('[') {
                Some(pos) => (&part[..pos], &part[pos..]),
                None => (part, ""),
            };
            if !key.is_empty() {
                segs.push(Seg::Key(key.to_string()));
            }
            while !rest.is_empty() {
                let Some(close) = rest.find(']') else {
                    bail!("field reference `{raw}` has an unclosed `[`");
                };
                let idx: usize = rest[1..close]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("field reference `{raw}` has a bad index"))?;
                segs.push(Seg::Index(idx));
                rest = &rest[close + 1..];
                if !rest.is_empty() && !rest.starts_with('[') {
                    bail!("field reference `{raw}` has text after an index");
                }
            }
            if key.is_empty() && part.is_empty() {
                bail!("field reference `{raw}` has an empty segment");
            }
        }
        if segs.is_empty() {
            bail!("field reference `{raw}` names no body field");
        }
        Ok(FieldRef::Body(segs))
    }

    /// Header names this reference reads, so the §9 payload can pass exactly
    /// those through its allow-list.
    pub(crate) fn header_name(&self) -> Option<&str> {
        match self {
            FieldRef::Header(name) => Some(name),
            _ => None,
        }
    }

    pub(crate) fn resolve(&self, req: &RequestView<'_>) -> Option<String> {
        match self {
            FieldRef::Header(name) => req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty()),
            FieldRef::Query(name) => req
                .query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty()),
            FieldRef::Body(segs) => {
                let mut cur = req.body?;
                for seg in segs {
                    cur = match seg {
                        Seg::Key(k) => cur.get(k)?,
                        Seg::Index(i) => cur.get(*i)?,
                    };
                }
                match cur {
                    Value::String(s) if !s.is_empty() => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn view<'a>(
        headers: &'a [(String, String)],
        query: &'a [(String, String)],
        body: Option<&'a Value>,
    ) -> RequestView<'a> {
        RequestView {
            headers,
            query,
            body,
        }
    }

    #[test]
    fn a_header_reference_is_case_insensitive() {
        let r = FieldRef::parse("header:X-Request-Id").unwrap();
        let headers = vec![("x-request-id".to_string(), "abc".to_string())];
        assert_eq!(r.resolve(&view(&headers, &[], None)), Some("abc".into()));
    }

    #[test]
    fn a_body_path_walks_keys_and_indexes() {
        let r = FieldRef::parse("body.entry[0].changes[1].value.id").unwrap();
        let body = json!({"entry":[{"changes":[{"value":{"id":"a"}},{"value":{"id":"b"}}]}]});
        assert_eq!(r.resolve(&view(&[], &[], Some(&body))), Some("b".into()));
    }

    #[test]
    fn a_number_resolves_to_its_string_form() {
        let r = FieldRef::parse("body.order.customer_id").unwrap();
        let body = json!({"order":{"customer_id": 42}});
        assert_eq!(r.resolve(&view(&[], &[], Some(&body))), Some("42".into()));
    }

    #[test]
    fn objects_nulls_and_missing_fields_do_not_resolve() {
        let body = json!({"a":{"b":null,"c":{"d":1}}});
        for raw in ["body.a.b", "body.a.c", "body.a.zz", "body.a.c.d.e"] {
            let r = FieldRef::parse(raw).unwrap();
            assert_eq!(r.resolve(&view(&[], &[], Some(&body))), None, "{raw}");
        }
    }

    #[test]
    fn a_non_json_body_resolves_nothing() {
        let r = FieldRef::parse("body.id").unwrap();
        assert_eq!(r.resolve(&view(&[], &[], None)), None);
    }

    #[test]
    fn malformed_references_are_refused() {
        for raw in [
            "id",
            "header:",
            "query:",
            "body.",
            "body.a[x]",
            "body.a[1",
            "body.a[0]b",
        ] {
            assert!(FieldRef::parse(raw).is_err(), "{raw} should be refused");
        }
    }
}
