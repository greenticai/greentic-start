//! Pure threshold-eval and edge-crossing logic for the threshold watcher.
//!
//! No I/O lives here: `side` classifies a sampled value against a threshold,
//! and `crossing` detects a genuine transition between two consecutive
//! samples. Both are deterministic and side-effect free so they can be
//! exhaustively unit tested without a runtime, HTTP client, or durable
//! state.

use serde::{Deserialize, Serialize};

/// How a sampled value is compared against the configured threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    Gt,
    Lt,
    Gte,
    Lte,
}

/// Which edge(s) of a crossing should fire the watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDirection {
    Rising,
    Falling,
    Both,
}

/// Classification of a sampled value relative to the threshold.
///
/// `Side::Above` means the comparator condition is SATISFIED (i.e. the
/// value is in the trigger region) — it does not mean "numerically greater
/// than the threshold." For `Comparator::Lt`/`Comparator::Lte`, a value
/// numerically BELOW (or equal to) the threshold satisfies the comparator
/// and therefore yields `Side::Above`. `Side::Unknown` represents the
/// absence of a prior sample (e.g. first poll, or a corrupt/missing durable
/// state file) and must never participate in a crossing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Above,
    Below,
    Unknown,
}

/// Classify `value` against `threshold` using `cmp`.
///
/// Returns `Side::Above` when the comparator condition holds for
/// `value`/`threshold`, `Side::Below` otherwise. See the `Side` doc comment
/// for the "Above = satisfied" semantic.
pub fn side(value: f64, threshold: f64, cmp: Comparator) -> Side {
    let satisfied = match cmp {
        Comparator::Gt => value > threshold,
        Comparator::Lt => value < threshold,
        Comparator::Gte => value >= threshold,
        Comparator::Lte => value <= threshold,
    };
    if satisfied { Side::Above } else { Side::Below }
}

/// Detect a genuine edge crossing between two consecutive `Side` samples,
/// filtered by the watch's configured `EdgeDirection`.
///
/// Returns `None` when:
/// - `prev` is `Side::Unknown` (no prior sample — the first poll never
///   fires; it only records the side),
/// - `prev == curr` (no transition occurred), or
/// - the transition occurred but doesn't match `dir`.
///
/// Returns `Some("rising")` on a `Below` -> `Above` transition and
/// `Some("falling")` on an `Above` -> `Below` transition, when `dir` allows
/// that edge.
pub fn crossing(prev: Side, curr: Side, dir: EdgeDirection) -> Option<&'static str> {
    if prev == Side::Unknown || prev == curr {
        return None;
    }
    match (prev, curr) {
        (Side::Below, Side::Above) => {
            matches!(dir, EdgeDirection::Rising | EdgeDirection::Both).then_some("rising")
        }
        (Side::Above, Side::Below) => {
            matches!(dir, EdgeDirection::Falling | EdgeDirection::Both).then_some("falling")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_respects_comparator() {
        assert_eq!(side(10.0, 5.0, Comparator::Gt), Side::Above);
        assert_eq!(side(3.0, 5.0, Comparator::Gt), Side::Below);
        assert_eq!(side(5.0, 5.0, Comparator::Gte), Side::Above);
        assert_eq!(side(5.0, 5.0, Comparator::Gt), Side::Below);
        assert_eq!(side(3.0, 5.0, Comparator::Lt), Side::Above); // "below threshold" IS the trigger side for Lt
    }

    #[test]
    fn crossing_fires_once_on_matching_edge() {
        assert_eq!(
            crossing(Side::Below, Side::Above, EdgeDirection::Rising),
            Some("rising")
        );
        assert_eq!(
            crossing(Side::Above, Side::Below, EdgeDirection::Rising),
            None
        );
        assert_eq!(
            crossing(Side::Above, Side::Below, EdgeDirection::Falling),
            Some("falling")
        );
        assert_eq!(
            crossing(Side::Below, Side::Above, EdgeDirection::Both),
            Some("rising")
        );
        assert_eq!(
            crossing(Side::Above, Side::Above, EdgeDirection::Both),
            None
        ); // no transition
        assert_eq!(
            crossing(Side::Unknown, Side::Above, EdgeDirection::Both),
            None
        ); // first poll never fires
    }
}
