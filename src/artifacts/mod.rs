//! Inbound attachments: fetch, validate, store behind the admin `artifacts`
//! door, extract text, rewrite the envelope to `artifact://<id>`.
//!
//! Contract: the attachments-and-artifacts master plan (C1 envelope, C3 door).

// The pipeline that consumes these modules is wired into the inbound path in a
// later step; until then only the tests reach them.
#![allow(dead_code)]

pub(crate) mod limits;
pub(crate) mod sniff;

#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod sniff_tests;
