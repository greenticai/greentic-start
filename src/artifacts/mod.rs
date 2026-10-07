//! Inbound attachments: fetch, validate, store behind the admin `artifacts`
//! door, extract text, rewrite the envelope to `artifact://<id>`.
//!
//! Contract: the attachments-and-artifacts master plan (C1 envelope, C3 door).

// The pipeline that consumes these modules is wired into the inbound path in a
// later step; until then only the tests reach them.
#![allow(dead_code)]

pub(crate) mod client;
pub(crate) mod dns;
pub(crate) mod extract;
pub(crate) mod host_policy;
pub(crate) mod limits;
pub(crate) mod pdf_isolation;
pub(crate) mod pdf_limits;
pub(crate) mod sniff;
pub(crate) mod store;
pub(crate) mod wire;

#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod dns_tests;
#[cfg(test)]
mod extract_tests;
#[cfg(test)]
mod host_policy_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod pdf_fixture;
#[cfg(all(test, target_os = "linux"))]
mod pdf_isolation_tests;
#[cfg(test)]
mod proxy_testkit;
#[cfg(test)]
mod sniff_tests;
#[cfg(test)]
mod store_tests;
