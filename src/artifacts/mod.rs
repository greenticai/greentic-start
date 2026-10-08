//! Inbound attachments: fetch, validate, store behind the admin `artifacts`
//! door, extract text, rewrite the envelope to `artifact://<id>`.
//!
//! Contract: the attachments-and-artifacts master plan (C1 envelope, C3 door).

pub(crate) mod activate;
pub(crate) mod boot;
pub(crate) mod client;
pub(crate) mod dns;
pub(crate) mod drops;
pub(crate) mod extract;
pub(crate) mod fetch;
pub(crate) mod fetch_ref;
pub(crate) mod hook;
pub(crate) mod host_access;
pub(crate) mod host_policy;
pub(crate) mod ingest;
pub(crate) mod instance_check;
pub(crate) mod label;
pub(crate) mod legacy;
pub(crate) mod limits;
pub(crate) mod link;
pub(crate) mod link_base;
pub(crate) mod link_table;
pub(crate) mod off;
pub(crate) mod origin;
pub(crate) mod outbound;
pub(crate) mod outbound_shape;
pub(crate) mod pdf_isolation;
pub(crate) mod pdf_limits;
pub(crate) mod port;
pub(crate) mod provenance;
pub(crate) mod quota_key;
pub(crate) mod recent_puts;
pub(crate) mod recovery;
pub(crate) mod secrets;
pub(crate) mod serve_link;
pub(crate) mod serve_link_limits;
pub(crate) mod sniff;
pub(crate) mod store;
pub(crate) mod unit;
pub(crate) mod unserved;
pub(crate) mod wire;

#[cfg(test)]
mod activate_dedup_tests;
#[cfg(test)]
mod activate_tests;
#[cfg(test)]
mod boot_tests;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod dns_tests;
#[cfg(test)]
mod drops_tests;
#[cfg(test)]
mod encoding_tests;
#[cfg(test)]
mod extract_tests;
#[cfg(test)]
mod fetch_origin_tests;
#[cfg(test)]
mod fetch_tests;
#[cfg(test)]
mod fetcher_id_tests;
#[cfg(test)]
mod fetcher_tests;
#[cfg(test)]
mod hook_tests;
#[cfg(test)]
mod host_access_tests;
#[cfg(test)]
mod host_policy_tests;
#[cfg(test)]
mod ingest_blocking_tests;
#[cfg(test)]
mod ingest_bounds_tests;
#[cfg(test)]
mod ingest_provenance_tests;
#[cfg(test)]
mod ingest_testkit;
#[cfg(test)]
mod ingest_tests;
#[cfg(test)]
mod instance_check_tests;
#[cfg(test)]
mod legacy_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod link_base_tests;
#[cfg(test)]
mod link_table_tests;
#[cfg(test)]
mod link_tests;
#[cfg(test)]
mod origin_tests;
#[cfg(test)]
mod outbound_side_tests;
#[cfg(test)]
mod outbound_tests;
#[cfg(test)]
mod pdf_fixture;
#[cfg(all(test, target_os = "linux"))]
mod pdf_isolation_tests;
#[cfg(test)]
mod port_tests;
#[cfg(test)]
mod proxy_testkit;
#[cfg(test)]
mod quota_key_tests;
#[cfg(test)]
mod recent_puts_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod redaction_ratchet_tests;
#[cfg(test)]
mod redaction_tests;
#[cfg(test)]
mod secrets_tests;
#[cfg(test)]
mod serve_link_limits_tests;
#[cfg(test)]
mod serve_link_testkit;
#[cfg(test)]
mod serve_link_tests;
#[cfg(test)]
mod sniff_tests;
#[cfg(test)]
mod store_retry_tests;
#[cfg(test)]
mod store_tests;
#[cfg(test)]
pub(crate) mod time_testkit;
#[cfg(test)]
mod unserved_tests;
#[cfg(test)]
mod wiring_tests;
