//! Server MVP: Google-authenticated fleet operations and consent-based Client audits.

pub mod client_catalog;
pub mod config;
pub mod custom_checks;
pub mod http;
pub mod storage;

pub mod auth;
pub mod tls;
pub mod tunnel;

#[cfg(test)]
mod oidc_tests;

#[cfg(test)]
mod client_fixture;
#[cfg(test)]
mod e2e_tests;

pub mod report;
pub mod report_integrity;

pub mod launcher;
// Client PDF snapshot keeps the Client's MSRV-1.80 `map_or(true, ..)` spelling for parity.
#[allow(clippy::unnecessary_map_or)]
mod pdf;
mod preferences;

pub mod requirement_config;

pub mod manifest;
