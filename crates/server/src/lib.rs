//! Server MVP: Google-authenticated fleet operations and consent-based Client audits.

pub mod config;
pub mod http;
pub mod storage;

pub mod auth;
pub mod remote;
pub mod tls;

#[cfg(test)]
mod oidc_tests;

#[cfg(test)]
mod client_fixture;
#[cfg(test)]
mod e2e_tests;

pub mod report;
pub mod report_integrity;

mod pdf;
mod preferences;

pub mod requirement_config;

pub mod manifest;
