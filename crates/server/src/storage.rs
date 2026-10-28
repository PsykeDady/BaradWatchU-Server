//! Persistence boundary. SQLite is the planned first adapter; this milestone
//! intentionally defines no data model or database implementation.

/// Extension point for storage implementations added with audit persistence.
pub trait AuditStore: Send + Sync {
    /// Return the storage backend's human-readable identity for diagnostics.
    fn backend_name(&self) -> &'static str;
}
