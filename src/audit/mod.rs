pub mod hash;
pub mod record;

pub use hash::{audit_hash, audit_hash_with_algo, AuditHashAlgo};
pub use record::compute_record_hash;
