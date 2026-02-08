// Compatibility shim — re-exports from transport_identity with legacy names.
// Will be removed after downstream tooling/scripts are updated.
pub use crate::transport_identity::{
    transport_cert_paths_from_db as cert_paths_from_db,
    load_transport_peer_id_from_db as load_identity_from_db,
    ensure_transport_peer_id_from_db as local_identity_from_db,
};
