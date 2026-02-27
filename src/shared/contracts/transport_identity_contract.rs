//! Typed contract for event/identity → transport identity transitions.
//!
//! Event/identity logic emits `TransportIdentityIntent`s to describe *what*
//! transition should happen. The `TransportIdentityAdapter` trait is
//! implemented by the transport layer to perform the actual cert/key
//! materialisation. Service and projection layers call through the adapter —
//! never directly to raw install functions.

use rusqlite::Connection;

/// Describes an identity transition that the transport layer should
/// materialise into cert/key state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportIdentityIntent {
    /// Install a deterministic transport cert derived from the PeerShared
    /// signing key, replacing any prior identity (random or invite-derived).
    InstallPeerSharedIdentityFromSigner {
        recorded_by: String,
        signer_event_id: [u8; 32],
    },
}

/// Typed errors from adapter operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportIdentityError {
    #[error("transport identity install failed: {0}")]
    InstallFailed(String),
    #[error("signer key not found for recorded_by={recorded_by}")]
    SignerKeyNotFound { recorded_by: String },
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
}

/// Adapter trait: the sole entry point for materialising transport identity.
///
/// Implementations live in the transport layer. Service and projection code
/// calls `apply_intent` — never the raw install functions directly.
pub trait TransportIdentityAdapter {
    fn apply_intent(
        &self,
        conn: &Connection,
        intent: TransportIdentityIntent,
    ) -> Result<String, TransportIdentityError>;
}
