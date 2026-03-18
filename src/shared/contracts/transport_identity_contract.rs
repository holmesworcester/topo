//! Typed contract for event/identity → transport identity transitions.
//!
//! Event/identity logic emits `TransportIdentitySpec`s to describe *what*
//! transition should happen. The `TransportIdentityMaterializer` trait is
//! implemented by the transport layer to perform the actual cert/key
//! materialisation. Service and projection layers call through the materializer —
//! never directly to raw install functions.

use rusqlite::Connection;

/// Describes an identity transition that the transport layer should
/// materialise into cert/key state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportIdentitySpec {
    /// Install bootstrap transport identity from locally projected invite_secret
    /// key material for a specific invite event.
    InstallBootstrapIdentityFromInviteSecret {
        recorded_by: String,
        invite_event_id: [u8; 32],
    },
    /// Install a deterministic transport cert derived from the PeerShared
    /// signing key, replacing any prior identity (random or invite-derived).
    InstallPeerSharedIdentityFromSigner {
        recorded_by: String,
        signer_event_id: [u8; 32],
    },
}

/// Typed errors from materializer operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportIdentityError {
    #[error("transport identity install failed: {0}")]
    InstallFailed(String),
    #[error("bootstrap transport identity install denied after peershared identity is active")]
    BootstrapAfterPeerSharedDenied,
    #[error(
        "invite secret not found for recorded_by={recorded_by}, invite_event_id={invite_event_id}"
    )]
    InviteSecretNotFound {
        recorded_by: String,
        invite_event_id: String,
    },
    #[error("signer key not found for recorded_by={recorded_by}")]
    SignerKeyNotFound { recorded_by: String },
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
}

/// Materializer trait: the sole entry point for materialising transport identity.
///
/// Implementations live in the transport layer. Service and projection code
/// calls `materialize` — never the raw install functions directly.
pub trait TransportIdentityMaterializer {
    fn materialize(
        &self,
        conn: &Connection,
        spec: TransportIdentitySpec,
    ) -> Result<String, TransportIdentityError>;
}
