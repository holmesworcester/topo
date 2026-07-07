//! Signer chain structural discipline — verified.
//!
//! A Signed event carries `signer_event_id: [u8; 32]` referencing another event that
//! must be a *valid signer identity*. Only a small, fixed set of event types carry
//! a public key intended for signing: Workspace, UserInvite, DeviceInvite, User,
//! PeerShared, Admin. Other types (Message, Reaction, Signed, Encrypted, KeySecret,
//! etc.) must never be accepted as signer identities — doing so would either
//! break the signer-key lookup or let an attacker use content events as keys.
//!
//! This is a *structural* check (what types are valid signers), orthogonal to the
//! cryptographic signature verification itself (which is trusted via ed25519-dalek).
//!
//! Runtime `src/state/projection/signer.rs::signer_identity_from_parsed` uses this
//! predicate as an early gate before the Rust match; a type-code not in the valid
//! set is rejected via the predicate without reaching the runtime's match arms,
//! preserving a single source of truth about which types are signers.

use crate::event_modules::registry::EventTypeCode;
use vstd::prelude::*;

verus! {

/// True iff the given event type is a valid signer identity (carries a public key
/// intended for signing). The exhaustive match enforces totality: any new
/// `EventTypeCode` variant must be classified as signer/non-signer at compile time.
pub fn is_valid_signer_type(code: EventTypeCode) -> (ok: bool)
    ensures
        ok == match code {
            EventTypeCode::Workspace
            | EventTypeCode::UserInvite
            | EventTypeCode::DeviceInvite
            | EventTypeCode::User
            | EventTypeCode::PeerShared
            | EventTypeCode::Admin => true,
            EventTypeCode::Message
            | EventTypeCode::Reaction
            | EventTypeCode::Encrypted
            | EventTypeCode::KeySecret
            | EventTypeCode::MessageDeletion
            | EventTypeCode::InviteAccepted
            | EventTypeCode::KeyShared
            | EventTypeCode::File
            | EventTypeCode::FileSlice
            | EventTypeCode::BenchDep
            | EventTypeCode::PeerSecret
            | EventTypeCode::InviteSecret
            | EventTypeCode::Tenant
            | EventTypeCode::KeyRequest
            | EventTypeCode::Removal
            | EventTypeCode::KeyRotation
            | EventTypeCode::EndpointSecret
            | EventTypeCode::EndpointShared
            | EventTypeCode::Signed => false,
        },
{
    match code {
        EventTypeCode::Workspace
        | EventTypeCode::UserInvite
        | EventTypeCode::DeviceInvite
        | EventTypeCode::User
        | EventTypeCode::PeerShared
        | EventTypeCode::Admin => true,
        EventTypeCode::Message
        | EventTypeCode::Reaction
        | EventTypeCode::Encrypted
        | EventTypeCode::KeySecret
        | EventTypeCode::MessageDeletion
        | EventTypeCode::InviteAccepted
        | EventTypeCode::KeyShared
        | EventTypeCode::File
        | EventTypeCode::FileSlice
        | EventTypeCode::BenchDep
        | EventTypeCode::PeerSecret
        | EventTypeCode::InviteSecret
        | EventTypeCode::Tenant
        | EventTypeCode::KeyRequest
        | EventTypeCode::Removal
        | EventTypeCode::KeyRotation
        | EventTypeCode::EndpointSecret
        | EventTypeCode::EndpointShared
        | EventTypeCode::Signed => false,
    }
}

} // verus!
