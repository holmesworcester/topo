//! Projector registry exhaustivity — every known event-type code has a formal
//! projector-family assignment.
//!
//! The runtime test `registry_formal_projector_coverage` asserts this at runtime by
//! iterating known codes. This file mirrors the claim as a verified exec fn whose
//! body is an exhaustive `match` over an `EventTypeCode` enum with one variant per
//! type code the registry recognizes. Exhaustivity is enforced by the compiler:
//! if a new variant is added to `EventTypeCode` without a matching family, the
//! match fails to compile; if a new registered event type is added to the runtime
//! without a corresponding `EventTypeCode` variant, the trusted extractor
//! `runtime_code_to_enum` (in `src/state/projection/apply/registry_coverage.rs`)
//! goes non-exhaustive at compile time and forces the update here.

use vstd::prelude::*;

verus! {

/// One variant per registered event-type code in the runtime registry.
/// Keep in sync with the `EVENT_TYPE_*` constants in `src/event_modules/mod.rs`.
/// The current registry includes the capped shared-key fanout model
/// (`KeyRotation`, `KeyHistory`, `KeyRequest`) used by the runtime.
/// Retired codes (e.g., PEER at code 23) are intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTypeCode {
    Message,          // 1
    Reaction,         // 2
    Encrypted,        // 5
    KeySecret,        // 6
    MessageDeletion,  // 7
    Workspace,        // 8
    InviteAccepted,   // 9
    UserInvite,       // 10
    DeviceInvite,     // 12
    User,             // 14
    PeerShared,       // 16
    Admin,            // 18
    KeyShared,        // 22
    File,             // 24
    FileSlice,        // 25
    BenchDep,         // 26
    PeerSecret,       // 27
    InviteSecret,     // 28
    Tenant,           // 29
    KeyRequest,       // 30
    Removal,          // 31
    KeyRotation,      // 32
    EndpointSecret,   // 33
    EndpointShared,   // 34
    Signed,           // 35
}

/// Formal projector family assignment. Mirrors the private `FormalProjectorFamily`
/// enum in `src/event_modules/mod.rs`. Every `EventTypeCode` variant must map to
/// exactly one family — an exhaustive match is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormalProjectorFamily {
    BasicInsert,
    Content,
    EnvelopeOnlyReject,
    InviteBootstrap,
    InviteAccepted,
    PeerShared,
    KeyDelivery,
    SignerFrontier,
    FileSlice,
    EndpointRoot,
    NoWrite,
}

/// Assigns a formal projector family to every known event-type code.
/// The exhaustive match (no `_` arm) means this function is *total* over
/// `EventTypeCode`. Adding a new variant without a corresponding branch
/// fails compilation, which fails `cargo-verus verify`.
pub fn formal_family_of(code: EventTypeCode) -> (family: FormalProjectorFamily)
    ensures
        // Semantic constraints: protocol envelopes must reject (not
        // have a projector of their own); file slices go through FileSlice.
        (code == EventTypeCode::Signed || code == EventTypeCode::Encrypted)
            ==> family == FormalProjectorFamily::EnvelopeOnlyReject,
        code == EventTypeCode::FileSlice ==> family == FormalProjectorFamily::FileSlice,
        code == EventTypeCode::InviteAccepted ==> family == FormalProjectorFamily::InviteAccepted,
        code == EventTypeCode::PeerShared ==> family == FormalProjectorFamily::PeerShared,
        code == EventTypeCode::BenchDep ==> family == FormalProjectorFamily::NoWrite,
{
    match code {
        EventTypeCode::Message
        | EventTypeCode::Reaction
        | EventTypeCode::MessageDeletion => FormalProjectorFamily::Content,
        EventTypeCode::Signed | EventTypeCode::Encrypted => FormalProjectorFamily::EnvelopeOnlyReject,
        EventTypeCode::Workspace
        | EventTypeCode::User
        | EventTypeCode::Admin
        | EventTypeCode::KeySecret
        | EventTypeCode::InviteSecret
        | EventTypeCode::Tenant
        | EventTypeCode::File => FormalProjectorFamily::BasicInsert,
        EventTypeCode::UserInvite | EventTypeCode::DeviceInvite => FormalProjectorFamily::InviteBootstrap,
        EventTypeCode::InviteAccepted => FormalProjectorFamily::InviteAccepted,
        EventTypeCode::PeerShared => FormalProjectorFamily::PeerShared,
        EventTypeCode::KeyRequest | EventTypeCode::KeyShared => FormalProjectorFamily::KeyDelivery,
        EventTypeCode::Removal | EventTypeCode::KeyRotation => FormalProjectorFamily::SignerFrontier,
        EventTypeCode::FileSlice => FormalProjectorFamily::FileSlice,
        EventTypeCode::PeerSecret
        | EventTypeCode::EndpointSecret
        | EventTypeCode::EndpointShared => FormalProjectorFamily::EndpointRoot,
        EventTypeCode::BenchDep => FormalProjectorFamily::NoWrite,
    }
}

} // verus!
