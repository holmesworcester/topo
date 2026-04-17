//! **Abstract specification — not grounded in runtime code.**
//!
//! Per `docs/planning/FORMAL_SEAM_COVERAGE.md`, this file encodes system-level
//! invariants that no single runtime function body satisfies on its own. The
//! SMT solver accepts the proofs inside this file, but they are NOT proofs about
//! runtime code — the grounded verification lives in the per-seam `ensures`
//! clauses on executable `pub fn`s in sibling modules. Do not treat entries
//! here as "the runtime is proven to satisfy X"; treat them as "X is modeled
//! in Verus and consistent with itself".
//!
//! Basic coverage model for every registered single-node event projector.
//!
//! This deliberately models only the projector-local `DecisionContext -> Result`
//! shape. SQL query correctness, cryptographic equality, and byte parsing stay in
//! runtime tests and typed query normalizers.

use vstd::prelude::*;
use crate::contract::*;
use crate::decision::*;

verus! {

pub enum RegisteredProjectorKind {
    Message,
    Reaction,
    SignedEnvelope,
    EncryptedEnvelope,
    KeySecret,
    MessageDeletion,
    Workspace,
    InviteAccepted,
    Removal,
    KeyRotation,
    KeyRequest,
    UserInvite,
    DeviceInvite,
    User,
    PeerShared,
    Admin,
    KeyShared,
    Tenant,
    File,
    FileSlice,
    BenchDep,
    PeerSecret,
    InviteSecret,
    EndpointSecret,
    EndpointShared,
}

pub struct BasicProjectorContext {
    pub expected_variant: bool,
    pub required_text_empty: bool,
    pub signer_user_mismatch: bool,
    pub owner_mismatch: bool,
    pub current_signer_present: bool,
    pub signer_field_matches_current_signer: bool,
    pub file_descriptor_count: nat,
    pub file_descriptor_authorized: bool,
    pub file_slice_idempotent_replay: bool,
    pub file_slice_slot_conflict: bool,
    pub local_create: bool,
    pub has_bootstrap_context: bool,
    pub bootstrap_addr_count: nat,
    pub has_local_invite_secret: bool,
    pub peer_shared_transport_identity_active: bool,
    pub bootstrap_spki_already_peer_shared: bool,
    pub peer_shared_endpoint_bound: bool,
    pub frontier_slots_valid: bool,
    pub frontier_refs_canonical: bool,
    pub frontier_hash_valid: bool,
    pub delivery_target_valid: bool,
    pub unwrapped_secret_present: bool,
    pub unwrapped_secret_matches_claim: bool,
    pub endpoint_recorded_by_matches_key: bool,
    pub endpoint_self_signature_valid: bool,
    pub deletion_intent_matches: bool,
    pub target_is_non_message: bool,
    pub target_tombstone_present: bool,
    pub target_tombstone_author_matches: bool,
    pub target_message_author_present: bool,
    pub target_message_author_matches: bool,
}

pub open spec fn simple_insert_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant {
        mk_reject()
    } else {
        mk_valid(1nat)
    }
}

pub open spec fn local_invite_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant {
        mk_reject()
    } else if c.local_create && c.has_bootstrap_context {
        mk_valid(2nat)
    } else {
        mk_valid(1nat)
    }
}

pub open spec fn invite_accepted_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant {
        mk_reject()
    } else {
        let trust_writes = if !c.bootstrap_spki_already_peer_shared && c.has_bootstrap_context {
            c.bootstrap_addr_count
        } else {
            0nat
        };
        let materialize_commands: nat = if c.has_local_invite_secret && !c.peer_shared_transport_identity_active {
            1nat
        } else {
            0nat
        };
        mk_valid_with_commands(1nat + trust_writes, 1nat + materialize_commands)
    }
}

pub open spec fn key_shared_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant
        || !c.frontier_slots_valid
        || !c.frontier_refs_canonical
        || !c.frontier_hash_valid
        || !c.delivery_target_valid
        || (c.unwrapped_secret_present && !c.unwrapped_secret_matches_claim)
    {
        mk_reject()
    } else if c.unwrapped_secret_present {
        mk_valid_with_commands(1nat, 1nat)
    } else {
        mk_valid(1nat)
    }
}

pub open spec fn signer_frontier_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant
        || !c.current_signer_present
        || !c.signer_field_matches_current_signer
        || !c.frontier_slots_valid
        || !c.frontier_refs_canonical
        || !c.frontier_hash_valid
    {
        mk_reject()
    } else {
        mk_valid(1nat)
    }
}

pub open spec fn message_deletion_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant
        || c.signer_user_mismatch
        || c.owner_mismatch
        || c.target_is_non_message
        || (c.target_tombstone_present && !c.target_tombstone_author_matches)
        || (c.target_message_author_present && !c.target_message_author_matches)
    {
        mk_reject()
    } else if c.target_tombstone_present {
        mk_valid_with_commands(1nat, 1nat)
    } else if c.target_message_author_present {
        mk_valid_with_commands(2nat, 1nat)
    } else {
        mk_valid(1nat)
    }
}

pub open spec fn file_slice_projector_result(c: &BasicProjectorContext) -> ProjectorResult {
    if !c.expected_variant || !c.current_signer_present {
        mk_reject()
    } else if c.file_descriptor_count == 0nat {
        mk_block(1nat)
    } else if c.file_descriptor_count > 1
        || !c.file_descriptor_authorized
        || c.file_slice_slot_conflict
    {
        mk_reject()
    } else if c.file_slice_idempotent_replay {
        mk_valid(0nat)
    } else {
        mk_valid(1nat)
    }
}

pub open spec fn basic_projector_result(
    kind: RegisteredProjectorKind,
    c: &BasicProjectorContext,
) -> ProjectorResult {
    match kind {
        RegisteredProjectorKind::SignedEnvelope
        | RegisteredProjectorKind::EncryptedEnvelope => mk_reject(),
        RegisteredProjectorKind::BenchDep => if c.expected_variant { mk_valid(0nat) } else { mk_reject() },
        RegisteredProjectorKind::Workspace
        | RegisteredProjectorKind::Admin
        | RegisteredProjectorKind::KeySecret
        | RegisteredProjectorKind::InviteSecret
        | RegisteredProjectorKind::Tenant => simple_insert_projector_result(c),
        RegisteredProjectorKind::PeerSecret => if c.expected_variant { mk_valid_with_commands(1nat, 1nat) } else { mk_reject() },
        RegisteredProjectorKind::EndpointSecret => if c.expected_variant && c.endpoint_recorded_by_matches_key { mk_valid(1nat) } else { mk_reject() },
        RegisteredProjectorKind::EndpointShared => if c.expected_variant && c.endpoint_recorded_by_matches_key && c.endpoint_self_signature_valid { mk_valid(1nat) } else { mk_reject() },
        RegisteredProjectorKind::User => if c.expected_variant && !c.required_text_empty { mk_valid(1nat) } else { mk_reject() },
        RegisteredProjectorKind::Message => if !c.expected_variant || c.required_text_empty || c.signer_user_mismatch || c.owner_mismatch {
            mk_reject()
        } else if c.deletion_intent_matches {
            mk_valid_with_commands(1nat, 1nat)
        } else {
            mk_valid(1nat)
        },
        RegisteredProjectorKind::Reaction => if c.expected_variant && !c.required_text_empty && !c.signer_user_mismatch && !c.owner_mismatch {
            mk_valid(1nat)
        } else {
            mk_reject()
        },
        RegisteredProjectorKind::MessageDeletion => message_deletion_projector_result(c),
        RegisteredProjectorKind::File => if c.expected_variant && c.current_signer_present && !c.owner_mismatch { mk_valid(1nat) } else { mk_reject() },
        RegisteredProjectorKind::FileSlice => file_slice_projector_result(c),
        RegisteredProjectorKind::UserInvite
        | RegisteredProjectorKind::DeviceInvite => local_invite_projector_result(c),
        RegisteredProjectorKind::InviteAccepted => invite_accepted_projector_result(c),
        RegisteredProjectorKind::PeerShared => if c.expected_variant && c.peer_shared_endpoint_bound { mk_valid(1nat) } else { mk_reject() },
        RegisteredProjectorKind::KeyRequest => if c.expected_variant && c.current_signer_present && c.delivery_target_valid { mk_valid(1nat) } else { mk_reject() },
        RegisteredProjectorKind::Removal
        | RegisteredProjectorKind::KeyRotation => signer_frontier_projector_result(c),
        RegisteredProjectorKind::KeyShared => key_shared_projector_result(c),
    }
}

pub open spec fn registered_projector_model_count() -> nat {
    25nat
}

proof fn registered_projector_count_matches_runtime_gate()
    ensures registered_projector_model_count() == 25nat,
{
}

proof fn every_basic_projector_result_is_well_formed(kind: RegisteredProjectorKind, c: BasicProjectorContext)
    ensures result_is_well_formed(&basic_projector_result(kind, &c)),
{
}

proof fn wrong_variant_is_inert(kind: RegisteredProjectorKind, c: BasicProjectorContext)
    requires !c.expected_variant
    ensures
        !matches!(basic_projector_result(kind, &c).decision, ProjectionDecision::Valid),
        basic_projector_result(kind, &c).write_ops_count == 0nat,
        basic_projector_result(kind, &c).emit_commands_count == 0nat,
{
}

proof fn envelope_projectors_are_dispatch_only(c: BasicProjectorContext)
    ensures
        basic_projector_result(RegisteredProjectorKind::SignedEnvelope, &c) == mk_reject(),
        basic_projector_result(RegisteredProjectorKind::EncryptedEnvelope, &c) == mk_reject(),
{
}

proof fn local_invites_write_pending_bootstrap_trust_only_for_local_bootstrap(c: BasicProjectorContext)
    requires c.expected_variant
    ensures
        ((c.local_create && c.has_bootstrap_context) ==> local_invite_projector_result(&c).write_ops_count == 2nat),
        (!(c.local_create && c.has_bootstrap_context) ==> local_invite_projector_result(&c).write_ops_count == 1nat),
{
}

proof fn invite_accepted_bootstrap_trust_is_gated(c: BasicProjectorContext)
    requires c.expected_variant
    ensures
        ((!c.bootstrap_spki_already_peer_shared && c.has_bootstrap_context) ==> invite_accepted_projector_result(&c).write_ops_count == 1nat + c.bootstrap_addr_count),
        ((c.bootstrap_spki_already_peer_shared || !c.has_bootstrap_context) ==> invite_accepted_projector_result(&c).write_ops_count == 1nat),
{
}

proof fn file_slice_block_has_no_writes(c: BasicProjectorContext)
    requires
        c.expected_variant,
        c.current_signer_present,
        c.file_descriptor_count == 0nat,
    ensures
        matches!(file_slice_projector_result(&c).decision, ProjectionDecision::Block { .. }),
        file_slice_projector_result(&c).write_ops_count == 0nat,
{
}

proof fn file_slice_write_requires_unique_authorized_descriptor(c: BasicProjectorContext)
    requires
        c.expected_variant,
        c.current_signer_present,
        file_slice_projector_result(&c).write_ops_count > 0nat,
    ensures
        c.file_descriptor_count == 1,
        c.file_descriptor_authorized,
        !c.file_slice_slot_conflict,
{
}

proof fn key_shared_emit_secret_requires_matching_unwrapped_material(c: BasicProjectorContext)
    requires key_shared_projector_result(&c).emit_commands_count > 0nat
    ensures
        c.expected_variant,
        c.frontier_slots_valid,
        c.frontier_refs_canonical,
        c.frontier_hash_valid,
        c.delivery_target_valid,
        c.unwrapped_secret_present,
        c.unwrapped_secret_matches_claim,
{
}

proof fn signer_frontier_writes_require_canonical_frontier_and_matching_signer(c: BasicProjectorContext)
    requires signer_frontier_projector_result(&c).write_ops_count > 0nat
    ensures
        c.expected_variant,
        c.current_signer_present,
        c.signer_field_matches_current_signer,
        c.frontier_slots_valid,
        c.frontier_refs_canonical,
        c.frontier_hash_valid,
{
}

proof fn endpoint_shared_write_requires_local_endpoint_and_self_signature(c: BasicProjectorContext)
    requires basic_projector_result(RegisteredProjectorKind::EndpointShared, &c).write_ops_count > 0nat
    ensures
        c.expected_variant,
        c.endpoint_recorded_by_matches_key,
        c.endpoint_self_signature_valid,
{
}

proof fn peer_shared_write_requires_endpoint_binding(c: BasicProjectorContext)
    requires basic_projector_result(RegisteredProjectorKind::PeerShared, &c).write_ops_count > 0nat
    ensures c.expected_variant && c.peer_shared_endpoint_bound,
{
}

} // verus!
