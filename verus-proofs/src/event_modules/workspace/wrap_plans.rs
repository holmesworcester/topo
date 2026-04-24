//! Verified planners for workspace sender-side wrap targets.
//!
//! Runtime uses these cores to keep two sender seams small and checkable:
//! - which peer_shared rows are eligible rotation recipients for the current
//!   removal frontier;
//! - which recipient ids/public keys are copied into authored key-rotation /
//!   key-history events.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationRecipientAuthorizationPlanCore {
    Include,
    ExcludeMissingPedigree,
    ExcludeRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationRecipientAuthorizationDecisionContextCore {
    pub has_peer_pedigree: bool,
    pub touches_removed_member: bool,
}

pub fn decide_rotation_recipient_authorization_plan_core(
    context: RotationRecipientAuthorizationDecisionContextCore,
) -> (plan: RotationRecipientAuthorizationPlanCore)
    ensures
        !context.has_peer_pedigree
            ==> plan == RotationRecipientAuthorizationPlanCore::ExcludeMissingPedigree,
        (context.has_peer_pedigree && context.touches_removed_member)
            ==> plan == RotationRecipientAuthorizationPlanCore::ExcludeRemoved,
        (context.has_peer_pedigree && !context.touches_removed_member)
            ==> plan == RotationRecipientAuthorizationPlanCore::Include,
{
    if !context.has_peer_pedigree {
        RotationRecipientAuthorizationPlanCore::ExcludeMissingPedigree
    } else if context.touches_removed_member {
        RotationRecipientAuthorizationPlanCore::ExcludeRemoved
    } else {
        RotationRecipientAuthorizationPlanCore::Include
    }
}

pub fn rotation_recipient_slots_prefix_core(
    recipient_event_ids: &[[u8; 32]],
) -> (slots: Vec<[u8; 32]>)
    ensures
        slots@ =~= recipient_event_ids@,
{
    let mut copied = Vec::with_capacity(recipient_event_ids.len());
    let mut i = 0;
    while i < recipient_event_ids.len()
        invariant
            0 <= i <= recipient_event_ids.len(),
            copied@ =~= recipient_event_ids@.subrange(0, i as int),
        decreases recipient_event_ids.len() - i
    {
        copied.push(recipient_event_ids[i]);
        i += 1;
    }
    copied
}

pub fn key_history_recipient_public_key_core(
    recipient_public_key: &[u8; 32],
) -> (public_key: [u8; 32])
    ensures
        public_key == *recipient_public_key,
{
    *recipient_public_key
}

} // verus!
