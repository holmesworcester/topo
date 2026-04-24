use crate::crypto::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RotationRecipientAuthorizationDecisionContext {
    pub has_peer_pedigree: bool,
    pub touches_removed_member: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotationRecipientAuthorizationPlan {
    Include,
    ExcludeMissingPedigree,
    ExcludeRemoved,
}

pub(crate) fn decide_rotation_recipient_authorization_plan(
    context: &RotationRecipientAuthorizationDecisionContext,
) -> RotationRecipientAuthorizationPlan {
    use topo_verus_proofs::event_modules::workspace::wrap_plans::{
        decide_rotation_recipient_authorization_plan_core,
        RotationRecipientAuthorizationDecisionContextCore, RotationRecipientAuthorizationPlanCore,
    };

    let core_ctx = RotationRecipientAuthorizationDecisionContextCore {
        has_peer_pedigree: context.has_peer_pedigree,
        touches_removed_member: context.touches_removed_member,
    };
    match decide_rotation_recipient_authorization_plan_core(core_ctx) {
        RotationRecipientAuthorizationPlanCore::Include => {
            RotationRecipientAuthorizationPlan::Include
        }
        RotationRecipientAuthorizationPlanCore::ExcludeMissingPedigree => {
            RotationRecipientAuthorizationPlan::ExcludeMissingPedigree
        }
        RotationRecipientAuthorizationPlanCore::ExcludeRemoved => {
            RotationRecipientAuthorizationPlan::ExcludeRemoved
        }
    }
}

pub(crate) fn planned_rotation_recipient_slots_prefix(
    recipient_event_ids: &[EventId],
) -> Vec<EventId> {
    topo_verus_proofs::event_modules::workspace::wrap_plans::rotation_recipient_slots_prefix_core(
        recipient_event_ids,
    )
}

pub(crate) fn planned_key_history_recipient_public_key(
    recipient_public_key: &[u8; 32],
) -> [u8; 32] {
    topo_verus_proofs::event_modules::workspace::wrap_plans::key_history_recipient_public_key_core(
        recipient_public_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_recipient_plan_includes_active_peer_with_pedigree() {
        let plan = decide_rotation_recipient_authorization_plan(
            &RotationRecipientAuthorizationDecisionContext {
                has_peer_pedigree: true,
                touches_removed_member: false,
            },
        );
        assert_eq!(plan, RotationRecipientAuthorizationPlan::Include);
    }

    #[test]
    fn rotation_recipient_plan_excludes_missing_pedigree_before_removed_check() {
        let plan = decide_rotation_recipient_authorization_plan(
            &RotationRecipientAuthorizationDecisionContext {
                has_peer_pedigree: false,
                touches_removed_member: true,
            },
        );
        assert_eq!(
            plan,
            RotationRecipientAuthorizationPlan::ExcludeMissingPedigree
        );
    }

    #[test]
    fn rotation_recipient_plan_excludes_removed_peer() {
        let plan = decide_rotation_recipient_authorization_plan(
            &RotationRecipientAuthorizationDecisionContext {
                has_peer_pedigree: true,
                touches_removed_member: true,
            },
        );
        assert_eq!(plan, RotationRecipientAuthorizationPlan::ExcludeRemoved);
    }
}
