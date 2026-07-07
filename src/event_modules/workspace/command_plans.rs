use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::transport::{load_local_daemon_endpoint_id, MISSING_DAEMON_IDENTITY_ERROR};

pub(crate) const MISSING_LOCAL_DAEMON_ENDPOINT_SHARED_ERROR: &str =
    "daemon endpoint_shared not found; start the daemon first";
pub(crate) const MALFORMED_LOCAL_DAEMON_IDENTITY_ERROR: &str = "daemon identity is malformed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExplicitBootstrapEndpointState {
    Absent,
    Present([u8; 32]),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalDaemonEndpointState {
    Missing,
    Present([u8; 32]),
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InviteBootstrapEndpointDecisionContext {
    pub explicit_endpoint: ExplicitBootstrapEndpointState,
    pub local_daemon_endpoint: LocalDaemonEndpointState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InviteBootstrapEndpointPlan {
    UseExplicit([u8; 32]),
    UseLocalDaemon([u8; 32]),
    RejectInvalidExplicit,
    RejectMissingLocalDaemonIdentity,
    RejectMalformedLocalDaemonIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalEndpointSharedState {
    Missing,
    Present(EventId),
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalEndpointSharedDecisionContext {
    pub local_endpoint_shared: LocalEndpointSharedState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalEndpointSharedPlan {
    UseLocalEndpointShared(EventId),
    RejectMissingLocalDaemonIdentity,
    RejectMalformedLocalDaemonIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoveMemberTargetKind {
    User,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoveMemberDecisionContext {
    pub actor_is_admin: bool,
    pub targets_self: bool,
    pub already_removed: bool,
    pub target_kind: RemoveMemberTargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoveMemberPlan {
    Proceed,
    RejectNotAdmin,
    RejectSelfTarget,
    RejectAlreadyRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GrantAdminDecisionContext {
    pub actor_is_admin: bool,
    pub target_already_admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantAdminPlan {
    Proceed,
    RejectNotAdmin,
    RejectAlreadyAdmin,
}

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(bytes)
}

fn decode_explicit_bootstrap_endpoint(
    public_endpoint_id_hex: Option<&str>,
) -> ExplicitBootstrapEndpointState {
    match public_endpoint_id_hex {
        Some(value) => match decode_hex32(value) {
            Some(endpoint_id) => ExplicitBootstrapEndpointState::Present(endpoint_id),
            None => ExplicitBootstrapEndpointState::Invalid,
        },
        None => ExplicitBootstrapEndpointState::Absent,
    }
}

fn load_local_daemon_endpoint_state(
    db: &Connection,
) -> Result<LocalDaemonEndpointState, Box<dyn std::error::Error + Send + Sync>> {
    Ok(match load_local_daemon_endpoint_id(db)? {
        Some(endpoint_id_hex) => match decode_hex32(&endpoint_id_hex) {
            Some(endpoint_id) => LocalDaemonEndpointState::Present(endpoint_id),
            None => LocalDaemonEndpointState::Malformed,
        },
        None => LocalDaemonEndpointState::Missing,
    })
}

pub(crate) fn load_invite_bootstrap_endpoint_decision_context(
    db: &Connection,
    public_endpoint_id_hex: Option<&str>,
) -> Result<InviteBootstrapEndpointDecisionContext, Box<dyn std::error::Error + Send + Sync>> {
    Ok(InviteBootstrapEndpointDecisionContext {
        explicit_endpoint: decode_explicit_bootstrap_endpoint(public_endpoint_id_hex),
        local_daemon_endpoint: load_local_daemon_endpoint_state(db)?,
    })
}

pub(crate) fn decide_invite_bootstrap_endpoint_plan(
    context: &InviteBootstrapEndpointDecisionContext,
) -> InviteBootstrapEndpointPlan {
    // The plan-tag dispatch is verified in verus-proofs. Runtime projects its rich
    // `Present(_)` payloads to payload-less tags, runs the verified dispatcher, and
    // rehydrates the original `[u8; 32]` payload on the `Use*` branches.
    use topo_verus_proofs::event_modules::workspace::command_plans::{
        decide_invite_bootstrap_endpoint_plan_core, ExplicitBootstrapEndpointStateCore,
        InviteBootstrapEndpointDecisionContextCore, InviteBootstrapEndpointPlanCore,
        LocalDaemonEndpointStateCore,
    };
    let core_ctx = InviteBootstrapEndpointDecisionContextCore {
        explicit_endpoint: match context.explicit_endpoint {
            ExplicitBootstrapEndpointState::Absent => ExplicitBootstrapEndpointStateCore::Absent,
            ExplicitBootstrapEndpointState::Present(_) => {
                ExplicitBootstrapEndpointStateCore::Present
            }
            ExplicitBootstrapEndpointState::Invalid => ExplicitBootstrapEndpointStateCore::Invalid,
        },
        local_daemon_endpoint: match context.local_daemon_endpoint {
            LocalDaemonEndpointState::Missing => LocalDaemonEndpointStateCore::Missing,
            LocalDaemonEndpointState::Present(_) => LocalDaemonEndpointStateCore::Present,
            LocalDaemonEndpointState::Malformed => LocalDaemonEndpointStateCore::Malformed,
        },
    };
    match decide_invite_bootstrap_endpoint_plan_core(core_ctx) {
        InviteBootstrapEndpointPlanCore::UseExplicit => match context.explicit_endpoint {
            ExplicitBootstrapEndpointState::Present(endpoint_id) => {
                InviteBootstrapEndpointPlan::UseExplicit(endpoint_id)
            }
            _ => unreachable!("core returned UseExplicit but explicit_endpoint was not Present"),
        },
        InviteBootstrapEndpointPlanCore::UseLocalDaemon => match context.local_daemon_endpoint {
            LocalDaemonEndpointState::Present(endpoint_id) => {
                InviteBootstrapEndpointPlan::UseLocalDaemon(endpoint_id)
            }
            _ => unreachable!(
                "core returned UseLocalDaemon but local daemon endpoint was not Present"
            ),
        },
        InviteBootstrapEndpointPlanCore::RejectInvalidExplicit => {
            InviteBootstrapEndpointPlan::RejectInvalidExplicit
        }
        InviteBootstrapEndpointPlanCore::RejectMissingLocalDaemonIdentity => {
            InviteBootstrapEndpointPlan::RejectMissingLocalDaemonIdentity
        }
        InviteBootstrapEndpointPlanCore::RejectMalformedLocalDaemonIdentity => {
            InviteBootstrapEndpointPlan::RejectMalformedLocalDaemonIdentity
        }
    }
}

pub(crate) fn resolve_invite_bootstrap_endpoint_plan(
    plan: InviteBootstrapEndpointPlan,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    match plan {
        InviteBootstrapEndpointPlan::UseExplicit(endpoint_id)
        | InviteBootstrapEndpointPlan::UseLocalDaemon(endpoint_id) => Ok(endpoint_id),
        InviteBootstrapEndpointPlan::RejectInvalidExplicit => {
            Err("endpoint_id is not valid 32-byte hex endpoint id".into())
        }
        InviteBootstrapEndpointPlan::RejectMissingLocalDaemonIdentity => {
            Err(MISSING_DAEMON_IDENTITY_ERROR.into())
        }
        InviteBootstrapEndpointPlan::RejectMalformedLocalDaemonIdentity => {
            Err(MALFORMED_LOCAL_DAEMON_IDENTITY_ERROR.into())
        }
    }
}

pub(crate) fn load_local_endpoint_shared_decision_context(
    db: &Connection,
) -> Result<LocalEndpointSharedDecisionContext, Box<dyn std::error::Error + Send + Sync>> {
    let local_endpoint_shared =
        match crate::event_modules::endpoint_secret::load_local_endpoint_secret(db)? {
            Some(secret_row) => {
                let event_id =
                    crate::event_modules::endpoint_shared::deterministic_endpoint_shared_event_id(
                        &secret_row.private_key_bytes,
                    );
                let event_present: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1)",
                    rusqlite::params![event_id_to_base64(&event_id)],
                    |row| row.get(0),
                )?;
                if event_present {
                    LocalEndpointSharedState::Present(event_id)
                } else {
                    LocalEndpointSharedState::Missing
                }
            }
            None => match crate::event_modules::endpoint_shared::load_local_endpoint_shared(db)? {
                Some(row) => match event_id_from_base64(&row.event_id) {
                    Some(event_id) => LocalEndpointSharedState::Present(event_id),
                    None => LocalEndpointSharedState::Malformed,
                },
                None => LocalEndpointSharedState::Missing,
            },
        };
    Ok(LocalEndpointSharedDecisionContext {
        local_endpoint_shared,
    })
}

pub(crate) fn decide_local_endpoint_shared_plan(
    context: &LocalEndpointSharedDecisionContext,
) -> LocalEndpointSharedPlan {
    use topo_verus_proofs::event_modules::workspace::command_plans::{
        decide_local_endpoint_shared_plan_core, LocalEndpointSharedDecisionContextCore,
        LocalEndpointSharedPlanCore, LocalEndpointSharedStateCore,
    };
    let core_ctx = LocalEndpointSharedDecisionContextCore {
        local_endpoint_shared: match context.local_endpoint_shared {
            LocalEndpointSharedState::Missing => LocalEndpointSharedStateCore::Missing,
            LocalEndpointSharedState::Present(_) => LocalEndpointSharedStateCore::Present,
            LocalEndpointSharedState::Malformed => LocalEndpointSharedStateCore::Malformed,
        },
    };
    match decide_local_endpoint_shared_plan_core(core_ctx) {
        LocalEndpointSharedPlanCore::UseLocalEndpointShared => match context.local_endpoint_shared {
            LocalEndpointSharedState::Present(event_id) => {
                LocalEndpointSharedPlan::UseLocalEndpointShared(event_id)
            }
            _ => unreachable!(
                "core returned UseLocalEndpointShared but local_endpoint_shared was not Present"
            ),
        },
        LocalEndpointSharedPlanCore::RejectMissingLocalDaemonIdentity => {
            LocalEndpointSharedPlan::RejectMissingLocalDaemonIdentity
        }
        LocalEndpointSharedPlanCore::RejectMalformedLocalDaemonIdentity => {
            LocalEndpointSharedPlan::RejectMalformedLocalDaemonIdentity
        }
    }
}

pub(crate) fn resolve_local_endpoint_shared_plan(
    plan: LocalEndpointSharedPlan,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    match plan {
        LocalEndpointSharedPlan::UseLocalEndpointShared(event_id) => Ok(event_id),
        LocalEndpointSharedPlan::RejectMissingLocalDaemonIdentity => {
            Err(MISSING_LOCAL_DAEMON_ENDPOINT_SHARED_ERROR.into())
        }
        LocalEndpointSharedPlan::RejectMalformedLocalDaemonIdentity => {
            Err(MALFORMED_LOCAL_DAEMON_IDENTITY_ERROR.into())
        }
    }
}

pub(crate) fn decide_remove_member_plan(context: &RemoveMemberDecisionContext) -> RemoveMemberPlan {
    use topo_verus_proofs::event_modules::workspace::command_plans::{
        decide_remove_member_plan_core, RemoveMemberDecisionContextCore, RemoveMemberPlanCore,
        RemoveMemberTargetKindCore,
    };
    let core_ctx = RemoveMemberDecisionContextCore {
        actor_is_admin: context.actor_is_admin,
        targets_self: context.targets_self,
        already_removed: context.already_removed,
        target_kind: match context.target_kind {
            RemoveMemberTargetKind::User => RemoveMemberTargetKindCore::User,
            RemoveMemberTargetKind::Peer => RemoveMemberTargetKindCore::Peer,
        },
    };
    match decide_remove_member_plan_core(core_ctx) {
        RemoveMemberPlanCore::Proceed => RemoveMemberPlan::Proceed,
        RemoveMemberPlanCore::RejectNotAdmin => RemoveMemberPlan::RejectNotAdmin,
        RemoveMemberPlanCore::RejectSelfTarget => RemoveMemberPlan::RejectSelfTarget,
        RemoveMemberPlanCore::RejectAlreadyRemoved => RemoveMemberPlan::RejectAlreadyRemoved,
    }
}

pub(crate) fn resolve_remove_member_plan(
    plan: RemoveMemberPlan,
    target_kind: RemoveMemberTargetKind,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match (plan, target_kind) {
        (RemoveMemberPlan::Proceed, _) => Ok(()),
        (RemoveMemberPlan::RejectNotAdmin, _) => {
            Err("Local peer signer is not admin for this workspace.".into())
        }
        (RemoveMemberPlan::RejectSelfTarget, RemoveMemberTargetKind::User) => {
            Err("cannot ban the active local user".into())
        }
        (RemoveMemberPlan::RejectSelfTarget, RemoveMemberTargetKind::Peer) => {
            Err("cannot unlink the active local device".into())
        }
        (RemoveMemberPlan::RejectAlreadyRemoved, RemoveMemberTargetKind::User) => {
            Err("user is already removed".into())
        }
        (RemoveMemberPlan::RejectAlreadyRemoved, RemoveMemberTargetKind::Peer) => {
            Err("device is already unlinked".into())
        }
    }
}

pub(crate) fn decide_grant_admin_plan(context: &GrantAdminDecisionContext) -> GrantAdminPlan {
    use topo_verus_proofs::event_modules::workspace::command_plans::{
        decide_grant_admin_plan_core, GrantAdminDecisionContextCore, GrantAdminPlanCore,
    };
    let core_ctx = GrantAdminDecisionContextCore {
        actor_is_admin: context.actor_is_admin,
        target_already_admin: context.target_already_admin,
    };
    match decide_grant_admin_plan_core(core_ctx) {
        GrantAdminPlanCore::Proceed => GrantAdminPlan::Proceed,
        GrantAdminPlanCore::RejectNotAdmin => GrantAdminPlan::RejectNotAdmin,
        GrantAdminPlanCore::RejectAlreadyAdmin => GrantAdminPlan::RejectAlreadyAdmin,
    }
}

pub(crate) fn resolve_grant_admin_plan(
    plan: GrantAdminPlan,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match plan {
        GrantAdminPlan::Proceed => Ok(()),
        GrantAdminPlan::RejectNotAdmin => {
            Err("Local peer signer is not admin for this workspace.".into())
        }
        GrantAdminPlan::RejectAlreadyAdmin => Err("user is already admin".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_bootstrap_plan_prefers_explicit_endpoint() {
        let explicit = [0x11; 32];
        let plan = decide_invite_bootstrap_endpoint_plan(&InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Present(explicit),
            local_daemon_endpoint: LocalDaemonEndpointState::Missing,
        });
        assert_eq!(plan, InviteBootstrapEndpointPlan::UseExplicit(explicit));
    }

    #[test]
    fn invite_bootstrap_plan_rejects_missing_local_daemon_identity_without_explicit() {
        let plan = decide_invite_bootstrap_endpoint_plan(&InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Absent,
            local_daemon_endpoint: LocalDaemonEndpointState::Missing,
        });
        assert_eq!(
            plan,
            InviteBootstrapEndpointPlan::RejectMissingLocalDaemonIdentity
        );
    }

    #[test]
    fn invite_bootstrap_plan_rejects_invalid_explicit_endpoint() {
        let plan = decide_invite_bootstrap_endpoint_plan(&InviteBootstrapEndpointDecisionContext {
            explicit_endpoint: ExplicitBootstrapEndpointState::Invalid,
            local_daemon_endpoint: LocalDaemonEndpointState::Present([0x22; 32]),
        });
        assert_eq!(plan, InviteBootstrapEndpointPlan::RejectInvalidExplicit);
    }

    #[test]
    fn local_endpoint_shared_plan_rejects_missing_identity() {
        let plan = decide_local_endpoint_shared_plan(&LocalEndpointSharedDecisionContext {
            local_endpoint_shared: LocalEndpointSharedState::Missing,
        });
        assert_eq!(
            plan,
            LocalEndpointSharedPlan::RejectMissingLocalDaemonIdentity
        );
    }

    #[test]
    fn remove_member_plan_rejects_non_admin_before_other_checks() {
        let plan = decide_remove_member_plan(&RemoveMemberDecisionContext {
            actor_is_admin: false,
            targets_self: false,
            already_removed: false,
            target_kind: RemoveMemberTargetKind::User,
        });
        assert_eq!(plan, RemoveMemberPlan::RejectNotAdmin);
    }

    #[test]
    fn remove_member_plan_rejects_self_target_for_peer() {
        let plan = decide_remove_member_plan(&RemoveMemberDecisionContext {
            actor_is_admin: true,
            targets_self: true,
            already_removed: false,
            target_kind: RemoveMemberTargetKind::Peer,
        });
        assert_eq!(plan, RemoveMemberPlan::RejectSelfTarget);
        let err = resolve_remove_member_plan(plan, RemoveMemberTargetKind::Peer)
            .expect_err("self-target unlink must reject");
        assert_eq!(err.to_string(), "cannot unlink the active local device");
    }

    #[test]
    fn remove_member_plan_rejects_already_removed_user() {
        let plan = decide_remove_member_plan(&RemoveMemberDecisionContext {
            actor_is_admin: true,
            targets_self: false,
            already_removed: true,
            target_kind: RemoveMemberTargetKind::User,
        });
        assert_eq!(plan, RemoveMemberPlan::RejectAlreadyRemoved);
        let err = resolve_remove_member_plan(plan, RemoveMemberTargetKind::User)
            .expect_err("already removed user must reject");
        assert_eq!(err.to_string(), "user is already removed");
    }

    #[test]
    fn grant_admin_plan_rejects_non_admin_before_already_admin() {
        let plan = decide_grant_admin_plan(&GrantAdminDecisionContext {
            actor_is_admin: false,
            target_already_admin: true,
        });
        assert_eq!(plan, GrantAdminPlan::RejectNotAdmin);
        let err = resolve_grant_admin_plan(plan).expect_err("non-admin grant should reject");
        assert_eq!(
            err.to_string(),
            "Local peer signer is not admin for this workspace."
        );
    }

    #[test]
    fn grant_admin_plan_rejects_already_admin_target() {
        let plan = decide_grant_admin_plan(&GrantAdminDecisionContext {
            actor_is_admin: true,
            target_already_admin: true,
        });
        assert_eq!(plan, GrantAdminPlan::RejectAlreadyAdmin);
        let err = resolve_grant_admin_plan(plan).expect_err("already-admin target must reject");
        assert_eq!(err.to_string(), "user is already admin");
    }
}
