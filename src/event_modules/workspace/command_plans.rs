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
    match context.explicit_endpoint {
        ExplicitBootstrapEndpointState::Present(endpoint_id) => {
            InviteBootstrapEndpointPlan::UseExplicit(endpoint_id)
        }
        ExplicitBootstrapEndpointState::Invalid => {
            InviteBootstrapEndpointPlan::RejectInvalidExplicit
        }
        ExplicitBootstrapEndpointState::Absent => match context.local_daemon_endpoint {
            LocalDaemonEndpointState::Present(endpoint_id) => {
                InviteBootstrapEndpointPlan::UseLocalDaemon(endpoint_id)
            }
            LocalDaemonEndpointState::Missing => {
                InviteBootstrapEndpointPlan::RejectMissingLocalDaemonIdentity
            }
            LocalDaemonEndpointState::Malformed => {
                InviteBootstrapEndpointPlan::RejectMalformedLocalDaemonIdentity
            }
        },
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
    match context.local_endpoint_shared {
        LocalEndpointSharedState::Present(event_id) => {
            LocalEndpointSharedPlan::UseLocalEndpointShared(event_id)
        }
        LocalEndpointSharedState::Missing => {
            LocalEndpointSharedPlan::RejectMissingLocalDaemonIdentity
        }
        LocalEndpointSharedState::Malformed => {
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
}
