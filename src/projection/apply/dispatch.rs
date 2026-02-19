use super::super::projectors::{
    project_file_slice_pure, project_message_attachment_pure, project_message_deletion_pure,
    project_message_pure, project_reaction_pure, project_secret_key_pure, project_signed_memo_pure,
};
use super::super::result::{ContextSnapshot, ProjectorResult};
use crate::event_modules::ParsedEvent;

/// Dispatch to the appropriate pure projector based on event type.
pub(crate) fn dispatch_pure_projector(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    match parsed {
        ParsedEvent::Message(msg) => project_message_pure(recorded_by, event_id_b64, msg, ctx),
        ParsedEvent::Reaction(rxn) => project_reaction_pure(recorded_by, event_id_b64, rxn, ctx),
        ParsedEvent::SignedMemo(memo) => project_signed_memo_pure(recorded_by, event_id_b64, memo),
        ParsedEvent::SecretKey(sk) => project_secret_key_pure(recorded_by, event_id_b64, sk),
        ParsedEvent::MessageDeletion(del) => {
            project_message_deletion_pure(recorded_by, event_id_b64, del, ctx)
        }
        ParsedEvent::MessageAttachment(att) => {
            project_message_attachment_pure(recorded_by, event_id_b64, att)
        }
        ParsedEvent::FileSlice(fs) => project_file_slice_pure(recorded_by, event_id_b64, fs, ctx),
        ParsedEvent::BenchDep(_) => {
            // No projection table — valid_events tracks completion
            ProjectorResult::valid(vec![])
        }
        // Identity events
        ParsedEvent::Workspace(_)
        | ParsedEvent::InviteAccepted(_)
        | ParsedEvent::UserInviteBoot(_)
        | ParsedEvent::UserInviteOngoing(_)
        | ParsedEvent::DeviceInviteFirst(_)
        | ParsedEvent::DeviceInviteOngoing(_)
        | ParsedEvent::UserBoot(_)
        | ParsedEvent::UserOngoing(_)
        | ParsedEvent::PeerSharedFirst(_)
        | ParsedEvent::PeerSharedOngoing(_)
        | ParsedEvent::AdminBoot(_)
        | ParsedEvent::AdminOngoing(_)
        | ParsedEvent::UserRemoved(_)
        | ParsedEvent::PeerRemoved(_)
        | ParsedEvent::SecretShared(_)
        | ParsedEvent::TransportKey(_) => super::super::identity::apply_identity_projection_pure(
            recorded_by,
            event_id_b64,
            parsed,
            ctx,
        ),
        // Encrypted is handled above before dispatch
        ParsedEvent::Encrypted(_) => ProjectorResult::reject(
            "encrypted events should not reach dispatch_pure_projector".to_string(),
        ),
    }
}
