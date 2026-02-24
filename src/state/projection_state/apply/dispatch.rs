use super::super::result::{ContextSnapshot, ProjectorResult};
use crate::event_modules::{registry, ParsedEvent};

/// Dispatch to the appropriate pure projector via registry lookup.
///
/// Each event module owns its projector function, registered in EventTypeMeta.
/// No central match statement required — the registry drives dispatch.
pub(crate) fn dispatch_pure_projector(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let type_code = parsed.event_type_code();
    match registry().lookup(type_code) {
        Some(meta) => (meta.projector)(recorded_by, event_id_b64, parsed, ctx),
        None => ProjectorResult::reject(format!("unknown type code {}", type_code)),
    }
}
