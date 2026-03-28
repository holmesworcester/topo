use std::collections::HashMap;

use super::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult};
use crate::projection::queries::ProjectionQueries;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareScope {
    Shared,
    Local,
}

impl ShareScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareScope::Shared => "shared",
            ShareScope::Local => "local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPrivacy {
    PlaintextOnly,
    Optional,
    RequireEncrypted,
}

pub struct EventTypeMeta {
    pub type_code: u8,
    pub type_name: &'static str,
    pub projection_table: &'static str,
    pub share_scope: ShareScope,
    pub dep_fields: &'static [&'static str],
    /// Parallel to dep_fields: valid type codes for each dep.
    /// Empty slice means any type is allowed (no type check).
    pub dep_field_type_codes: &'static [&'static [u8]],
    pub signer_required: bool,
    pub signature_byte_len: usize,
    /// Whether this event type is admissible as inner payload of an encrypted wrapper.
    /// Identity events, encrypted (nested), and bench_dep_perf_testing are not permitted.
    pub encryptable: bool,
    pub parse: fn(&[u8]) -> Result<ParsedEvent, EventError>,
    pub encode: fn(&ParsedEvent) -> Result<Vec<u8>, EventError>,
    /// Module-owned pure projector function. The pipeline dispatches to this
    /// via registry lookup — no central match statement required.
    pub projector: fn(&str, &str, &ParsedEvent, &ContextSnapshot) -> ProjectorResult,
    /// Module-owned projector context loader. Projector-specific context queries
    /// belong with the owning event module's projection surface, not in shared
    /// apply code.
    pub context_loader: fn(
        &dyn ProjectionQueries,
        &str,
        &str,
        &ParsedEvent,
    ) -> Result<ContextSnapshot, Box<dyn std::error::Error>>,
}

/// Default context loader for event types whose projectors do not require
/// additional DB-derived context.
pub fn load_empty_context(
    _queries: &dyn ProjectionQueries,
    _recorded_by: &str,
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    Ok(ContextSnapshot::default())
}

pub struct EventRegistry {
    by_code: HashMap<u8, &'static EventTypeMeta>,
}

impl EventRegistry {
    pub fn new(metas: &[&'static EventTypeMeta]) -> Self {
        let mut by_code = HashMap::new();
        for meta in metas {
            by_code.insert(meta.type_code, *meta);
        }
        Self { by_code }
    }

    pub fn lookup(&self, type_code: u8) -> Option<&'static EventTypeMeta> {
        self.by_code.get(&type_code).copied()
    }

    pub fn lookup_by_name(&self, type_name: &str) -> Option<&'static EventTypeMeta> {
        self.by_code
            .values()
            .copied()
            .find(|meta| meta.type_name == type_name)
    }
}

impl EventTypeMeta {
    pub fn transport_privacy(&self) -> TransportPrivacy {
        match self.type_code {
            super::EVENT_TYPE_MESSAGE
            | super::EVENT_TYPE_REACTION
            | super::EVENT_TYPE_MESSAGE_DELETION
            | super::EVENT_TYPE_FILE
            | super::EVENT_TYPE_FILE_SLICE => TransportPrivacy::RequireEncrypted,
            super::EVENT_TYPE_KEY_SECRET => TransportPrivacy::Optional,
            _ => TransportPrivacy::PlaintextOnly,
        }
    }
}
