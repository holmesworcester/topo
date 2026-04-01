use std::collections::HashMap;

use super::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult};
use crate::projection::queries::{ContextLoadResult, ProjectionFrameContext, ProjectionQueries};

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
    pub dep_field_type_codes: &'static [&'static [u8]],
    pub signer_required: bool,
    pub signature_byte_len: usize,
    pub encryptable: bool,
    pub parse: fn(&[u8]) -> Result<ParsedEvent, EventError>,
    pub encode: fn(&ParsedEvent) -> Result<Vec<u8>, EventError>,
    pub projector: fn(&str, &str, &ParsedEvent, &ContextSnapshot) -> ProjectorResult,
    pub context_loader: fn(
        &dyn ProjectionQueries,
        &ProjectionFrameContext,
        &str,
        &str,
        &ParsedEvent,
    ) -> Result<ContextLoadResult, Box<dyn std::error::Error>>,
}

pub fn load_empty_context(
    _queries: &dyn ProjectionQueries,
    _frame: &ProjectionFrameContext,
    _recorded_by: &str,
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
) -> Result<ContextLoadResult, Box<dyn std::error::Error>> {
    Ok(ContextLoadResult::ready(ContextSnapshot::default()))
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

macro_rules! event_type_meta {
    (
        type_code: $type_code:expr,
        type_name: $type_name:expr,
        projection_table: $projection_table:expr,
        share_scope: $share_scope:expr,
        dep_fields: $dep_fields:expr,
        dep_field_type_codes: $dep_field_type_codes:expr,
        signer_required: $signer_required:expr,
        signature_byte_len: $signature_byte_len:expr,
        encryptable: $encryptable:expr,
        parse: $parse:expr,
        encode: $encode:expr,
        projector: $projector:expr,
        context_loader: $context_loader:expr $(,)?
    ) => {
        $crate::event_modules::registry::EventTypeMeta {
            type_code: $type_code,
            type_name: $type_name,
            projection_table: $projection_table,
            share_scope: $share_scope,
            dep_fields: $dep_fields,
            dep_field_type_codes: $dep_field_type_codes,
            signer_required: $signer_required,
            signature_byte_len: $signature_byte_len,
            encryptable: $encryptable,
            parse: $parse,
            encode: $encode,
            projector: $projector,
            context_loader: $context_loader,
        }
    };
}

pub(crate) use event_type_meta;
