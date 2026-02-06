use std::collections::HashMap;

use super::{EventError, ParsedEvent};

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

pub struct EventTypeMeta {
    pub type_code: u8,
    pub type_name: &'static str,
    pub projection_table: &'static str,
    pub share_scope: ShareScope,
    pub dep_fields: &'static [&'static str],
    pub parse: fn(&[u8]) -> Result<ParsedEvent, EventError>,
    pub encode: fn(&ParsedEvent) -> Result<Vec<u8>, EventError>,
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
}
