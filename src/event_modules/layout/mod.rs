//! Declarative wire-format primitives shared by every event type. [`field_spec`] defines
//! `FieldSpec`/`FieldValue` for fixed-length-field layouts; [`common`] hosts cross-type
//! helpers including `encrypted_inner_wire_size`, which the Encrypted wrapper consults to
//! size inner payloads.

pub mod common;
pub mod field_spec;
