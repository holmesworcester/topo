//! Abstract contracts for content-event command APIs.
//!
//! These proofs do not model rusqlite or event encoding. They prove the command
//! family planners we expect human and LLM authors to preserve when editing the
//! event-module command APIs.

use vstd::prelude::*;

verus! {

pub enum ContentCommandKind {
    MessageSend,
    ReactionCreate,
    MessageDelete,
}

pub struct ContentCommandInputs {
    pub kind: ContentCommandKind,
    pub has_content_key: bool,
    pub has_target_owner_binding: bool,
}

pub enum ContentCommandPlan {
    Reject,
    CreateEncrypted,
    CreateEncryptedWithOwner,
}

pub open spec fn decide_content_command_plan(i: ContentCommandInputs) -> ContentCommandPlan {
    match i.kind {
        ContentCommandKind::MessageSend | ContentCommandKind::MessageDelete => {
            if i.has_content_key {
                ContentCommandPlan::CreateEncrypted
            } else {
                ContentCommandPlan::Reject
            }
        }
        ContentCommandKind::ReactionCreate => {
            if i.has_content_key && i.has_target_owner_binding {
                ContentCommandPlan::CreateEncryptedWithOwner
            } else {
                ContentCommandPlan::Reject
            }
        }
    }
}

proof fn message_send_requires_content_key()
    ensures
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageSend,
            has_content_key: false,
            has_target_owner_binding: false,
        }) == ContentCommandPlan::Reject,
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageSend,
            has_content_key: true,
            has_target_owner_binding: false,
        }) == ContentCommandPlan::CreateEncrypted,
{
}

proof fn message_delete_requires_content_key()
    ensures
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageDelete,
            has_content_key: false,
            has_target_owner_binding: false,
        }) == ContentCommandPlan::Reject,
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageDelete,
            has_content_key: true,
            has_target_owner_binding: true,
        }) == ContentCommandPlan::CreateEncrypted,
{
}

proof fn reaction_requires_target_owner_binding_and_content_key()
    ensures
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::ReactionCreate,
            has_content_key: true,
            has_target_owner_binding: false,
        }) == ContentCommandPlan::Reject,
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::ReactionCreate,
            has_content_key: false,
            has_target_owner_binding: true,
        }) == ContentCommandPlan::Reject,
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::ReactionCreate,
            has_content_key: true,
            has_target_owner_binding: true,
        }) == ContentCommandPlan::CreateEncryptedWithOwner,
{
}

proof fn irrelevant_owner_binding_does_not_change_non_owner_commands(has_content_key: bool)
    ensures
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageSend,
            has_content_key,
            has_target_owner_binding: false,
        }) == decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageSend,
            has_content_key,
            has_target_owner_binding: true,
        }),
        decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageDelete,
            has_content_key,
            has_target_owner_binding: false,
        }) == decide_content_command_plan(ContentCommandInputs {
            kind: ContentCommandKind::MessageDelete,
            has_content_key,
            has_target_owner_binding: true,
        }),
{
}

} // verus!
