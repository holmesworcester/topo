//! RPC method catalog: display metadata for `topo rpc methods` and `topo rpc describe`.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct MethodParam {
    pub name: &'static str,
    pub param_type: &'static str,
    pub required: bool,
    pub default: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodInfo {
    pub name: &'static str,
    pub purpose: &'static str,
    pub params: &'static [MethodParam],
    pub example_json: &'static str,
}

const PARAM_NONE: &[MethodParam] = &[];

macro_rules! params {
    ($($name:expr, $ty:expr, $req:expr, $default:expr);+ $(;)?) => {
        &[$(MethodParam { name: $name, param_type: $ty, required: $req, default: $default }),+]
    };
}

static CATALOG: &[MethodInfo] = &[
    MethodInfo {
        name: "Status",
        purpose: "Show database and runtime status",
        params: PARAM_NONE,
        example_json: r#"{"type":"Status"}"#,
    },
    MethodInfo {
        name: "Messages",
        purpose: "List projected messages",
        params: params!["limit", "usize", true, None],
        example_json: r#"{"type":"Messages","limit":50}"#,
    },
    MethodInfo {
        name: "Send",
        purpose: "Send a message in the active workspace",
        params: params![
            "content", "string", true, None;
            "client_op_id", "string?", false, None
        ],
        example_json: r#"{"type":"Send","content":"hello","client_op_id":"op-123"}"#,
    },
    MethodInfo {
        name: "SendFile",
        purpose: "Send a message with a file",
        params: params![
            "content", "string", true, None;
            "file_path", "string", true, None;
            "add_bad_slices", "usize", false, Some("0");
            "client_op_id", "string?", false, None
        ],
        example_json: r#"{"type":"SendFile","content":"see attached","file_path":"/tmp/notes.txt","add_bad_slices":8,"client_op_id":"op-456"}"#,
    },
    MethodInfo {
        name: "Files",
        purpose: "List files available to save",
        params: params!["limit", "usize", false, Some("50")],
        example_json: r#"{"type":"Files","limit":50}"#,
    },
    MethodInfo {
        name: "SaveFile",
        purpose: "Save a file to disk",
        params: params![
            "target", "string", true, None;
            "output_path", "string", true, None
        ],
        example_json: r#"{"type":"SaveFile","target":"1","output_path":"/tmp/output.bin"}"#,
    },
    MethodInfo {
        name: "GenerateFiles",
        purpose: "Generate synthetic file events",
        params: params![
            "count", "usize", true, None;
            "size_mib", "usize", true, None
        ],
        example_json: r#"{"type":"GenerateFiles","count":5,"size_mib":1}"#,
    },
    MethodInfo {
        name: "AssertNow",
        purpose: "Assert a predicate holds right now",
        params: params!["predicate", "string", true, None],
        example_json: r#"{"type":"AssertNow","predicate":"message_count >= 1"}"#,
    },
    MethodInfo {
        name: "AssertEventually",
        purpose: "Assert a predicate eventually holds (with timeout)",
        params: params![
            "predicate", "string", true, None;
            "timeout_ms", "u64", true, None;
            "interval_ms", "u64", true, None
        ],
        example_json: r#"{"type":"AssertEventually","predicate":"message_count == 10","timeout_ms":10000,"interval_ms":200}"#,
    },
    MethodInfo {
        name: "TransportKeys",
        purpose: "List all local transport keys (SPKI fingerprints)",
        params: PARAM_NONE,
        example_json: r#"{"type":"TransportKeys"}"#,
    },
    MethodInfo {
        name: "TransportAuth",
        purpose: "List all currently authorized remote transport fingerprints for the active tenant, with projected provenance",
        params: PARAM_NONE,
        example_json: r#"{"type":"TransportAuth"}"#,
    },
    MethodInfo {
        name: "React",
        purpose: "Create a reaction to a message",
        params: params![
            "target", "string", true, None;
            "emoji", "string", true, None;
            "client_op_id", "string?", false, None
        ],
        example_json: r#"{"type":"React","target":"1","emoji":"thumbsup","client_op_id":"op-789"}"#,
    },
    MethodInfo {
        name: "DeleteMessage",
        purpose: "Delete a message by target",
        params: params!["target", "string", true, None],
        example_json: r#"{"type":"DeleteMessage","target":"1"}"#,
    },
    MethodInfo {
        name: "Reactions",
        purpose: "List all reactions",
        params: PARAM_NONE,
        example_json: r#"{"type":"Reactions"}"#,
    },
    MethodInfo {
        name: "Users",
        purpose: "List users from projection",
        params: PARAM_NONE,
        example_json: r#"{"type":"Users"}"#,
    },
    MethodInfo {
        name: "GrantAdmin",
        purpose: "Admin-only: promote a user by selector",
        params: params!["target", "string", true, None],
        example_json: r#"{"type":"GrantAdmin","target":"2"}"#,
    },
    MethodInfo {
        name: "BanUser",
        purpose: "Admin-only: remove a user by selector",
        params: params!["target", "string", true, None],
        example_json: r#"{"type":"BanUser","target":"1"}"#,
    },
    MethodInfo {
        name: "Keys",
        purpose: "List keys from projection",
        params: params!["summary", "bool", true, None],
        example_json: r#"{"type":"Keys","summary":true}"#,
    },
    MethodInfo {
        name: "ContentKeys",
        purpose: "List local content/decryption keys",
        params: params!["summary", "bool", true, None],
        example_json: r#"{"type":"ContentKeys","summary":true}"#,
    },
    MethodInfo {
        name: "Workspaces",
        purpose: "List workspaces from projection",
        params: PARAM_NONE,
        example_json: r#"{"type":"Workspaces"}"#,
    },
    MethodInfo {
        name: "CreateInvite",
        purpose: "Create a user invite link for the active workspace",
        params: params![
            "public_addr", "string?", false, Some("omitted");
            "public_spki", "string?", false, None
        ],
        example_json: r#"{"type":"CreateInvite"}"#,
    },
    MethodInfo {
        name: "RotateKey",
        purpose: "Create a new content key and frontier-bound key_rotation for the active workspace",
        params: PARAM_NONE,
        example_json: r#"{"type":"RotateKey"}"#,
    },
    MethodInfo {
        name: "AcceptInvite",
        purpose: "Accept a user invite link",
        params: params![
            "invite", "string", true, None;
            "username", "string", true, None;
            "devicename", "string", true, None
        ],
        example_json: r#"{"type":"AcceptInvite","invite":"topo://invite/...","username":"user","devicename":"device"}"#,
    },
    MethodInfo {
        name: "CreateDeviceLink",
        purpose: "Create a device link invite for the active peer's user",
        params: params![
            "public_addr", "string?", false, Some("omitted");
            "public_spki", "string?", false, None
        ],
        example_json: r#"{"type":"CreateDeviceLink"}"#,
    },
    MethodInfo {
        name: "AcceptLink",
        purpose: "Accept a device link invite",
        params: params![
            "invite", "string", true, None;
            "devicename", "string", true, None
        ],
        example_json: r#"{"type":"AcceptLink","invite":"topo://link/...","devicename":"device"}"#,
    },
    MethodInfo {
        name: "Identity",
        purpose: "Show combined identity info for the active peer",
        params: PARAM_NONE,
        example_json: r#"{"type":"Identity"}"#,
    },
    MethodInfo {
        name: "Shutdown",
        purpose: "Stop the daemon",
        params: PARAM_NONE,
        example_json: r#"{"type":"Shutdown"}"#,
    },
    MethodInfo {
        name: "Tenants",
        purpose: "List local tenants in this DB",
        params: PARAM_NONE,
        example_json: r#"{"type":"Tenants"}"#,
    },
    MethodInfo {
        name: "UseTenant",
        purpose: "Switch active tenant by 1-based index",
        params: params!["index", "usize", true, None],
        example_json: r#"{"type":"UseTenant","index":1}"#,
    },
    MethodInfo {
        name: "ActiveTenant",
        purpose: "Return the currently active tenant",
        params: PARAM_NONE,
        example_json: r#"{"type":"ActiveTenant"}"#,
    },
    MethodInfo {
        name: "GetTopoLogConfig",
        purpose: "Return the current topo log config for the running daemon",
        params: PARAM_NONE,
        example_json: r#"{"type":"GetTopoLogConfig"}"#,
    },
    MethodInfo {
        name: "SetTopoLogLevel",
        purpose: "Update topo log level for the running daemon and persist it",
        params: params!["level", "string", true, None],
        example_json: r#"{"type":"SetTopoLogLevel","level":"debug"}"#,
    },
    MethodInfo {
        name: "CreateWorkspace",
        purpose: "Create a new workspace + identity chain (auto-creates invite)",
        params: params![
            "workspace_name", "string", false, Some("\"workspace\"");
            "username", "string", false, Some("\"user\"");
            "device_name", "string", false, Some("\"device\"");
            "message_count", "usize", false, Some("0");
            "network_age", "string", false, Some("\"3y\"")
        ],
        example_json: r#"{"type":"CreateWorkspace","workspace_name":"myws","username":"alice","device_name":"laptop","message_count":1000,"network_age":"3y"}"#,
    },
    MethodInfo {
        name: "Peers",
        purpose: "List all known peers with connection status",
        params: PARAM_NONE,
        example_json: r#"{"type":"Peers"}"#,
    },
    MethodInfo {
        name: "UnlinkDevice",
        purpose: "Admin-only: unlink a device by peer selector",
        params: params!["target", "string", true, None],
        example_json: r#"{"type":"UnlinkDevice","target":"2"}"#,
    },
    MethodInfo {
        name: "View",
        purpose: "Combined view: sidebar + messages with inline reactions",
        params: params!["limit", "usize", false, Some("50")],
        example_json: r#"{"type":"View","limit":50}"#,
    },
    MethodInfo {
        name: "SubCreate",
        purpose: "Create a local subscription",
        params: params![
            "name", "string", true, None;
            "event_type", "string", true, None;
            "delivery_mode", "string", true, None;
            "spec_json", "string", false, Some("\"\"")
        ],
        example_json: r#"{"type":"SubCreate","name":"msgs","event_type":"message","delivery_mode":"full","spec_json":""}"#,
    },
    MethodInfo {
        name: "SubList",
        purpose: "List all subscriptions for the active peer",
        params: PARAM_NONE,
        example_json: r#"{"type":"SubList"}"#,
    },
    MethodInfo {
        name: "SubDisable",
        purpose: "Disable a subscription",
        params: params!["subscription_id", "string", true, None],
        example_json: r#"{"type":"SubDisable","subscription_id":"sub-123"}"#,
    },
    MethodInfo {
        name: "SubEnable",
        purpose: "Enable a subscription",
        params: params!["subscription_id", "string", true, None],
        example_json: r#"{"type":"SubEnable","subscription_id":"sub-123"}"#,
    },
    MethodInfo {
        name: "SubPoll",
        purpose: "Poll feed items from a subscription",
        params: params![
            "subscription_id", "string", true, None;
            "after_seq", "i64", false, Some("0");
            "limit", "usize", false, Some("50")
        ],
        example_json: r#"{"type":"SubPoll","subscription_id":"sub-123","after_seq":0,"limit":50}"#,
    },
    MethodInfo {
        name: "SubAck",
        purpose: "Acknowledge feed items through a given seq",
        params: params![
            "subscription_id", "string", true, None;
            "through_seq", "i64", true, None
        ],
        example_json: r#"{"type":"SubAck","subscription_id":"sub-123","through_seq":42}"#,
    },
    MethodInfo {
        name: "SubState",
        purpose: "Get subscription state (pending count, dirty flag, cursors)",
        params: params!["subscription_id", "string", true, None],
        example_json: r#"{"type":"SubState","subscription_id":"sub-123"}"#,
    },
    MethodInfo {
        name: "EventList",
        purpose: "List all events with parsed fields and decryption (workspace-scoped)",
        params: PARAM_NONE,
        example_json: r#"{"type":"EventList"}"#,
    },
    MethodInfo {
        name: "EventListByIds",
        purpose: "List specific events by their IDs",
        params: params!["ids", "string[]", true, None],
        example_json: r#"{"type":"EventListByIds","ids":["evt1","evt2"]}"#,
    },
    MethodInfo {
        name: "EventShow",
        purpose: "Show events matching an ID prefix",
        params: params!["prefix", "string", true, None],
        example_json: r#"{"type":"EventShow","prefix":"abc123"}"#,
    },
    MethodInfo {
        name: "EventDeps",
        purpose: "Show reverse dependencies for an event prefix",
        params: params![
            "prefix", "string", true, None;
            "depth", "usize", true, None
        ],
        example_json: r#"{"type":"EventDeps","prefix":"abc123","depth":3}"#,
    },
    MethodInfo {
        name: "EventBlocked",
        purpose: "List blocked events with their missing dependencies",
        params: PARAM_NONE,
        example_json: r#"{"type":"EventBlocked"}"#,
    },
    MethodInfo {
        name: "EventTimeline",
        purpose: "Show delivery timeline for a specific event",
        params: params!["event_id", "string", true, None],
        example_json: r#"{"type":"EventTimeline","event_id":"<base64>"}"#,
    },
    MethodInfo {
        name: "SyncRoundPeer",
        purpose: "Trigger a negentropy round for a specific peer",
        params: params!["peer", "string", true, None],
        example_json: r#"{"type":"SyncRoundPeer","peer":"peer-id"}"#,
    },
    MethodInfo {
        name: "SyncRoundAll",
        purpose: "Trigger a negentropy round for all connected peers",
        params: PARAM_NONE,
        example_json: r#"{"type":"SyncRoundAll"}"#,
    },
    MethodInfo {
        name: "Stats",
        purpose: "Return all projection table counts for the active tenant",
        params: PARAM_NONE,
        example_json: r#"{"type":"Stats"}"#,
    },
    MethodInfo {
        name: "Replay",
        purpose: "Run a replay pass and return the projection fingerprint",
        params: params!["pass", "string", true, None],
        example_json: r#"{"type":"Replay","pass":"forward"}"#,
    },
    MethodInfo {
        name: "Connections",
        purpose: "List recent/active peer connections from endpoint observations",
        params: PARAM_NONE,
        example_json: r#"{"type":"Connections"}"#,
    },
    MethodInfo {
        name: "IngestObservability",
        purpose: "Return persisted ingest observability for the active peer",
        params: params!["event_ids", "string[]", false, Some("[]")],
        example_json: r#"{"type":"IngestObservability","event_ids":["<event-id>"]}"#,
    },
    #[cfg(feature = "discovery")]
    MethodInfo {
        name: "Discover",
        purpose: "Browse for peers via mDNS discovery",
        params: params!["timeout_ms", "u64", false, Some("5000")],
        example_json: r#"{"type":"Discover","timeout_ms":5000}"#,
    },
];

/// Return all methods in the catalog.
pub fn all_methods() -> &'static [MethodInfo] {
    CATALOG
}

/// Return method names only.
pub fn method_names() -> Vec<&'static str> {
    CATALOG.iter().map(|m| m.name).collect()
}

/// Look up a method by name (case-insensitive).
pub fn describe(name: &str) -> Option<&'static MethodInfo> {
    CATALOG.iter().find(|m| m.name.eq_ignore_ascii_case(name))
}
