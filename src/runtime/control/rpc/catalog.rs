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
        params: params!["content", "string", true, None],
        example_json: r#"{"type":"Send","content":"hello"}"#,
    },
    MethodInfo {
        name: "SendFile",
        purpose: "Send a message with a file attachment",
        params: params![
            "content", "string", true, None;
            "file_path", "string", true, None
        ],
        example_json: r#"{"type":"SendFile","content":"see attached","file_path":"/tmp/notes.txt"}"#,
    },
    MethodInfo {
        name: "Generate",
        purpose: "Generate synthetic test messages",
        params: params!["count", "usize", true, None],
        example_json: r#"{"type":"Generate","count":10}"#,
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
        name: "TransportIdentity",
        purpose: "Print local transport SPKI fingerprint",
        params: PARAM_NONE,
        example_json: r#"{"type":"TransportIdentity"}"#,
    },
    MethodInfo {
        name: "React",
        purpose: "Create a reaction to a message",
        params: params![
            "target", "string", true, None;
            "emoji", "string", true, None
        ],
        example_json: r#"{"type":"React","target":"1","emoji":"thumbsup"}"#,
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
        name: "Keys",
        purpose: "List keys from projection",
        params: params!["summary", "bool", true, None],
        example_json: r#"{"type":"Keys","summary":true}"#,
    },
    MethodInfo {
        name: "Workspaces",
        purpose: "List workspaces from projection",
        params: PARAM_NONE,
        example_json: r#"{"type":"Workspaces"}"#,
    },
    MethodInfo {
        name: "IntroAttempts",
        purpose: "Show intro attempt records",
        params: params!["peer", "string?", false, None],
        example_json: r#"{"type":"IntroAttempts","peer":null}"#,
    },
    MethodInfo {
        name: "CreateInvite",
        purpose: "Create a user invite link for the active workspace",
        params: params![
            "public_addr", "string", true, None;
            "public_spki", "string?", false, None
        ],
        example_json: r#"{"type":"CreateInvite","public_addr":"127.0.0.1:4433"}"#,
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
            "public_addr", "string", true, None;
            "public_spki", "string?", false, None
        ],
        example_json: r#"{"type":"CreateDeviceLink","public_addr":"127.0.0.1:4433"}"#,
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
        name: "Ban",
        purpose: "Ban (remove) a user by number or hex event ID",
        params: params!["target", "string", true, None],
        example_json: r#"{"type":"Ban","target":"1"}"#,
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
        name: "CreateWorkspace",
        purpose: "Create a new workspace + identity chain",
        params: params![
            "workspace_name", "string", false, Some("\"workspace\"");
            "username", "string", false, Some("\"user\"");
            "device_name", "string", false, Some("\"device\"")
        ],
        example_json: r#"{"type":"CreateWorkspace","workspace_name":"myws","username":"alice","device_name":"laptop"}"#,
    },
    MethodInfo {
        name: "Peers",
        purpose: "List all known peers with connection status",
        params: PARAM_NONE,
        example_json: r#"{"type":"Peers"}"#,
    },
    MethodInfo {
        name: "Upnp",
        purpose: "Attempt UPnP port mapping for QUIC listen port",
        params: PARAM_NONE,
        example_json: r#"{"type":"Upnp"}"#,
    },
    MethodInfo {
        name: "View",
        purpose: "Combined view: sidebar + messages with inline reactions",
        params: params!["limit", "usize", false, Some("50")],
        example_json: r#"{"type":"View","limit":50}"#,
    },
    MethodInfo {
        name: "EventList",
        purpose: "List all events with parsed fields and decryption (workspace-scoped)",
        params: PARAM_NONE,
        example_json: r#"{"type":"EventList"}"#,
    },
    MethodInfo {
        name: "Intro",
        purpose: "Run intro: connect two peers via this node",
        params: params![
            "peer_a", "string", true, None;
            "peer_b", "string", true, None;
            "ttl_ms", "u64", false, Some("30000");
            "attempt_window_ms", "u32", false, Some("4000")
        ],
        example_json: r#"{"type":"Intro","peer_a":"<hex-spki>","peer_b":"<hex-spki>"}"#,
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
    CATALOG
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(name))
}
