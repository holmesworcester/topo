use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use topo::db::{friendly_db_error, open_connection, schema::create_tables, sync_log};
use topo::rpc::client::{rpc_call, RpcClientError};
use topo::rpc::protocol::RpcMethod;
use topo::service;

use crate::cli::{
    EventAction, IrohLogAction, SubAction, SyncLogAction, TenantAction, TopoLogAction,
};
use crate::format::{
    group_runs_by_peer, print_iroh_log_config, print_sync_log_config, print_sync_trace_run,
    print_sync_tree_groups, print_topo_log_config, short_id,
};

// ---------------------------------------------------------------------------
// RPC helpers: auto-start daemon for target DB/socket, then call.
// ---------------------------------------------------------------------------

/// Validate that a JSON value looks like an RpcRequest envelope before sending.
pub(crate) fn validate_request_envelope(v: &serde_json::Value) {
    if v.get("version").is_none() {
        eprintln!("error: request JSON must have a \"version\" field");
        eprintln!(
            "  Hint: did you mean --method-json? (auto-wraps in {{\"version\":1,\"method\":...}})"
        );
        eprintln!("  Full request format: {{\"version\":1,\"method\":{{\"type\":\"Status\"}}}}");
        std::process::exit(1);
    }
    if !v["version"].is_number() {
        eprintln!("error: \"version\" must be a number, got: {}", v["version"]);
        std::process::exit(1);
    }
    if v.get("method").is_none() || v["method"].is_null() {
        eprintln!("error: request JSON must have a \"method\" field");
        eprintln!("  Full request format: {{\"version\":1,\"method\":{{\"type\":\"Status\"}}}}");
        std::process::exit(1);
    }
    // Try to deserialize the method portion for better errors.
    if let Err(e) = serde_json::from_value::<RpcMethod>(v["method"].clone()) {
        eprintln!("error: invalid method in request: {}", e);
        if let Some(type_name) = v["method"].get("type").and_then(|t| t.as_str()) {
            eprintln!(
                "  Hint: run `topo rpc describe {}` to see required parameters",
                type_name
            );
        }
        std::process::exit(1);
    }
}

pub(crate) fn target_socket_path(db: &str, socket: Option<&str>) -> PathBuf {
    socket
        .map(PathBuf::from)
        .unwrap_or_else(|| service::socket_path_for_db(db))
}

pub(crate) fn rpc_require_daemon(
    db: &str,
    socket: Option<&str>,
    method: RpcMethod,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let sock = target_socket_path(db, socket);

    match rpc_call(&sock, method) {
        Ok(resp) => {
            if !resp.ok {
                if let Some(err) = resp.error {
                    return Err(err.into());
                }
            }
            Ok(resp.data.unwrap_or(serde_json::Value::Null))
        }
        Err(RpcClientError::DaemonNotRunning(_)) => Err(format!(
            "daemon is not running for {} — start it with: topo --db {} start",
            db, db
        )
        .into()),
        Err(e) => Err(e.to_string().into()),
    }
}

pub(crate) fn resolve_send_file_path(
    file: Option<String>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut candidate = file
        .map(|path| path.trim().to_string())
        .filter(|p| !p.is_empty());

    // Optional convenience: when --file is omitted, accept a path from piped stdin.
    if candidate.is_none() && !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim();
        if !trimmed.is_empty() {
            candidate = Some(trimmed.to_string());
        }
    }

    match candidate {
        Some(path) => {
            let input = Path::new(&path);
            let abs = if input.is_absolute() {
                input.to_path_buf()
            } else {
                std::env::current_dir()?.join(input)
            };
            if !abs.exists() {
                return Err(format!("file does not exist: {}", abs.display()).into());
            }
            if !abs.is_file() {
                return Err(format!("path is not a file: {}", abs.display()).into());
            }
            Ok(abs.to_string_lossy().to_string())
        }
        None => {
            let tmp = std::env::temp_dir().join("topo-placeholder.txt");
            std::fs::write(&tmp, "placeholder file\n")
                .map_err(|e| format!("failed to create placeholder: {}", e))?;
            Ok(tmp.to_string_lossy().to_string())
        }
    }
}

pub(crate) fn resolve_target_selector(
    positional: Option<String>,
    deprecated_flag: Option<String>,
    command_name: &str,
    default_when_missing: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match (positional, deprecated_flag) {
        (Some(_), Some(_)) => Err(format!(
            "conflicting target selectors for `{}`: pass either positional target or deprecated --target, not both",
            command_name
        )
        .into()),
        (Some(target), None) => Ok(target),
        (None, Some(target)) => {
            eprintln!(
                "warning: `--target` is deprecated for `{}`; pass target positionally instead",
                command_name
            );
            Ok(target)
        }
        (None, None) => match default_when_missing {
            Some(default_target) => Ok(default_target.to_string()),
            None => Err(format!(
                "missing target for `{}`: pass it positionally (for example `{}`)",
                command_name,
                match command_name {
                    "react" => "topo react thumbsup 1",
                    "delete-message" => "topo delete-message 1",
                    "save-file" => "topo save-file 1 --out /tmp/file.bin",
                    _ => "topo <command> <target>",
                }
            )
            .into()),
        },
    }
}

#[derive(Debug, Clone)]
struct SubscriptionRef {
    subscription_id: String,
    name: String,
}

fn list_subscription_refs(
    db: &str,
    socket: Option<&str>,
) -> Result<Vec<SubscriptionRef>, Box<dyn std::error::Error + Send + Sync>> {
    let data = rpc_require_daemon(db, socket, RpcMethod::SubList)?;
    let items = data
        .as_array()
        .ok_or_else(|| "unexpected sub-list response shape".to_string())?;
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let sub_id = item["subscription_id"].as_str().unwrap_or("").to_string();
        if sub_id.is_empty() {
            continue;
        }
        let name = item["name"].as_str().unwrap_or("").to_string();
        refs.push(SubscriptionRef {
            subscription_id: sub_id,
            name,
        });
    }
    Ok(refs)
}

pub(crate) fn resolve_subscription_selector(
    db: &str,
    socket: Option<&str>,
    positional: Option<String>,
    deprecated_flag: Option<String>,
    command_name: &str,
    default_if_single: bool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let selector = match (positional, deprecated_flag) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "conflicting selectors for `{}`: pass either positional selector or deprecated --sub, not both",
                command_name
            )
            .into())
        }
        (Some(s), None) => Some(s),
        (None, Some(s)) => {
            eprintln!(
                "warning: `--sub` is deprecated for `{}`; pass selector positionally instead",
                command_name
            );
            Some(s)
        }
        (None, None) => None,
    }
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());

    let refs = list_subscription_refs(db, socket)?;
    if refs.is_empty() {
        return Err(
            "no subscriptions found — run `topo sub create --name ... --event-type message` first"
                .into(),
        );
    }

    let Some(selector) = selector else {
        if default_if_single && refs.len() == 1 {
            return Ok(refs[0].subscription_id.clone());
        }
        return Err(format!(
            "missing subscription selector for `{}`; pass id/name/#N (run `topo sub list`)",
            command_name
        )
        .into());
    };

    let selector_no_hash = selector.strip_prefix('#').unwrap_or(&selector);
    if let Ok(index) = selector_no_hash.parse::<usize>() {
        if index == 0 || index > refs.len() {
            return Err(format!(
                "invalid subscription index {}; available: 1-{}",
                index,
                refs.len()
            )
            .into());
        }
        return Ok(refs[index - 1].subscription_id.clone());
    }

    if let Some(found) = refs.iter().find(|r| r.subscription_id == selector) {
        return Ok(found.subscription_id.clone());
    }

    let matches: Vec<&SubscriptionRef> = refs.iter().filter(|r| r.name == selector).collect();
    match matches.len() {
        1 => Ok(matches[0].subscription_id.clone()),
        0 => Err(format!(
            "subscription selector `{}` not found; run `topo sub list` for available ids/names",
            selector
        )
        .into()),
        _ => Err(format!(
            "subscription name `{}` is ambiguous; use subscription id instead",
            selector
        )
        .into()),
    }
}

pub(crate) fn run_sub_action(
    db: &str,
    socket: Option<&str>,
    action: SubAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match action {
        SubAction::Create {
            name,
            event_type,
            delivery,
            since_ms,
            since_event_id,
            spec,
        } => {
            let spec_json = if let Some(raw) = spec {
                raw
            } else {
                let since = if since_ms.is_some() || since_event_id.is_some() {
                    Some(serde_json::json!({
                        "created_at_ms": since_ms.unwrap_or(0),
                        "event_id": since_event_id.unwrap_or_default(),
                    }))
                } else {
                    None
                };
                let spec_obj = serde_json::json!({
                    "event_type": event_type,
                    "since": since,
                    "filters": [],
                });
                serde_json::to_string(&spec_obj).unwrap()
            };
            let data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubCreate {
                    name,
                    event_type,
                    delivery_mode: delivery,
                    spec_json,
                },
            )?;
            let sub_id = data["subscription_id"].as_str().unwrap_or("?");
            let sub_name = data["name"].as_str().unwrap_or("?");
            println!("Created subscription \"{}\" (id: {})", sub_name, sub_id);
            Ok(())
        }
        SubAction::List => {
            let data = rpc_require_daemon(db, socket, RpcMethod::SubList)?;
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("No subscriptions.");
                } else {
                    println!("SUBSCRIPTIONS:");
                    for (idx, item) in items.iter().enumerate() {
                        let enabled = if item["enabled"].as_bool().unwrap_or(false) {
                            "on"
                        } else {
                            "off"
                        };
                        let name = item["name"].as_str().unwrap_or("?");
                        let sub_id = item["subscription_id"].as_str().unwrap_or("?");
                        let et = item["event_type"].as_str().unwrap_or("?");
                        let dm = item["delivery_mode"].as_str().unwrap_or("?");
                        println!(
                            "  {}. [{}] \"{}\" type={} delivery={} id={}",
                            idx + 1,
                            enabled,
                            name,
                            et,
                            dm,
                            sub_id
                        );
                    }
                }
            }
            Ok(())
        }
        SubAction::Poll {
            sub,
            sub_flag,
            after_seq,
            limit,
            json,
        } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub poll", true)?;
            let data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubPoll {
                    subscription_id: sub_id,
                    after_seq,
                    limit,
                },
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("(no new items)");
                } else {
                    for item in items {
                        let seq = item["seq"].as_i64().unwrap_or(0);
                        let etype = item["event_type"].as_str().unwrap_or("?");
                        let eid = item["event_id"].as_str().unwrap_or("?");
                        let payload = &item["payload"];
                        if let Some(content) = payload["content"].as_str() {
                            println!(
                                "  seq={} {} event={} content={:?}",
                                seq,
                                etype,
                                &eid[..eid.len().min(12)],
                                content
                            );
                        } else {
                            println!(
                                "  seq={} {} event={}",
                                seq,
                                etype,
                                &eid[..eid.len().min(12)]
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        SubAction::State {
            sub,
            sub_flag,
            json,
        } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub state", true)?;
            let data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubState {
                    subscription_id: sub_id,
                },
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else {
                let pending = data["pending_count"].as_i64().unwrap_or(0);
                let dirty = data["dirty"].as_bool().unwrap_or(false);
                let next_seq = data["next_seq"].as_i64().unwrap_or(0);
                let latest = data["latest_event_id"].as_str().unwrap_or("");
                println!(
                    "pending={} dirty={} next_seq={} latest_event={}",
                    pending,
                    dirty,
                    next_seq,
                    if latest.is_empty() {
                        "(none)"
                    } else {
                        &latest[..latest.len().min(12)]
                    },
                );
            }
            Ok(())
        }
        SubAction::Ack {
            sub,
            sub_flag,
            through_seq,
        } => {
            let sub_id = resolve_subscription_selector(db, socket, sub, sub_flag, "sub ack", true)?;
            let _data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubAck {
                    subscription_id: sub_id,
                    through_seq,
                },
            )?;
            println!("Acked through seq {}", through_seq);
            Ok(())
        }
        SubAction::Disable { sub, sub_flag } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub disable", true)?;
            let _data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubDisable {
                    subscription_id: sub_id,
                },
            )?;
            println!("Subscription disabled.");
            Ok(())
        }
        SubAction::Enable { sub, sub_flag } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub enable", true)?;
            let _data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubEnable {
                    subscription_id: sub_id,
                },
            )?;
            println!("Subscription enabled.");
            Ok(())
        }
        SubAction::Watch {
            sub,
            sub_flag,
            interval_ms,
            json,
            ack,
        } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub watch", true)?;

            // Reject has_changed subscriptions: they produce no feed rows,
            // so watch would never output anything.
            let list_data = rpc_require_daemon(db, socket, RpcMethod::SubList)?;
            if let Some(items) = list_data.as_array() {
                for item in items {
                    if item["subscription_id"].as_str() == Some(&sub_id) {
                        if item["delivery_mode"].as_str() == Some("has_changed") {
                            return Err(format!(
                                "subscription uses has_changed delivery mode which produces no feed items; \
                                 use `topo sub state` to check dirty/pending instead",
                            ).into());
                        }
                    }
                }
            }

            eprintln!(
                "Watching subscription {} (poll every {}ms, Ctrl-C to stop)",
                &sub_id[..sub_id.len().min(12)],
                interval_ms
            );
            // Start from seq 0: drain any pending backlog first, then follow
            // new items. This avoids silent data loss when --ack is used.
            let mut cursor: i64 = 0;
            let mut consecutive_not_found = 0u32;
            loop {
                match rpc_require_daemon(
                    db,
                    socket,
                    RpcMethod::SubPoll {
                        subscription_id: sub_id.clone(),
                        after_seq: cursor,
                        limit: 100,
                    },
                ) {
                    Ok(data) => {
                        consecutive_not_found = 0;
                        let mut page_full = false;
                        if let Some(items) = data.as_array() {
                            page_full = items.len() >= 100;
                            let mut max_seq = cursor;
                            for item in items {
                                let seq = item["seq"].as_i64().unwrap_or(0);
                                if seq > max_seq {
                                    max_seq = seq;
                                }
                                if json {
                                    println!("{}", serde_json::to_string(item).unwrap_or_default());
                                } else {
                                    let etype = item["event_type"].as_str().unwrap_or("?");
                                    let eid = item["event_id"].as_str().unwrap_or("?");
                                    let eid_short = &eid[..eid.len().min(12)];
                                    let ts = item["created_at_ms"].as_u64().unwrap_or(0);
                                    let payload = &item["payload"];
                                    if let Some(content) = payload["content"].as_str() {
                                        let author = payload["author_id"].as_str().unwrap_or("?");
                                        let author_short = &author[..author.len().min(8)];
                                        // Escape control chars so each event is one safe terminal line
                                        let escaped: String = content
                                            .chars()
                                            .map(|c| match c {
                                                '\\' => "\\\\".to_string(),
                                                '\n' => "\\n".to_string(),
                                                '\r' => "\\r".to_string(),
                                                '\t' => "\\t".to_string(),
                                                c if c.is_control() => {
                                                    format!("\\x{:02x}", c as u32)
                                                }
                                                c => c.to_string(),
                                            })
                                            .collect();
                                        println!(
                                            "[seq={}] {} event={} ts={} author={} | {}",
                                            seq, etype, eid_short, ts, author_short, escaped,
                                        );
                                    } else {
                                        println!(
                                            "[seq={}] {} event={} ts={}",
                                            seq, etype, eid_short, ts,
                                        );
                                    }
                                }
                            }
                            if max_seq > cursor {
                                if ack {
                                    match rpc_require_daemon(
                                        db,
                                        socket,
                                        RpcMethod::SubAck {
                                            subscription_id: sub_id.clone(),
                                            through_seq: max_seq,
                                        },
                                    ) {
                                        Ok(_) => {
                                            cursor = max_seq;
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "ack error (items will be re-delivered): {}",
                                                e
                                            );
                                        }
                                    }
                                } else {
                                    cursor = max_seq;
                                }
                            }
                        }
                        // If page was full, immediately re-poll to drain backlog
                        if page_full {
                            continue;
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("not found") {
                            consecutive_not_found += 1;
                            if consecutive_not_found >= 3 {
                                return Err(format!(
                                    "subscription {} no longer accessible — \
                                     the active tenant may have changed (use `topo tenant use` to switch back)",
                                    &sub_id[..sub_id.len().min(12)],
                                ).into());
                            }
                        } else if msg.contains("daemon is not running")
                            || msg.contains("connection refused")
                        {
                            return Err(format!("daemon stopped — watch exiting ({})", msg,).into());
                        } else {
                            consecutive_not_found = 0;
                        }
                        eprintln!("poll error: {}", msg);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            }
        }
    }
}

pub(crate) fn run_tenant_action(
    db: &str,
    socket: Option<&str>,
    action: TenantAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match action {
        TenantAction::List => {
            let data = rpc_require_daemon(db, socket, RpcMethod::Tenants)?;
            println!("TENANTS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for item in items {
                        let marker = if item["active"].as_bool().unwrap_or(false) {
                            "*"
                        } else {
                            " "
                        };
                        let username = item["username"].as_str().unwrap_or("");
                        let ws_id = item["workspace_id"].as_str().unwrap_or("");
                        let ws_name = item["workspace_name"].as_str().unwrap_or("");
                        let idx = item["index"].as_u64().unwrap_or(0);
                        let workspace_display = if ws_name.is_empty() {
                            short_id(ws_id).to_string()
                        } else {
                            ws_name.to_string()
                        };
                        let user_display = if username.is_empty() {
                            "(no username)".to_string()
                        } else {
                            username.to_string()
                        };
                        println!(
                            "  {}. {} {}@{}",
                            idx, marker, user_display, workspace_display
                        );
                    }
                }
            }
            Ok(())
        }
        TenantAction::Use { index } => {
            let data = rpc_require_daemon(db, socket, RpcMethod::UseTenant { index })?;
            let peer_id = data["peer_id"].as_str().unwrap_or("");
            let ws_id = data["workspace_id"].as_str().unwrap_or("");
            let ws_name = data["workspace_name"].as_str().unwrap_or("");
            let workspace_display = if ws_name.is_empty() {
                short_id(ws_id).to_string()
            } else {
                ws_name.to_string()
            };
            println!(
                "Switched to tenant {} (workspace: {})",
                short_id(peer_id),
                workspace_display
            );
            Ok(())
        }
        TenantAction::Active => {
            let data = rpc_require_daemon(db, socket, RpcMethod::ActiveTenant)?;
            match data["peer_id"].as_str() {
                Some(peer_id) => println!("{}", peer_id),
                None => println!("(no active tenant)"),
            }
            Ok(())
        }
    }
}

pub(crate) fn run_event_action(
    db: &str,
    socket: Option<&str>,
    action: EventAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match action {
        EventAction::Tree => {
            let data = rpc_require_daemon(db, socket, RpcMethod::EventList)?;
            let resp: service::EventListResponse = serde_json::from_value(data)?;
            topo::display::print_event_tree(&resp.events);
            Ok(())
        }
        EventAction::List {
            event_type,
            ids_only,
            fingerprint,
        } => {
            let data = rpc_require_daemon(db, socket, RpcMethod::EventList)?;
            let mut resp: service::EventListResponse = serde_json::from_value(data)?;
            if let Some(event_type) = event_type {
                resp.events.retain(|e| {
                    e.event_type == event_type
                        || e.decrypted_inner
                            .as_ref()
                            .map(|inner| inner.inner_type == event_type)
                            .unwrap_or(false)
                });
            }
            if fingerprint || ids_only {
                let mut ids: Vec<String> = resp.events.iter().map(|e| e.id.clone()).collect();
                ids.sort();
                if fingerprint {
                    let mut hasher = blake3::Hasher::new();
                    for id in &ids {
                        hasher.update(id.as_bytes());
                        hasher.update(b"\n");
                    }
                    let result: [u8; 32] = *hasher.finalize().as_bytes();
                    println!("EVENT IDS ({}):", ids.len());
                    println!("  fingerprint: {}", hex::encode(result));
                } else {
                    println!("EVENT IDS ({}):", ids.len());
                    for id in &ids {
                        println!("  {}", id);
                    }
                }
            } else {
                topo::display::print_event_list(&resp.events);
            }
            Ok(())
        }
        EventAction::Display { mode } => {
            let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
            topo::db::event_display::ensure_schema(&conn)?;
            match mode {
                None => {
                    let current = topo::db::event_display::load_mode(&conn)?;
                    println!("{}", current.as_str());
                }
                Some(m) => match topo::db::event_display::EventDisplayMode::from_str(&m) {
                    Some(mode) => {
                        topo::db::event_display::save_mode(&conn, mode)?;
                        println!("Event display mode set to: {}", mode.as_str());
                    }
                    None => {
                        return Err(
                            format!("Invalid display mode '{}'. Use: tree, list, off", m).into(),
                        );
                    }
                },
            }
            Ok(())
        }
        EventAction::Blocked { json } => {
            let data = rpc_require_daemon(db, socket, RpcMethod::EventBlocked)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else if let Some(items) = data.as_array() {
                println!("BLOCKED EVENTS ({}):", items.len());
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    // Group by event_id
                    let mut current_eid = String::new();
                    let mut idx = 0;
                    for item in items {
                        let eid = item["event_id"].as_str().unwrap_or("");
                        if eid != current_eid {
                            idx += 1;
                            current_eid = eid.to_string();
                            println!("  {}. {}", idx, &eid[..eid.len().min(12)]);
                        }
                        println!(
                            "       {} {}",
                            item["dep"].as_str().unwrap_or(""),
                            &item["blocker_event_id"].as_str().unwrap_or("")[..item
                                ["blocker_event_id"]
                                .as_str()
                                .unwrap_or("")
                                .len()
                                .min(12)]
                        );
                    }
                }
            }
            Ok(())
        }
        EventAction::Timeline { event_id, json } => {
            let data = rpc_require_daemon(db, socket, RpcMethod::EventTimeline { event_id })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else {
                let eid = data["event_id"].as_str().unwrap_or("?");
                println!("TIMELINE ({}):", &eid[..eid.len().min(12)]);
                if let Some(v) = data["first_received_at_ms"].as_i64() {
                    println!("  First received:  {} ms", v);
                }
                if let Some(v) = data["first_stored_at_ms"].as_i64() {
                    println!("  First stored:    {} ms", v);
                }
                if let Some(v) = data["blocked_at_ms"].as_i64() {
                    println!("  Blocked at:      {} ms", v);
                }
                if let Some(v) = data["unblocked_at_ms"].as_i64() {
                    println!("  Unblocked at:    {} ms", v);
                }
                if let Some(v) = data["projected_at_ms"].as_i64() {
                    println!("  Projected at:    {} ms", v);
                }
            }
            Ok(())
        }
        EventAction::Show { prefix } => {
            let data = rpc_require_daemon(db, socket, RpcMethod::EventShow { prefix })?;
            let resp: service::EventListResponse = serde_json::from_value(data)?;
            if resp.events.is_empty() {
                println!("No events matching that prefix.");
            } else {
                if resp.events.len() > 1 {
                    println!("({} matches)\n", resp.events.len());
                }
                topo::display::print_event_list(&resp.events);
            }
            Ok(())
        }
        EventAction::Deps { prefix, depth } => {
            let data = rpc_require_daemon(db, socket, RpcMethod::EventDeps { prefix, depth })?;
            let root_id = data["root_id"].as_str().unwrap_or("").to_string();
            let items: Vec<service::EventListItem> =
                serde_json::from_value(data["events"].clone()).unwrap_or_default();
            if items.is_empty() {
                println!("No events matching that prefix.");
            } else {
                topo::display::print_deps_tree(&root_id, &items, depth);
            }
            Ok(())
        }
    }
}

pub(crate) fn run_sync_log_action(
    db: &str,
    action: SyncLogAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match action {
        SyncLogAction::Show {
            limit,
            run,
            peer,
            all,
        } => {
            let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
            create_tables(&conn)?;
            let runs = sync_log::list_runs(&conn, limit, all, run, peer.as_deref())?;
            if runs.is_empty() {
                println!("No sync runs logged.");
            } else {
                if !all {
                    println!("Showing changed/error runs only (use --all for full history).");
                    println!();
                }
                for (idx, r) in runs.iter().enumerate() {
                    let events = sync_log::list_run_events(&conn, r.run_id)?;
                    print_sync_trace_run(r, &events);
                    if idx + 1 < runs.len() {
                        println!();
                    }
                }
            }
            Ok(())
        }
        SyncLogAction::Tree {
            limit,
            run,
            peer,
            all,
        } => {
            let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
            create_tables(&conn)?;
            let runs = sync_log::list_runs(&conn, limit, all, run, peer.as_deref())?;
            if runs.is_empty() {
                println!("No sync runs logged.");
            } else {
                if !all {
                    println!("Showing changed/error runs only (use --all for full history).");
                    println!();
                }
                let mut run_events = Vec::with_capacity(runs.len());
                for r in runs {
                    let events = sync_log::list_run_events(&conn, r.run_id)?;
                    run_events.push((r, events));
                }
                let groups = group_runs_by_peer(run_events);
                print_sync_tree_groups(&groups);
            }
            Ok(())
        }
        SyncLogAction::Enable {
            all_runs,
            capture_full_ids,
        } => {
            let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
            create_tables(&conn)?;
            let cfg = sync_log::update_config(
                &conn,
                sync_log::SyncLogConfigPatch {
                    enabled: Some(true),
                    changed_only: Some(!all_runs),
                    capture_full_ids: Some(capture_full_ids),
                    ..Default::default()
                },
            )?;
            print_sync_log_config(&cfg);
            Ok(())
        }
        SyncLogAction::Disable => {
            let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
            create_tables(&conn)?;
            let cfg = sync_log::update_config(
                &conn,
                sync_log::SyncLogConfigPatch {
                    enabled: Some(false),
                    ..Default::default()
                },
            )?;
            print_sync_log_config(&cfg);
            Ok(())
        }
        SyncLogAction::Config => {
            let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
            create_tables(&conn)?;
            let cfg = sync_log::load_config(&conn)?;
            print_sync_log_config(&cfg);
            Ok(())
        }
    }
}

pub(crate) fn run_iroh_log_action(
    db: &str,
    action: IrohLogAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
    create_tables(&conn)?;
    match action {
        IrohLogAction::Config => {
            let mode = topo::db::iroh_log::load_mode(&conn)?;
            print_iroh_log_config(mode);
            Ok(())
        }
        IrohLogAction::Show => {
            topo::db::iroh_log::save_mode(&conn, topo::db::iroh_log::IrohLogMode::Show)?;
            print_iroh_log_config(topo::db::iroh_log::IrohLogMode::Show);
            Ok(())
        }
        IrohLogAction::Suppress => {
            topo::db::iroh_log::save_mode(&conn, topo::db::iroh_log::IrohLogMode::Suppress)?;
            print_iroh_log_config(topo::db::iroh_log::IrohLogMode::Suppress);
            Ok(())
        }
    }
}

fn topo_log_level_for_action(action: TopoLogAction) -> Option<topo::db::topo_log::TopoLogLevel> {
    match action {
        TopoLogAction::Config => None,
        TopoLogAction::Error => Some(topo::db::topo_log::TopoLogLevel::Error),
        TopoLogAction::Warn => Some(topo::db::topo_log::TopoLogLevel::Warn),
        TopoLogAction::Info => Some(topo::db::topo_log::TopoLogLevel::Info),
        TopoLogAction::Debug => Some(topo::db::topo_log::TopoLogLevel::Debug),
        TopoLogAction::Trace => Some(topo::db::topo_log::TopoLogLevel::Trace),
    }
}

pub(crate) fn run_topo_log_action(
    db: &str,
    socket: Option<&str>,
    action: TopoLogAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sock = target_socket_path(db, socket);
    if let Some(level) = topo_log_level_for_action(action) {
        match rpc_call(
            &sock,
            RpcMethod::SetTopoLogLevel {
                level: level.as_str().to_string(),
            },
        ) {
            Ok(resp) if resp.ok => {
                let data = resp.data.unwrap_or(serde_json::Value::Null);
                let effective_now = data["effective_now"].as_bool().unwrap_or(true);
                print_topo_log_config(level, effective_now);
                Ok(())
            }
            Ok(resp) => Err(resp
                .error
                .unwrap_or_else(|| "set topo log level failed".to_string())
                .into()),
            Err(RpcClientError::DaemonNotRunning(_)) => {
                let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
                create_tables(&conn)?;
                topo::db::topo_log::save_level(&conn, level)?;
                print_topo_log_config(level, false);
                Ok(())
            }
            Err(e) => Err(e.to_string().into()),
        }
    } else {
        match rpc_call(&sock, RpcMethod::GetTopoLogConfig) {
            Ok(resp) if resp.ok => {
                let data = resp.data.unwrap_or(serde_json::Value::Null);
                let level = data["level"]
                    .as_str()
                    .and_then(topo::db::topo_log::TopoLogLevel::from_str)
                    .ok_or_else(|| "unexpected topo log config response shape".to_string())?;
                let effective_now = data["effective_now"].as_bool().unwrap_or(true);
                print_topo_log_config(level, effective_now);
                Ok(())
            }
            Ok(resp) => Err(resp
                .error
                .unwrap_or_else(|| "get topo log config failed".to_string())
                .into()),
            Err(RpcClientError::DaemonNotRunning(_)) => {
                let conn = open_connection(db).map_err(|e| friendly_db_error(db, e))?;
                create_tables(&conn)?;
                let level = topo::db::topo_log::load_level(&conn)?;
                print_topo_log_config(level, false);
                Ok(())
            }
            Err(e) => Err(e.to_string().into()),
        }
    }
}
