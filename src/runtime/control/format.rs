use topo::db::{open_connection, sync_log};
use topo::runtime::control::logging::IROH_LOG_SUPPRESSION_DIRECTIVES;
use topo::service;

// ---------------------------------------------------------------------------
// Display helpers — delegated to display module
// ---------------------------------------------------------------------------

pub(crate) fn short_id(b64: &str) -> &str {
    topo::display::short_id(b64)
}

/// Show created events from a server response, respecting the display mode setting.
pub(crate) fn maybe_show_created_events(db: &str, data: &serde_json::Value) {
    use topo::db::event_display::{self, EventDisplayMode};

    let Some(events_json) = data.get("created_events") else {
        return;
    };
    let Ok(events): Result<Vec<service::EventListItem>, _> =
        serde_json::from_value(events_json.clone())
    else {
        return;
    };
    if events.is_empty() {
        return;
    }

    println!();

    // Load display mode from infra DB (direct read, no RPC).
    let mode = match open_connection(db) {
        Ok(conn) => {
            let _ = event_display::ensure_schema(&conn);
            event_display::load_mode(&conn).unwrap_or(EventDisplayMode::Tree)
        }
        Err(_) => EventDisplayMode::Tree,
    };

    match mode {
        EventDisplayMode::Tree => topo::display::print_event_tree(&events),
        EventDisplayMode::List => topo::display::print_event_list(&events),
        EventDisplayMode::Off => {}
    }
}

pub(crate) fn print_sync_log_config(cfg: &sync_log::SyncLogConfig) {
    println!(
        "sync-log enabled={} changed_only={} capture_full_ids={} max_runs={} max_age_days={}",
        cfg.enabled, cfg.changed_only, cfg.capture_full_ids, cfg.max_runs, cfg.max_age_days
    );
}

pub(crate) fn print_iroh_log_config(mode: topo::db::iroh_log::IrohLogMode) {
    println!("iroh-log mode={}", mode.as_str());
    println!("effective_on_next_start=true");
    println!(
        "suppression_targets={}",
        IROH_LOG_SUPPRESSION_DIRECTIVES.join(",")
    );
}

pub(crate) fn print_topo_log_config(level: topo::db::topo_log::TopoLogLevel, effective_now: bool) {
    println!("topo-log level={}", level.as_str());
    println!("effective_now={}", effective_now);
    println!("effective_on_next_start=true");
}

fn short_sync_id(raw: &str) -> String {
    let prefix = &raw[..raw.len().min(4)];
    if raw.len() > 4 {
        format!("{}...", prefix)
    } else {
        prefix.to_string()
    }
}

fn run_status(run: &sync_log::SyncRunRow) -> &'static str {
    if run.error.is_some() || run.outcome != "ok" {
        "error"
    } else if run.changed {
        "changed"
    } else {
        "match"
    }
}

fn event_id_prefix_from_detail_json(detail_json: Option<&str>) -> Option<String> {
    let raw = detail_json?;
    let v = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    let eid = v.get("event_id")?.as_str()?;
    Some(short_sync_id(eid))
}

fn summarize_sync_event_detail(frame_type: &str, detail_json: Option<&str>) -> String {
    let Some(raw) = detail_json else {
        return String::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return " detail=parse_error".to_string();
    };

    match frame_type {
        "NegOpen" | "NegMsg" => {
            let entries = v["entry_count"].as_u64().unwrap_or(0);
            let fp = v["fingerprint_count"].as_u64().unwrap_or(0);
            let idl = v["idlist_count"].as_u64().unwrap_or(0);
            let skip = v["skip_count"].as_u64().unwrap_or(0);
            if let Some(err) = v["parse_error"].as_str() {
                format!(
                    " detail=neg(entries={} fp={} idlists={} skip={} err={})",
                    entries, fp, idl, skip, err
                )
            } else {
                format!(
                    " detail=neg(entries={} fp={} idlists={} skip={})",
                    entries, fp, idl, skip
                )
            }
        }
        "RangePolicyReject" => {
            let rejected = v["rejected_window_kind"].as_u64().unwrap_or(0);
            let oldest_allowed = v["oldest_allowed_window_kind"].as_u64().unwrap_or(0);
            format!(
                " detail=range_policy(rejected_kind={} oldest_allowed_kind={})",
                rejected, oldest_allowed
            )
        }
        "Event" => {
            let eid = v["event_id"].as_str().unwrap_or("");
            let blob_len = v["blob_len"].as_u64().unwrap_or(0);
            if eid.is_empty() {
                format!(" detail=event(blob_len={})", blob_len)
            } else {
                format!(
                    " detail=event(id={} blob_len={})",
                    short_sync_id(eid),
                    blob_len
                )
            }
        }
        _ => String::new(),
    }
}

#[derive(Debug, Clone)]
struct NegEntryView {
    bound_ts: String,
    bound_id_prefix: String,
    mode: String,
    fingerprint_hex: Option<String>,
    id_count: Option<u64>,
    ids: Vec<String>,
    ids_truncated: bool,
}

#[derive(Debug, Clone)]
struct NegFrameView {
    protocol: Option<u64>,
    entry_count: u64,
    skip_count: u64,
    fingerprint_count: u64,
    idlist_count: u64,
    entries: Vec<NegEntryView>,
    parse_error: Option<String>,
}

fn parse_neg_frame_view(detail_json: Option<&str>) -> Option<NegFrameView> {
    let raw = detail_json?;
    let v = serde_json::from_str::<serde_json::Value>(raw).ok()?;

    let entries = v["entries"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|entry| {
                    let ids = entry["ids"]
                        .as_array()
                        .map(|ids_arr| {
                            ids_arr
                                .iter()
                                .filter_map(|x| x.as_str())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    NegEntryView {
                        bound_ts: entry["bound_ts"].as_str().unwrap_or("?").to_string(),
                        bound_id_prefix: entry["bound_id_prefix"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        mode: entry["mode"].as_str().unwrap_or("?").to_string(),
                        fingerprint_hex: entry["fingerprint_hex"].as_str().map(|s| s.to_string()),
                        id_count: entry["id_count"].as_u64(),
                        ids,
                        ids_truncated: entry["ids_truncated"].as_bool().unwrap_or(false),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(NegFrameView {
        protocol: v["protocol"].as_u64(),
        entry_count: v["entry_count"].as_u64().unwrap_or(0),
        skip_count: v["skip_count"].as_u64().unwrap_or(0),
        fingerprint_count: v["fingerprint_count"].as_u64().unwrap_or(0),
        idlist_count: v["idlist_count"].as_u64().unwrap_or(0),
        entries,
        parse_error: v["parse_error"].as_str().map(|s| s.to_string()),
    })
}

fn neg_entry_depth_hint(prefix_hex: &str) -> usize {
    let bytes = prefix_hex.len() / 2;
    if bytes <= 1 {
        0
    } else if bytes <= 3 {
        1
    } else if bytes <= 7 {
        2
    } else {
        3
    }
}

fn neg_entry_readable_line(round_no: usize, entry_idx: usize, entry: &NegEntryView) -> String {
    let bound_prefix = short_sync_id(&entry.bound_id_prefix);
    let bound = if bound_prefix.is_empty() {
        format!("({})", entry.bound_ts)
    } else {
        format!("({}, {})", entry.bound_ts, bound_prefix)
    };
    let range_label = format!("{}.{}", round_no, entry_idx + 1);
    match entry.mode.as_str() {
        "Skip" => format!("range={} MATCH bound={}", range_label, bound),
        "Fingerprint" => {
            let fp = entry
                .fingerprint_hex
                .as_deref()
                .map(short_sync_id)
                .unwrap_or_else(|| "?".to_string());
            format!(
                "range={} HASH bound={} fp={} (await compare)",
                range_label, bound, fp
            )
        }
        "IdList" => {
            let count = entry.id_count.unwrap_or(0);
            let ids = entry
                .ids
                .iter()
                .take(4)
                .map(|id| short_sync_id(id))
                .collect::<Vec<_>>()
                .join(",");
            if ids.is_empty() {
                format!(
                    "range={} MISMATCH -> IdList count={} truncated={}",
                    range_label, count, entry.ids_truncated
                )
            } else {
                let shown = entry.ids.len().min(4) as u64;
                let more_count = count.saturating_sub(shown);
                let more = if more_count > 0 {
                    format!(" (+{} more)", more_count)
                } else if entry.ids_truncated {
                    " ...".to_string()
                } else {
                    String::new()
                };
                format!(
                    "range={} MISMATCH -> IdList count={} ids=[{}]{} truncated={}",
                    range_label, count, ids, more, entry.ids_truncated
                )
            }
        }
        other => format!("range={} {} bound={}", range_label, other, bound),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RenderedFrameLine {
    pub seq_start: u64,
    pub seq_end: u64,
    pub dt_start_ms: i64,
    pub dt_end_ms: i64,
    pub lane: String,
    pub direction: String,
    pub frame_type: String,
    pub len_label: String,
    pub detail: String,
    pub detail_json: Option<String>,
}

impl RenderedFrameLine {
    pub fn seq_label(&self) -> String {
        if self.seq_start == self.seq_end {
            format!("{:04}", self.seq_start)
        } else {
            format!("{:04}-{:04}", self.seq_start, self.seq_end)
        }
    }

    pub fn dt_label(&self) -> String {
        if self.dt_start_ms == self.dt_end_ms {
            format!("+{}ms", self.dt_start_ms)
        } else {
            format!("+{}..{}ms", self.dt_start_ms, self.dt_end_ms)
        }
    }
}

pub(crate) fn render_frame_lines(
    run: &sync_log::SyncRunRow,
    events: &[sync_log::SyncRunEventRow],
) -> Vec<RenderedFrameLine> {
    const COLLAPSE_EVENT_BURST_MIN: usize = 3;
    const EVENT_SAMPLE_IDS: usize = 4;

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < events.len() {
        let ev = &events[i];
        if ev.frame_type == "Event" {
            let mut j = i + 1;
            while j < events.len() {
                let nxt = &events[j];
                if nxt.frame_type == "Event" && nxt.lane == ev.lane && nxt.direction == ev.direction
                {
                    j += 1;
                } else {
                    break;
                }
            }

            let burst = &events[i..j];
            if burst.len() >= COLLAPSE_EVENT_BURST_MIN {
                let first = &burst[0];
                let last = &burst[burst.len() - 1];
                let mut total_len: usize = 0;
                let mut min_len: usize = usize::MAX;
                let mut max_len: usize = 0;
                let mut ids: Vec<String> = Vec::new();
                for item in burst {
                    total_len = total_len.saturating_add(item.msg_len);
                    min_len = min_len.min(item.msg_len);
                    max_len = max_len.max(item.msg_len);
                    if ids.len() < EVENT_SAMPLE_IDS {
                        if let Some(id) =
                            event_id_prefix_from_detail_json(item.detail_json.as_deref())
                        {
                            ids.push(id);
                        }
                    }
                }
                if min_len == usize::MAX {
                    min_len = 0;
                }
                let detail = if ids.is_empty() {
                    format!(" detail=events(count={})", burst.len())
                } else {
                    let more_count = burst.len().saturating_sub(ids.len());
                    let more = if more_count > 0 {
                        format!(" (+{} more)", more_count)
                    } else {
                        String::new()
                    };
                    format!(
                        " detail=events(count={} ids=[{}]{})",
                        burst.len(),
                        ids.join(","),
                        more
                    )
                };
                out.push(RenderedFrameLine {
                    seq_start: first.seq,
                    seq_end: last.seq,
                    dt_start_ms: first.ts_ms.saturating_sub(run.started_at_ms),
                    dt_end_ms: last.ts_ms.saturating_sub(run.started_at_ms),
                    lane: first.lane.clone(),
                    direction: first.direction.clone(),
                    frame_type: "Event*".to_string(),
                    len_label: format!(
                        "total:{} range:{}-{} count:{}",
                        total_len,
                        min_len,
                        max_len,
                        burst.len()
                    ),
                    detail,
                    detail_json: None,
                });
                i = j;
                continue;
            }
        }

        out.push(RenderedFrameLine {
            seq_start: ev.seq,
            seq_end: ev.seq,
            dt_start_ms: ev.ts_ms.saturating_sub(run.started_at_ms),
            dt_end_ms: ev.ts_ms.saturating_sub(run.started_at_ms),
            lane: ev.lane.clone(),
            direction: ev.direction.clone(),
            frame_type: ev.frame_type.clone(),
            len_label: ev.msg_len.to_string(),
            detail: summarize_sync_event_detail(&ev.frame_type, ev.detail_json.as_deref()),
            detail_json: ev.detail_json.clone(),
        });
        i += 1;
    }

    out
}

pub(crate) fn print_sync_trace_run(
    run: &sync_log::SyncRunRow,
    events: &[sync_log::SyncRunEventRow],
) {
    let status = run_status(run);
    let dur_ms = run.ended_at_ms.saturating_sub(run.started_at_ms);
    let frame_lines = render_frame_lines(run, events);
    println!(
        "RUN {} [{}] session={} tenant={} peer={} dir={} role={} remote={} start={} end={} dur_ms={} sync_rounds={} sync_events_tx={} sync_events_rx={} bytes_tx={} bytes_rx={} raw_frames={} frame_lines={} outcome={}",
        run.run_id,
        status,
        run.session_id,
        short_sync_id(&run.tenant_id),
        short_sync_id(&run.peer_id),
        run.direction,
        run.role,
        run.remote_addr,
        format_absolute(run.started_at_ms),
        format_absolute(run.ended_at_ms),
        dur_ms,
        run.rounds,
        run.events_sent,
        run.events_received,
        run.bytes_sent,
        run.bytes_received,
        events.len(),
        frame_lines.len(),
        run.outcome,
    );
    if let Some(err) = &run.error {
        println!("  error: {}", err);
    }
    if events.is_empty() {
        println!("  (no frame events)");
        return;
    }
    for line in frame_lines {
        println!(
            "  [{}] {:>11} {:7} {:2} {:8} len={}{}",
            line.seq_label(),
            line.dt_label(),
            line.lane,
            line.direction,
            line.frame_type,
            line.len_label,
            line.detail
        );
    }
}

#[derive(Debug)]
pub(crate) struct PeerSyncTreeGroup {
    pub peer_id: String,
    pub runs: Vec<(sync_log::SyncRunRow, Vec<sync_log::SyncRunEventRow>)>,
}

pub(crate) fn group_runs_by_peer(
    runs: Vec<(sync_log::SyncRunRow, Vec<sync_log::SyncRunEventRow>)>,
) -> Vec<PeerSyncTreeGroup> {
    let mut groups: Vec<PeerSyncTreeGroup> = Vec::new();
    for (run, events) in runs {
        if let Some(group) = groups.iter_mut().find(|g| g.peer_id == run.peer_id) {
            group.runs.push((run, events));
        } else {
            groups.push(PeerSyncTreeGroup {
                peer_id: run.peer_id.clone(),
                runs: vec![(run, events)],
            });
        }
    }
    groups
}

pub(crate) fn print_sync_tree_groups(groups: &[PeerSyncTreeGroup]) {
    for (peer_idx, group) in groups.iter().enumerate() {
        let changed = group
            .runs
            .iter()
            .filter(|(run, _)| run_status(run) == "changed")
            .count();
        let errors = group
            .runs
            .iter()
            .filter(|(run, _)| run_status(run) == "error")
            .count();
        println!(
            "peer={} runs={} changed={} errors={}",
            short_sync_id(&group.peer_id),
            group.runs.len(),
            changed,
            errors
        );

        for (run_idx, (run, events)) in group.runs.iter().enumerate() {
            let run_branch = if run_idx + 1 == group.runs.len() {
                "\u{2514}\u{2500}"
            } else {
                "\u{251c}\u{2500}"
            };
            let run_pad = if run_idx + 1 == group.runs.len() {
                "  "
            } else {
                "\u{2502} "
            };
            let status = run_status(run);
            let dt = run.ended_at_ms.saturating_sub(run.started_at_ms);
            let frame_lines = render_frame_lines(run, events);
            let mut prev_neg_entry_count: Option<u64> = None;
            let mut neg_round_no: usize = 0;
            println!(
            "{} run={} status={} ended_at={} direction={} role={} sync_rounds={} sync_events_tx={} sync_events_rx={} dur_ms={} raw_frames={} frame_lines={} outcome={}",
                run_branch,
                run.run_id,
                status,
                format_compact_datetime(run.ended_at_ms),
                run.direction,
                run.role,
                run.rounds,
                run.events_sent,
                run.events_received,
                dt,
                events.len(),
                frame_lines.len(),
                run.outcome
            );
            if let Some(err) = &run.error {
                println!("{}  error: {}", run_pad, err);
            }

            if events.is_empty() {
                println!("{}  \u{2514}\u{2500} (no frame events)", run_pad);
                continue;
            }

            for (event_idx, line) in frame_lines.iter().enumerate() {
                let ev_branch = if event_idx + 1 == frame_lines.len() {
                    "\u{2514}\u{2500}"
                } else {
                    "\u{251c}\u{2500}"
                };
                println!(
                    "{}  {} {} seq={} {} {} {} len={}{}",
                    run_pad,
                    ev_branch,
                    line.dt_label(),
                    line.seq_label(),
                    line.lane,
                    line.direction,
                    line.frame_type,
                    line.len_label,
                    line.detail
                );

                if (line.frame_type == "NegOpen" || line.frame_type == "NegMsg")
                    && line.detail_json.is_some()
                {
                    neg_round_no += 1;
                    if let Some(neg) = parse_neg_frame_view(line.detail_json.as_deref()) {
                        let child_stem = if event_idx + 1 == frame_lines.len() {
                            "  "
                        } else {
                            "\u{2502} "
                        };
                        let drilldown = prev_neg_entry_count
                            .filter(|prev| neg.entry_count > *prev)
                            .map(|prev| format!(" drilldown={}->{}", prev, neg.entry_count))
                            .unwrap_or_default();
                        println!(
                            "{}  {}    reconcile round={} protocol={} ranges={} hash_match(skip)={} hash_probe(fp)={} idlists={}{}",
                            run_pad,
                            child_stem,
                            neg_round_no,
                            neg.protocol
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "?".to_string()),
                            neg.entry_count,
                            neg.skip_count,
                            neg.fingerprint_count,
                            neg.idlist_count,
                            drilldown
                        );
                        if let Some(err) = &neg.parse_error {
                            println!("{}  {}    parse_error={}", run_pad, child_stem, err);
                        }

                        const MAX_RANGE_LINES: usize = 10;
                        for (entry_idx, entry) in neg.entries.iter().enumerate() {
                            if entry_idx >= MAX_RANGE_LINES {
                                let rem = neg.entries.len() - MAX_RANGE_LINES;
                                println!("{}  {}    (+{} more ranges)", run_pad, child_stem, rem);
                                break;
                            }
                            let depth = neg_entry_depth_hint(&entry.bound_id_prefix);
                            let depth_pad = "  ".repeat(depth);
                            println!(
                                "{}  {}    {}{}",
                                run_pad,
                                child_stem,
                                depth_pad,
                                neg_entry_readable_line(neg_round_no, entry_idx, entry)
                            );
                        }
                        prev_neg_entry_count = Some(neg.entry_count);
                    }
                }
            }
        }

        if peer_idx + 1 < groups.len() {
            println!();
        }
    }
}

pub(crate) fn system_hostname() -> String {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == 0 {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).into_owned()
    } else {
        "device".to_string()
    }
}

pub(crate) fn format_timestamp(ms: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let age_ms = now - ms;

    if age_ms < 0 {
        return format_absolute(ms);
    }

    let secs = age_ms / 1000;
    if secs < 60 {
        return format!("{}s ago", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}m ago", mins);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}h ago", hours);
    }
    let days = hours / 24;
    if days < 7 {
        return format!("{}d ago", days);
    }

    format_absolute(ms)
}

pub(crate) fn format_absolute(ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms as u64);
    let secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    let (_year, month, day) = days_to_ymd(days_since_epoch as i64);
    let month_name = match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    };
    format!("{} {} {:02}:{:02}", month_name, day, hours, minutes)
}

pub(crate) fn format_compact_datetime(ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms as u64);
    let total_secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = total_secs / 86_400;
    let time_of_day = total_secs % 86_400;
    let hours = time_of_day / 3_600;
    let minutes = (time_of_day % 3_600) / 60;
    let seconds = time_of_day % 60;
    let millis = (ms.rem_euclid(1000)) as u32;

    let (year, month, day) = days_to_ymd(days_since_epoch as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hours, minutes, seconds, millis
    )
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Messages display (from JSON data)
// ---------------------------------------------------------------------------

pub(crate) fn show_messages_from_json(_db_path: &str, data: &serde_json::Value) {
    let messages = match data["messages"].as_array() {
        Some(msgs) => msgs,
        None => {
            println!("  (no messages)");
            return;
        }
    };

    if messages.is_empty() {
        println!("  (no messages)");
        return;
    }

    let total = data["total"].as_i64().unwrap_or(0) as usize;
    println!("MESSAGES ({} total):\n", total);

    let skipped = if total > messages.len() {
        total - messages.len()
    } else {
        0
    };
    if skipped > 0 {
        println!("  ({} older messages not shown)\n", skipped);
    }

    let mut last_author = String::new();
    for (i, msg) in messages.iter().enumerate() {
        let created_at = msg["created_at"].as_i64().unwrap_or(0);
        let ts = format_timestamp(created_at);
        let author_id = msg["author_id"].as_str().unwrap_or("");
        let author_name = msg["author_name"].as_str().unwrap_or("");
        let display_name = if author_name.is_empty() {
            short_id(author_id).to_string()
        } else {
            author_name.to_string()
        };
        let content = msg["content"].as_str().unwrap_or("");

        if author_id != last_author {
            if i > 0 {
                println!();
            }
            println!("  {} [{}]", display_name, ts);
            last_author = author_id.to_string();
        }
        println!("    {}. {}", skipped + i + 1, content);

        // Reactions: Slack-style grouped counts on one line
        if let Some(reactions) = msg["reactions"].as_array() {
            if !reactions.is_empty() {
                let mut counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for r in reactions {
                    let emoji = r["emoji"].as_str().unwrap_or("?").to_string();
                    *counts.entry(emoji).or_default() += 1;
                }
                let parts: Vec<String> = counts
                    .iter()
                    .map(|(name, count)| {
                        let glyph = emoji_shortcode_to_unicode(name);
                        if *count > 1 {
                            format!("{} ({})", glyph, count)
                        } else {
                            glyph.to_string()
                        }
                    })
                    .collect();
                println!("        {}", parts.join("  "));
            }
        }

        // Files: checkmark = complete, hourglass = syncing
        if let Some(files) = msg["files"].as_array() {
            for att in files {
                let filename = att["filename"].as_str().unwrap_or("file");
                let blob_bytes = att["blob_bytes"].as_i64().unwrap_or(0);
                let total = att["total_slices"].as_i64().unwrap_or(0);
                let received = att["slices_received"].as_i64().unwrap_or(0);
                let complete = total > 0 && received >= total;
                let download_rate_mib_s = att["download_rate_mib_s"].as_f64();
                println!(
                    "        {}",
                    format_file_display(
                        filename,
                        blob_bytes,
                        complete,
                        total,
                        received,
                        download_rate_mib_s,
                    )
                );
            }
        }
    }
    println!();
}

pub(crate) fn show_files_from_json(data: &serde_json::Value) {
    let files = match data["files"].as_array() {
        Some(files) => files,
        None => {
            println!("  (no files)");
            return;
        }
    };
    if files.is_empty() {
        println!("  (no files)");
        return;
    }

    let total = data["total"].as_i64().unwrap_or(0);
    println!("FILES ({} total):\n", total);

    for (i, file) in files.iter().enumerate() {
        let filename = file["filename"].as_str().unwrap_or("file");
        let blob_bytes = file["blob_bytes"].as_i64().unwrap_or(0);
        let total_slices = file["total_slices"].as_i64().unwrap_or(0);
        let slices_received = file["slices_received"].as_i64().unwrap_or(0);
        let complete = file["complete"].as_bool().unwrap_or(false);
        let download_rate_mib_s = file["download_rate_mib_s"].as_f64();
        println!(
            "  {}. {}",
            i + 1,
            format_file_display(
                filename,
                blob_bytes,
                complete,
                total_slices,
                slices_received,
                download_rate_mib_s,
            )
        );
    }
    println!();
}

pub(crate) fn emoji_shortcode_to_unicode(name: &str) -> &str {
    match name {
        "thumbsup" | "+1" => "\u{1f44d}",
        "thumbsdown" | "-1" => "\u{1f44e}",
        "heart" | "red_heart" => "\u{2764}\u{fe0f}",
        "laugh" | "joy" => "\u{1f602}",
        "cry" | "sob" => "\u{1f62d}",
        "fire" => "\u{1f525}",
        "rocket" => "\u{1f680}",
        "eyes" => "\u{1f440}",
        "tada" | "party" => "\u{1f389}",
        "100" => "\u{1f4af}",
        "wave" => "\u{1f44b}",
        "clap" => "\u{1f44f}",
        "thinking" | "thinking_face" => "\u{1f914}",
        "pray" | "folded_hands" => "\u{1f64f}",
        "ok_hand" => "\u{1f44c}",
        "raised_hands" => "\u{1f64c}",
        "star" => "\u{2b50}",
        "sparkles" => "\u{2728}",
        "check" | "white_check_mark" => "\u{2705}",
        "x" | "cross_mark" => "\u{274c}",
        "warning" => "\u{26a0}\u{fe0f}",
        "question" => "\u{2753}",
        "exclamation" => "\u{2757}",
        "smile" | "smiley" => "\u{1f604}",
        "wink" => "\u{1f609}",
        "sunglasses" | "cool" => "\u{1f60e}",
        "sad" | "disappointed" => "\u{1f61e}",
        "angry" => "\u{1f620}",
        "scream" => "\u{1f631}",
        "skull" => "\u{1f480}",
        "poop" => "\u{1f4a9}",
        "muscle" => "\u{1f4aa}",
        "brain" => "\u{1f9e0}",
        "bulb" | "light_bulb" => "\u{1f4a1}",
        "memo" => "\u{1f4dd}",
        "pin" | "pushpin" => "\u{1f4cc}",
        "link" => "\u{1f517}",
        "bug" => "\u{1f41b}",
        "wrench" => "\u{1f527}",
        "hammer" => "\u{1f528}",
        "gear" => "\u{2699}\u{fe0f}",
        "lock" => "\u{1f512}",
        "key" => "\u{1f511}",
        "bell" => "\u{1f514}",
        "megaphone" | "loudspeaker" => "\u{1f4e3}",
        _ => name, // pass through unknown shortcodes as-is
    }
}

pub(crate) fn format_byte_size(bytes: i64) -> String {
    const KIB: i64 = 1024;
    const MIB: i64 = 1024 * 1024;
    const GIB: i64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

pub(crate) fn format_download_rate_mib_s(download_rate_mib_s: Option<f64>) -> Option<String> {
    let rate = download_rate_mib_s?;
    if !rate.is_finite() || rate <= 0.0 {
        return None;
    }
    Some(format!("{rate:.2} MiB/s"))
}

pub(crate) fn format_file_display(
    filename: &str,
    blob_bytes: i64,
    complete: bool,
    total_slices: i64,
    slices_received: i64,
    download_rate_mib_s: Option<f64>,
) -> String {
    let status = if complete { "\u{2714}" } else { "\u{23f3}" };
    let size = format_byte_size(blob_bytes);

    if !complete {
        if total_slices > 0 {
            let pct = (slices_received as f64 / total_slices as f64 * 100.0) as u32;
            return format!("{status}  {filename} ({size}, {pct}%)");
        }
        return format!("{status}  {filename} ({size})");
    }

    match format_download_rate_mib_s(download_rate_mib_s) {
        Some(rate) => format!("{status}  {filename} ({size}, {rate})"),
        None => format!("{status}  {filename} ({size})"),
    }
}

pub(crate) fn show_view(data: &serde_json::Value) {
    let workspace_name = data["workspace_name"].as_str().unwrap_or("(unnamed)");
    let own_user_eid = data["own_user_event_id"].as_str().unwrap_or("");

    println!("TENANTS:");
    if let Some(tenants) = data["tenants"]
        .as_array()
        .or_else(|| data["accounts"].as_array())
    {
        if tenants.is_empty() {
            println!("  (none)");
        } else {
            for (idx, tenant) in tenants.iter().enumerate() {
                let marker = if tenant["active"].as_bool().unwrap_or(false) {
                    "*"
                } else {
                    " "
                };
                let tenant_eid = tenant["event_id"].as_str().unwrap_or("");
                let username = tenant["username"].as_str().unwrap_or("");
                let workspace_name = tenant["workspace_name"].as_str().unwrap_or("");
                let workspace_id = tenant["workspace_id"].as_str().unwrap_or("");
                let user_display = if username.is_empty() {
                    short_id(tenant["peer_id"].as_str().unwrap_or("")).to_string()
                } else {
                    username.to_string()
                };
                let workspace_display = if workspace_name.is_empty() {
                    short_id(workspace_id).to_string()
                } else {
                    workspace_name.to_string()
                };
                let joining_tag = if tenant["ready"].as_bool().unwrap_or(false) {
                    ""
                } else {
                    " [still joining]"
                };
                println!(
                    "  {}. {} {} {}@{}{}",
                    idx + 1,
                    marker,
                    short_id(tenant_eid),
                    user_display,
                    workspace_display,
                    joining_tag
                );
            }
        }
    }

    println!();
    println!("WORKSPACE:");
    println!("  {}", workspace_name);
    println!();
    println!("  USERS:");

    if let Some(users) = data["users"].as_array() {
        if users.is_empty() {
            println!("    (none)");
        } else {
            for user in users {
                let username = user["username"].as_str().unwrap_or("");
                let device_name = user["device_name"].as_str().unwrap_or("");
                let user_eid = user["event_id"].as_str().unwrap_or("");
                let user_display = if username.is_empty() {
                    short_id(user_eid).to_string()
                } else {
                    username.to_string()
                };
                let label = if device_name.is_empty() {
                    user_display
                } else {
                    format!("{}/{}", user_display, device_name)
                };
                if user_eid == own_user_eid {
                    println!("    {} (you)", label);
                } else {
                    println!("    {}", label);
                }
            }
        }
    }

    println!();
    println!("  {}", "\u{2500}".repeat(40));
    println!();

    // Messages with inline reactions
    if let Some(messages) = data["messages"].as_array() {
        if messages.is_empty() {
            println!("    (no messages)");
        } else {
            let mut last_author = String::new();
            for (i, msg) in messages.iter().enumerate() {
                let created_at = msg["created_at"].as_i64().unwrap_or(0);
                let ts = format_timestamp(created_at);
                let author_id = msg["author_id"].as_str().unwrap_or("");
                let author_name = msg["author_name"].as_str().unwrap_or("");
                let display_name = if author_name.is_empty() {
                    short_id(author_id).to_string()
                } else {
                    author_name.to_string()
                };
                let content = msg["content"].as_str().unwrap_or("");

                if author_id != last_author {
                    if i > 0 {
                        println!();
                    }
                    println!("    {} [{}]", display_name, ts);
                    last_author = author_id.to_string();
                }
                println!("      {}. {}", i + 1, content);

                // Inline reactions
                if let Some(reactions) = msg["reactions"].as_array() {
                    if !reactions.is_empty() {
                        let mut counts: std::collections::BTreeMap<String, usize> =
                            std::collections::BTreeMap::new();
                        for r in reactions {
                            let emoji = r["emoji"].as_str().unwrap_or("?").to_string();
                            *counts.entry(emoji).or_default() += 1;
                        }
                        let parts: Vec<String> = counts
                            .iter()
                            .map(|(name, count)| {
                                let glyph = emoji_shortcode_to_unicode(name);
                                if *count > 1 {
                                    format!("{} ({})", glyph, count)
                                } else {
                                    glyph.to_string()
                                }
                            })
                            .collect();
                        println!("         {}", parts.join("  "));
                    }
                }

                // Inline file attachments
                if let Some(files) = msg["files"].as_array() {
                    for att in files {
                        let filename = att["filename"].as_str().unwrap_or("file");
                        let blob_bytes = att["blob_bytes"].as_i64().unwrap_or(0);
                        let total = att["total_slices"].as_i64().unwrap_or(0);
                        let received = att["slices_received"].as_i64().unwrap_or(0);
                        let size = format_byte_size(blob_bytes);
                        let status = if total > 0 && received >= total {
                            "\u{2714}" // checkmark
                        } else {
                            "\u{23f3}" // hourglass
                        };
                        if total > 0 && received < total {
                            let pct = (received as f64 / total as f64 * 100.0) as u32;
                            println!("         {}  {} ({}, {}%)", status, filename, size, pct);
                        } else {
                            println!("         {}  {} ({})", status, filename, size);
                        }
                    }
                }
            }
        }
    }
    println!();
}

pub(crate) fn print_round_capture(data: &serde_json::Value) {
    let peer = data["peer_id"].as_str().unwrap_or("?");
    let short_peer = &peer[..16.min(peer.len())];

    if let Some(ids) = data["observed_ids"].as_array() {
        if ids.is_empty() {
            println!("SYNC ROUND peer={}", short_peer);
            println!("  Newly observed: nothing new learned");
        } else {
            println!("SYNC ROUND peer={}", short_peer);
            println!("  Newly observed: {} event(s)", ids.len());
            for id in ids {
                if let Some(s) = id.as_str() {
                    println!("    {}", &s[..16.min(s.len())]);
                }
            }
        }
    } else {
        println!("SYNC ROUND peer={}", short_peer);
        println!("  Newly observed: nothing new learned");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emoji_shortcode_known() {
        assert_eq!(emoji_shortcode_to_unicode("thumbsup"), "\u{1f44d}");
        assert_eq!(emoji_shortcode_to_unicode("+1"), "\u{1f44d}");
        assert_eq!(emoji_shortcode_to_unicode("heart"), "\u{2764}\u{fe0f}");
        assert_eq!(emoji_shortcode_to_unicode("fire"), "\u{1f525}");
        assert_eq!(emoji_shortcode_to_unicode("rocket"), "\u{1f680}");
        assert_eq!(emoji_shortcode_to_unicode("tada"), "\u{1f389}");
    }

    #[test]
    fn test_emoji_shortcode_unknown_passthrough() {
        assert_eq!(emoji_shortcode_to_unicode("zzz_unknown"), "zzz_unknown");
    }

    #[test]
    fn test_format_byte_size() {
        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(512), "512 B");
        assert_eq!(format_byte_size(1024), "1.0 KiB");
        assert_eq!(format_byte_size(1536), "1.5 KiB");
        assert_eq!(format_byte_size(1048576), "1.0 MiB");
        assert_eq!(format_byte_size(1258291), "1.2 MiB");
        assert_eq!(format_byte_size(1073741824), "1.0 GiB");
    }

    #[test]
    fn test_format_file_display_complete_with_rate() {
        assert_eq!(
            format_file_display("payload.bin", 12 * 1024 * 1024, true, 48, 48, Some(3.42)),
            "\u{2714}  payload.bin (12.0 MiB, 3.42 MiB/s)"
        );
    }

    #[test]
    fn test_format_file_display_complete_without_rate() {
        assert_eq!(
            format_file_display("payload.bin", 12 * 1024 * 1024, true, 48, 48, None),
            "\u{2714}  payload.bin (12.0 MiB)"
        );
    }

    #[test]
    fn test_format_file_display_incomplete_uses_percentage_only() {
        assert_eq!(
            format_file_display("payload.bin", 12 * 1024 * 1024, false, 48, 36, Some(3.42)),
            "\u{23f3}  payload.bin (12.0 MiB, 75%)"
        );
    }
}
