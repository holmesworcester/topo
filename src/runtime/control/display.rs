//! CLI display helpers for event rendering (tree, list, deps).
//!
//! Extracted from main.rs — pure formatting, no business logic.

use crate::service;

/// Truncate a base64-encoded event ID to its first 8 characters for display.
pub fn short_id(b64: &str) -> &str {
    &b64[..b64.len().min(8)]
}

/// Return a concise annotation for an event type (displayed after em-dash).
pub fn event_type_note(type_name: &str) -> Option<&'static str> {
    match type_name {
        "workspace" => Some("creates the workspace"),
        "invite_accepted" => Some("joins the workspace"),
        "user_invite_shared" => Some("invites a user"),
        "peer_invite_shared" => Some("invites a device"),
        "user" => Some("registers the user"),
        "peer_shared" => Some("registers a device"),
        "admin" => Some("grants admin rights"),
        "key_secret" => Some("stores a local encryption key"),
        "key_request" => Some("requests an encryption key"),
        "key_shared" => Some("shares an encryption key"),
        "encrypted" => Some("encrypts an inner event"),
        "message" => Some("sends a message"),
        "reaction" => Some("reacts to a message"),
        "message_deletion" => Some("deletes a message"),
        "file" => Some("attaches a file"),
        "file_slice" => Some("stores a file chunk"),
        "tenant" => Some("creates local tenant identity"),
        "peer_secret" => Some("stores a local signing key"),
        "invite_secret" => Some("stores a local invite key"),
        _ => None,
    }
}

/// Format a type name with its annotation suffix, e.g. `workspace — creates the workspace`.
fn type_with_note(type_name: &str) -> String {
    match event_type_note(type_name) {
        Some(note) => format!("{} \u{2014} {}", type_name, note),
        None => type_name.to_string(),
    }
}

/// Format a millisecond timestamp to a human-readable local-time string.
///
/// Returns an em-dash for zero or clearly bogus timestamps.
pub fn format_timestamp_ms(ms: u64) -> String {
    // Reject zero or clearly bogus timestamps (before 2020 or after 2100).
    if ms == 0 || ms < 1_577_836_800_000 || ms > 4_102_444_800_000 {
        return "\u{2014}".to_string(); // em-dash
    }
    let secs = (ms / 1000) as i64;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Use libc localtime_r for formatting without pulling in chrono.
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    let tm = unsafe {
        libc::localtime_r(&secs as *const i64, tm.as_mut_ptr());
        tm.assume_init()
    };

    let mut buf = [0u8; 64];
    let now_year = {
        let mut now_tm = std::mem::MaybeUninit::<libc::tm>::uninit();
        unsafe {
            libc::localtime_r(&now_secs as *const i64, now_tm.as_mut_ptr());
            now_tm.assume_init().tm_year
        }
    };
    let same_year = tm.tm_year == now_year;
    let fmt: &[u8] = if same_year {
        b"%b %d %H:%M:%S\0"
    } else {
        b"%Y %b %d %H:%M:%S\0"
    };
    let len = unsafe {
        libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr() as *const libc::c_char,
            &tm,
        )
    };
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn print_decrypted_inner(dec: &service::EventListDecrypted, prefix: &str) {
    let inner_type_display = type_with_note(&dec.inner_type);
    println!("{}--- decrypted: {} ---", prefix, inner_type_display);
    for (k, v) in &dec.fields {
        println!("{}  {}: {}", prefix, k, v);
    }
}

// ---------------------------------------------------------------------------
// Event tree
// ---------------------------------------------------------------------------

/// Render events as a dependency tree. First dep = tree parent.
pub fn print_event_tree(events: &[service::EventListItem]) {
    use std::collections::{HashMap, HashSet};

    if events.is_empty() {
        println!("(no events)");
        return;
    }

    let id_set: HashSet<&str> = events.iter().map(|e| e.id.as_str()).collect();

    // For each event, pick the first dep as tree parent (if it exists in the db).
    // Events with no valid tree parent are roots.
    let mut parent_of: HashMap<&str, &str> = HashMap::new();
    for e in events {
        for (_, dep_id) in &e.deps {
            if id_set.contains(dep_id.as_str()) {
                parent_of.insert(&e.id, dep_id.as_str());
                break;
            }
        }
    }

    // Build children map.
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in events {
        if let Some(&parent) = parent_of.get(e.id.as_str()) {
            children.entry(parent).or_default().push(&e.id);
        }
    }

    // Roots: events with no tree parent.
    let roots: Vec<&str> = events
        .iter()
        .filter(|e| !parent_of.contains_key(e.id.as_str()))
        .map(|e| e.id.as_str())
        .collect();

    let event_map: HashMap<&str, &service::EventListItem> =
        events.iter().map(|e| (e.id.as_str(), e)).collect();

    // Print each root tree, then lone roots.
    let mut first = true;
    for root in &roots {
        let has_children = children.contains_key(root);
        if !first && has_children {
            println!();
        }
        print_tree_node(root, "", true, true, &children, &event_map, &parent_of);
        if has_children {
            first = false;
        }
    }

    println!(
        "\n{} events. Tree parent = first dependency; siblings in insertion order.",
        events.len()
    );
}

fn print_tree_node(
    id: &str,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    children: &std::collections::HashMap<&str, Vec<&str>>,
    event_map: &std::collections::HashMap<&str, &service::EventListItem>,
    parent_of: &std::collections::HashMap<&str, &str>,
) {
    let info = event_map[id];
    let connector = if is_root {
        ""
    } else if is_last {
        "\u{2514}\u{2500}\u{2500} "
    } else {
        "\u{251c}\u{2500}\u{2500} "
    };

    let short = short_id(&info.id);

    // Collect cross-ref deps (deps that aren't the tree parent).
    let tree_parent = parent_of.get(id).copied();
    let cross_refs: Vec<String> = info
        .deps
        .iter()
        .filter(|(_, dep_id)| Some(dep_id.as_str()) != tree_parent)
        .map(|(field, dep_id)| format!("{}: {}", field, short_id(dep_id)))
        .collect();

    let suffix = if !cross_refs.is_empty() {
        format!("  [{}]", cross_refs.join(", "))
    } else if tree_parent.is_none() {
        " \u{2190} root".to_string()
    } else {
        String::new()
    };

    let type_display = type_with_note(&info.event_type);

    println!(
        "{}{}({}) {}{}",
        prefix, connector, short, type_display, suffix
    );

    // Show decrypted inner info inline for tree nodes.
    if let Some(dec) = &info.decrypted_inner {
        let inner_prefix = if is_root {
            "  ".to_string()
        } else if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}\u{2502}   ", prefix)
        };
        print_decrypted_inner(dec, &inner_prefix);
    }

    if let Some(kids) = children.get(id) {
        let new_prefix = if is_root {
            String::new()
        } else if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}\u{2502}   ", prefix)
        };
        for (i, kid) in kids.iter().enumerate() {
            let kid_is_last = i == kids.len() - 1;
            print_tree_node(
                kid,
                &new_prefix,
                kid_is_last,
                false,
                children,
                event_map,
                parent_of,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Event list
// ---------------------------------------------------------------------------

/// Render events as a flat list with full details.
pub fn print_event_list(events: &[service::EventListItem]) {
    if events.is_empty() {
        println!("(no events)");
        return;
    }

    for e in events {
        let short = format!("({})", short_id(&e.id));
        let ts = format_timestamp_ms(e.created_at_ms);
        let type_display = type_with_note(&e.event_type);

        let deps_str = if e.deps.is_empty() {
            String::new()
        } else {
            let d = e
                .deps
                .iter()
                .map(|(field, dep_id)| format!("{}: ({})", field, short_id(dep_id)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("  deps: {}", d)
        };

        println!("{} {} {}  [{} bytes]", short, type_display, ts, e.blob_len);
        if !deps_str.is_empty() {
            println!("{}", deps_str);
        }
        for (k, v) in &e.fields {
            println!("  {}: {}", k, v);
        }

        if let Some(dec) = &e.decrypted_inner {
            print_decrypted_inner(dec, "  ");
        } else if e.event_type == "encrypted" {
            println!("  (key not available)");
        }

        println!();
    }
    println!("{} events. Sorted by insertion order.", events.len());
}

// ---------------------------------------------------------------------------
// Deps tree (reverse dependency traversal)
// ---------------------------------------------------------------------------

/// Render a reverse dependency tree from a root event down through its deps.
pub fn print_deps_tree(root_id: &str, all_items: &[service::EventListItem], max_depth: usize) {
    use std::collections::{HashMap, HashSet};

    let item_map: HashMap<&str, &service::EventListItem> =
        all_items.iter().map(|e| (e.id.as_str(), e)).collect();

    let Some(root) = item_map.get(root_id) else {
        println!("(event not found)");
        return;
    };

    let mut visited: HashSet<&str> = HashSet::new();
    visited.insert(root_id);

    // Print root event.
    let type_display = type_with_note(&root.event_type);
    println!("({}) {}", short_id(&root.id), type_display);
    for (k, v) in &root.fields {
        println!("  {}: {}", k, v);
    }
    if let Some(dec) = &root.decrypted_inner {
        print_decrypted_inner(dec, "  ");
    }

    // Print dependency subtrees.
    let deps = &root.deps;
    for (i, (field, dep_id)) in deps.iter().enumerate() {
        let is_last = i == deps.len() - 1;
        print_dep_node(
            dep_id,
            field,
            "",
            is_last,
            &item_map,
            &mut visited,
            1,
            max_depth,
        );
    }

    println!("\n{} unique events (depth {}).", visited.len(), max_depth);
}

fn print_dep_node<'a>(
    id: &'a str,
    field_name: &str,
    prefix: &str,
    is_last: bool,
    item_map: &std::collections::HashMap<&'a str, &'a service::EventListItem>,
    visited: &mut std::collections::HashSet<&'a str>,
    depth: usize,
    max_depth: usize,
) {
    let connector = if is_last {
        "\u{2514}\u{2500}\u{2500} "
    } else {
        "\u{251c}\u{2500}\u{2500} "
    };

    let Some(info) = item_map.get(id) else {
        // Event not in our result set (e.g. not yet synced).
        println!(
            "{}{}{}: ({}) (not found)",
            prefix,
            connector,
            field_name,
            short_id(id)
        );
        return;
    };

    let type_display = type_with_note(&info.event_type);

    if !visited.insert(id) {
        // Already visited — show cross-reference.
        println!(
            "{}{}{}: ({}) {} (see above)",
            prefix,
            connector,
            field_name,
            short_id(id),
            type_display,
        );
        return;
    }

    if info.deps.is_empty() {
        // Root event — no further deps.
        println!(
            "{}{}{}: ({}) {} \u{2190} root",
            prefix,
            connector,
            field_name,
            short_id(id),
            type_display,
        );
        // Show fields inline.
        let child_prefix = if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}\u{2502}   ", prefix)
        };
        for (k, v) in &info.fields {
            println!("{}{}: {}", child_prefix, k, v);
        }
        return;
    }

    if depth >= max_depth {
        // Depth exceeded.
        println!(
            "{}{}{}: ({}) {} ...",
            prefix,
            connector,
            field_name,
            short_id(id),
            type_display,
        );
        return;
    }

    println!(
        "{}{}{}: ({}) {}",
        prefix,
        connector,
        field_name,
        short_id(id),
        type_display,
    );

    let child_prefix = if is_last {
        format!("{}    ", prefix)
    } else {
        format!("{}\u{2502}   ", prefix)
    };

    // Show fields inline.
    for (k, v) in &info.fields {
        println!("{}{}: {}", child_prefix, k, v);
    }

    // Recurse into deps.
    for (i, (dep_field, dep_id)) in info.deps.iter().enumerate() {
        let dep_is_last = i == info.deps.len() - 1;
        print_dep_node(
            dep_id,
            dep_field,
            &child_prefix,
            dep_is_last,
            item_map,
            visited,
            depth + 1,
            max_depth,
        );
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_id_normal() {
        assert_eq!(short_id("abcdefghijklmnop"), "abcdefgh");
    }

    #[test]
    fn test_short_id_exact_8() {
        assert_eq!(short_id("abcdefgh"), "abcdefgh");
    }

    #[test]
    fn test_short_id_short() {
        assert_eq!(short_id("abc"), "abc");
    }

    #[test]
    fn test_short_id_empty() {
        assert_eq!(short_id(""), "");
    }

    #[test]
    fn test_format_timestamp_ms_zero() {
        assert_eq!(format_timestamp_ms(0), "\u{2014}");
    }

    #[test]
    fn test_format_timestamp_ms_bogus_low() {
        assert_eq!(format_timestamp_ms(1_000_000_000), "\u{2014}");
    }

    #[test]
    fn test_format_timestamp_ms_bogus_high() {
        assert_eq!(format_timestamp_ms(5_000_000_000_000), "\u{2014}");
    }

    #[test]
    fn test_format_timestamp_ms_valid() {
        let ts = 1_736_899_200_000;
        let result = format_timestamp_ms(ts);
        assert!(!result.is_empty());
        assert_ne!(result, "\u{2014}");
    }

    #[test]
    fn test_event_type_note_known() {
        assert_eq!(event_type_note("workspace"), Some("creates the workspace"));
        assert_eq!(event_type_note("message"), Some("sends a message"));
        assert_eq!(
            event_type_note("peer_secret"),
            Some("stores a local signing key")
        );
    }

    #[test]
    fn test_event_type_note_unknown() {
        assert_eq!(event_type_note("unknown_type"), None);
    }

    #[test]
    fn test_type_with_note_known() {
        assert_eq!(
            type_with_note("workspace"),
            "workspace \u{2014} creates the workspace"
        );
    }

    #[test]
    fn test_type_with_note_unknown() {
        assert_eq!(type_with_note("unknown"), "unknown");
    }
}
