use std::collections::HashMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;

use crate::crypto::{event_id_to_base64, EventId};
use crate::db::{
    open_connection,
    schema::create_tables,
};
use crate::events::*;
use crate::identity_ops::{self, IdentityChain, InviteType, LinkChain};
use crate::invite_link::{create_invite_link, parse_invite_link, InviteLinkKind};
use crate::projection::create::create_signed_event_sync;
use crate::transport_identity::{
    ensure_transport_peer_id_from_db, expected_invite_bootstrap_spki_from_invite_key,
    install_invite_bootstrap_transport_identity,
};

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Config, Context, Editor, Helper};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Per-account state within an interactive session.
struct Account {
    db_path: String,
    identity: String,
    /// Signing keys indexed by event_id base64
    signing_keys: HashMap<String, SigningKey>,
    workspace_id: Option<EventId>,
    workspace_name: Option<String>,
    workspace_key: Option<SigningKey>,
    user_event_id: Option<EventId>,
    user_key: Option<SigningKey>,
    peer_shared_event_id: Option<EventId>,
    peer_shared_key: Option<SigningKey>,
    user_name: String,
    device_name: String,
    active_channel: [u8; 32],
    author_id: [u8; 32],
    _tempdir: tempfile::TempDir,
}

impl Account {
    fn new(user_name: &str, device_name: &str) -> Self {
        let tempdir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = tempdir
            .path()
            .join(format!("{}.db", user_name))
            .to_str()
            .unwrap()
            .to_string();

        let db = open_connection(&db_path).expect("failed to open db");
        create_tables(&db).expect("failed to create tables");

        let identity =
            ensure_transport_peer_id_from_db(&db_path).expect("failed to compute identity");

        let mut default_channel = [0u8; 32];
        default_channel[..16]
            .copy_from_slice(&hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap());

        Account {
            db_path,
            identity,
            signing_keys: HashMap::new(),
            workspace_id: None,
            workspace_name: None,
            workspace_key: None,
            user_event_id: None,
            user_key: None,
            peer_shared_event_id: None,
            peer_shared_key: None,
            user_name: user_name.to_string(),
            device_name: device_name.to_string(),
            active_channel: default_channel,
            author_id: rand::random(),
            _tempdir: tempdir,
        }
    }

    fn store_chain_keys(&mut self, chain: &IdentityChain) {
        self.workspace_id = Some(chain.workspace_id);
        self.workspace_key = Some(chain.workspace_key.clone());
        self.user_event_id = Some(chain.user_event_id);
        self.user_key = Some(chain.user_key.clone());
        self.peer_shared_event_id = Some(chain.peer_shared_event_id);
        self.peer_shared_key = Some(chain.peer_shared_key.clone());

        let keys_to_store = [
            (chain.workspace_id, chain.workspace_key.clone()),
            (chain.user_invite_event_id, chain.invite_key.clone()),
            (chain.user_event_id, chain.user_key.clone()),
            (
                chain.device_invite_event_id,
                chain.device_invite_key.clone(),
            ),
            (chain.peer_shared_event_id, chain.peer_shared_key.clone()),
            (chain.admin_event_id, chain.admin_key.clone()),
        ];
        for (eid, key) in keys_to_store {
            self.signing_keys.insert(event_id_to_base64(&eid), key);
        }
    }

    fn store_link_keys(&mut self, link: &LinkChain) {
        self.peer_shared_event_id = Some(link.peer_shared_event_id);
        self.peer_shared_key = Some(link.peer_shared_key.clone());
        self.signing_keys.insert(
            event_id_to_base64(&link.peer_shared_event_id),
            link.peer_shared_key.clone(),
        );
    }

    fn short_user_id(&self) -> String {
        self.user_event_id
            .map(|eid| {
                let b64 = event_id_to_base64(&eid);
                format!("user_{}", &b64[..8])
            })
            .unwrap_or_else(|| "user_none".to_string())
    }

    fn short_peer_id(&self) -> String {
        self.peer_shared_event_id
            .map(|eid| {
                let b64 = event_id_to_base64(&eid);
                format!("peer_{}", &b64[..8])
            })
            .unwrap_or_else(|| "peer_none".to_string())
    }
}

struct ChannelInfo {
    name: String,
    id: [u8; 32],
}

struct FrontendInvite {
    link: String,
}

struct Session {
    accounts: Vec<Account>,
    active: usize,
    invites: Vec<FrontendInvite>,
    channels: Vec<ChannelInfo>,
    rt: tokio::runtime::Handle,
}

impl Session {
    fn new() -> Self {
        let rt = tokio::runtime::Handle::current();
        let mut default_channel = [0u8; 32];
        default_channel[..16]
            .copy_from_slice(&hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap());
        Session {
            accounts: Vec::new(),
            active: 0,
            invites: Vec::new(),
            channels: vec![ChannelInfo {
                name: "general".to_string(),
                id: default_channel,
            }],
            rt,
        }
    }

    fn active_account(&self) -> Option<&Account> {
        self.accounts.get(self.active)
    }

    fn active_account_mut(&mut self) -> Option<&mut Account> {
        self.accounts.get_mut(self.active)
    }

    fn add_invite(&mut self, link: String) -> usize {
        self.invites.push(FrontendInvite { link });
        self.invites.len()
    }

    fn invite_link_by_number(&self, invite_num: usize) -> Option<&str> {
        if invite_num == 0 {
            return None;
        }
        self.invites
            .get(invite_num - 1)
            .map(|entry| entry.link.as_str())
    }
}

// ---------------------------------------------------------------------------
// Autocomplete
// ---------------------------------------------------------------------------

const COMMANDS: &[&str] = &[
    "accept-invite",
    "accept-link",
    "accounts",
    "ban",
    "channel",
    "channels",
    "delete",
    "exit",
    "help",
    "identity",
    "invite",
    "keys",
    "link",
    "messages",
    "new-channel",
    "new-workspace",
    "quit",
    "react",
    "reactions",
    "send",
    "status",
    "switch",
    "users",
    "workspaces",
];

const COMMAND_FLAGS: &[(&str, &[&str])] = &[
    ("new-workspace", &["--name", "--username", "--devicename"]),
    ("invite", &["--bootstrap"]),
    ("accept-invite", &["--username", "--devicename", "--invite"]),
    ("link", &["--bootstrap"]),
    ("accept-link", &["--devicename", "--invite"]),
    ("keys", &["--summary"]),
];

#[derive(Default)]
struct CliHelper;

impl Helper for CliHelper {}
impl Highlighter for CliHelper {}
impl Validator for CliHelper {}
impl Hinter for CliHelper {
    type Hint = String;
}

impl Completer for CliHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        let parts: Vec<&str> = before.split_whitespace().collect();

        if parts.is_empty() || (parts.len() == 1 && !before.ends_with(' ')) {
            // Completing command name
            let prefix = parts.first().copied().unwrap_or("");
            let matches: Vec<Pair> = COMMANDS
                .iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();
            Ok((0, matches))
        } else {
            let cmd = parts[0];
            let current = if before.ends_with(' ') {
                ""
            } else {
                parts.last().unwrap()
            };
            let start = pos - current.len();

            // Flag completion
            if current.starts_with('-') {
                if let Some((_, flags)) = COMMAND_FLAGS.iter().find(|(c, _)| *c == cmd) {
                    let matches: Vec<Pair> = flags
                        .iter()
                        .filter(|f| f.starts_with(current))
                        .map(|f| Pair {
                            display: f.to_string(),
                            replacement: f.to_string(),
                        })
                        .collect();
                    return Ok((start, matches));
                }
            }

            Ok((pos, vec![]))
        }
    }
}

/// Dispatch a single command line. Returns Ok(true) to quit.
fn dispatch(
    session: &mut Session,
    line: &str,
    out: &mut impl Write,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    let cmd = parts[0];
    let args = &parts[1..];

    match cmd {
        "new-workspace" => cmd_new_workspace(session, args, out)?,
        "send" => cmd_send(session, args, out)?,
        "messages" => cmd_messages(session, out)?,
        "react" => cmd_react(session, args, out)?,
        "reactions" => cmd_reactions(session, args, out)?,
        "delete" => cmd_delete(session, args, out)?,
        "invite" => cmd_invite(session, args, out)?,
        "accept-invite" => cmd_accept_invite(session, args, out)?,
        "link" => cmd_link(session, args, out)?,
        "accept-link" => cmd_accept_link(session, args, out)?,
        "switch" => cmd_switch(session, args, out)?,
        "accounts" => cmd_accounts(session, out)?,
        "channels" => cmd_channels(session, out)?,
        "new-channel" => cmd_new_channel(session, args, out)?,
        "channel" => cmd_channel(session, args, out)?,
        "users" => cmd_users(session, out)?,
        "keys" => cmd_keys(session, args, out)?,
        "workspaces" => cmd_workspaces(session, out)?,
        "status" => cmd_status(session, out)?,
        "identity" => cmd_identity(session, out)?,
        "ban" => cmd_ban(session, args, out)?,
        "help" => cmd_help(out)?,
        "quit" | "exit" => return Ok(true),
        _ => {
            writeln!(
                out,
                "Unknown command: {}. Type 'help' for available commands.",
                cmd
            )?;
        }
    }
    Ok(false)
}

/// Run the interactive REPL. Uses rustyline when stdin is a TTY, plain BufRead otherwise.
pub fn run_interactive() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if io::stdin().is_terminal() {
        run_interactive_tty()
    } else {
        run_interactive_piped()
    }
}

/// TTY mode: rustyline with autocomplete and history.
fn run_interactive_tty() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::builder()
        .completion_type(rustyline::CompletionType::List)
        .build();
    let mut rl = Editor::with_config(config)?;
    rl.set_helper(Some(CliHelper));

    // Ensure tab triggers completion
    rl.bind_sequence(rustyline::KeyEvent::from('\t'), rustyline::Cmd::Complete);

    let history_path = dirs_next::home_dir()
        .map(|h| h.join(".poc7_cli_history"))
        .unwrap_or_else(|| std::path::PathBuf::from(".poc7_cli_history"));
    let _ = rl.load_history(&history_path);

    let mut session = Session::new();
    let mut out = io::stdout();

    loop {
        let prompt = if let Some(acct) = session.active_account() {
            let ch_name = session
                .channels
                .iter()
                .find(|c| c.id == acct.active_channel)
                .map(|c| c.name.as_str())
                .unwrap_or("?");
            format!("{}#{}> ", acct.user_name, ch_name)
        } else {
            "> ".to_string()
        };

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(&line)?;

                match dispatch(&mut session, &line, &mut out) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => {
                        writeln!(out, "Error: {}", e)?;
                    }
                }
                out.flush()?;
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => return Err(e.into()),
        }
    }

    let _ = rl.save_history(&history_path);
    Ok(())
}

/// Piped mode: plain BufRead (used by tests).
fn run_interactive_piped() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut session = Session::new();

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        writeln!(out, "> {}", line)?;

        match dispatch(&mut session, &line, &mut out) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => {
                writeln!(out, "Error: {}", e)?;
            }
        }

        out.flush()?;
    }

    Ok(())
}

fn parse_named_arg<'a>(args: &'a [&str], name: &str) -> Option<&'a str> {
    for i in 0..args.len() {
        if args[i] == name && i + 1 < args.len() {
            return Some(args[i + 1]);
        }
    }
    None
}

fn resolve_bootstrap_addr(args: &[&str]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(addr) = parse_named_arg(args, "--bootstrap") {
        if !addr.trim().is_empty() {
            return Ok(addr.to_string());
        }
    }
    if let Ok(addr) = std::env::var("POC7_BOOTSTRAP_ADDR") {
        if !addr.trim().is_empty() {
            return Ok(addr);
        }
    }
    Err("Missing bootstrap endpoint. Pass --bootstrap <host:port> or set POC7_BOOTSTRAP_ADDR.".into())
}

fn resolve_invite_ref(
    session: &Session,
    invite_ref: &str,
) -> Result<(String, Option<usize>), Box<dyn std::error::Error + Send + Sync>> {
    if invite_ref.chars().all(|c| c.is_ascii_digit()) {
        let invite_num: usize = invite_ref.parse().map_err(|_| "Invalid invite number")?;
        let link = session.invite_link_by_number(invite_num).ok_or_else(|| {
            format!(
                "Invalid invite number {}. Available: 1-{}",
                invite_num,
                session.invites.len()
            )
        })?;
        return Ok((link.to_string(), Some(invite_num)));
    }
    Ok((invite_ref.to_string(), None))
}

fn decode_spki_hex(spki_hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let raw = hex::decode(spki_hex)?;
    if raw.len() != 32 {
        return Err(format!("SPKI fingerprint must be 32 bytes, got {}", raw.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn cmd_new_workspace(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let name = parse_named_arg(args, "--name").unwrap_or("default");
    let username = parse_named_arg(args, "--username").unwrap_or("user");
    let devicename = parse_named_arg(args, "--devicename").unwrap_or("device");

    let mut account = Account::new(username, devicename);
    let conn = open_connection(&account.db_path)?;
    let chain = identity_ops::bootstrap_workspace(&conn, &account.identity)?;
    account.store_chain_keys(&chain);
    account.workspace_name = Some(name.to_string());

    let user_id = account.short_user_id();
    let peer_id = account.short_peer_id();
    session.accounts.push(account);
    session.active = session.accounts.len() - 1;

    writeln!(
        out,
        "Created workspace '{}' with user {} ({}) {} {}",
        name, username, devicename, user_id, peer_id
    )?;

    Ok(())
}

fn cmd_send(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session
        .active_account()
        .ok_or("No active account. Run 'new-workspace' first.")?;

    let content = args.join(" ");
    if content.is_empty() {
        writeln!(out, "Usage: send <message>")?;
        return Ok(());
    }

    let workspace_id = account
        .workspace_id
        .ok_or("No workspace created. Run 'new-workspace' first.")?;

    let conn = open_connection(&account.db_path)?;
    let peer_shared_eid = account
        .peer_shared_event_id
        .ok_or("No signing key. Run 'new-workspace' first.")?;
    let peer_shared_key = account
        .peer_shared_key
        .as_ref()
        .ok_or("No signing key.")?
        .clone();
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: now_ms(),
        workspace_id,
        author_id: account.author_id,
        content: content.clone(),
        signed_by: peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(&conn, &account.identity, &msg, &peer_shared_key)?;
    let eid_b64 = event_id_to_base64(&eid);

    writeln!(out, "Sent: {} ({})", content, &eid_b64[..8])?;

    Ok(())
}

fn cmd_messages(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session
        .active_account()
        .ok_or("No active account. Run 'new-workspace' first.")?;

    let conn = open_connection(&account.db_path)?;
    // Build author_id -> username map from all accounts in session
    let author_map: HashMap<String, String> = session
        .accounts
        .iter()
        .map(|a| (base64_encode(&a.author_id), a.user_name.clone()))
        .collect();

    let mut stmt = conn.prepare(
        "SELECT message_id, author_id, content, created_at
         FROM messages WHERE recorded_by = ?1
         ORDER BY created_at ASC, rowid ASC",
    )?;

    let rows: Vec<(String, String, String, i64)> = stmt
        .query_map(rusqlite::params![&account.identity], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Check deleted messages
    let deleted_targets: Vec<String> = {
        let mut del_stmt =
            conn.prepare("SELECT message_id FROM deleted_messages WHERE recorded_by = ?1")?;
        let result = del_stmt
            .query_map(rusqlite::params![&account.identity], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        result
    };

    // Find channel name
    let ch_name = session
        .channels
        .iter()
        .find(|c| c.id == account.active_channel)
        .map(|c| c.name.as_str())
        .unwrap_or("?");

    writeln!(out, "MESSAGES (#{}):", ch_name)?;
    if rows.is_empty() {
        writeln!(out, "  (no messages)")?;
    } else {
        let mut num = 0;
        for (msg_id, author_id, content, _created_at) in &rows {
            num += 1;
            if deleted_targets.contains(msg_id) {
                writeln!(out, "  {}. [deleted]", num)?;
            } else {
                let author_name = author_map
                    .get(author_id)
                    .cloned()
                    .unwrap_or_else(|| "?".to_string());
                writeln!(out, "  {}. [{}] {}", num, author_name, content)?;

                // Show reactions inline
                let mut rxn_stmt = conn.prepare(
                    "SELECT emoji FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
                )?;
                let emojis: Vec<String> = rxn_stmt
                    .query_map(rusqlite::params![&account.identity, msg_id], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                if !emojis.is_empty() {
                    // Group reactions by emoji with counts
                    let mut counts: Vec<(String, usize)> = Vec::new();
                    for e in &emojis {
                        if let Some(entry) = counts.iter_mut().find(|(em, _)| em == e) {
                            entry.1 += 1;
                        } else {
                            counts.push((e.clone(), 1));
                        }
                    }
                    let parts: Vec<String> = counts
                        .iter()
                        .map(|(em, c)| format!("{}({})", em, c))
                        .collect();
                    writeln!(out, "     {}", parts.join(" "))?;
                }
            }
        }
    }

    Ok(())
}

fn cmd_react(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.len() < 2 {
        writeln!(out, "Usage: react <msg-num> <emoji>")?;
        return Ok(());
    }

    let msg_num: usize = args[0].parse().map_err(|_| "Invalid message number")?;
    let emoji = args[1];

    let account = session.active_account().ok_or("No active account.")?;

    let conn = open_connection(&account.db_path)?;
    let target_event_id = get_message_event_id_by_num(&conn, &account.identity, msg_num)?;

    let peer_shared_eid = account.peer_shared_event_id.ok_or("No signing key.")?;
    let peer_shared_key = account
        .peer_shared_key
        .as_ref()
        .ok_or("No signing key.")?
        .clone();
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: now_ms(),
        target_event_id,
        author_id: account.author_id,
        emoji: emoji.to_string(),
        signed_by: peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    create_signed_event_sync(
        &conn,
        &account.identity,
        &rxn,
        &peer_shared_key,
    )?;

    writeln!(out, "Reacted {} to message {}", emoji, msg_num)?;

    Ok(())
}

fn cmd_reactions(
    session: &Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        writeln!(out, "Usage: reactions <msg-num>")?;
        return Ok(());
    }

    let msg_num: usize = args[0].parse().map_err(|_| "Invalid message number")?;

    let account = session.active_account().ok_or("No active account.")?;

    let conn = open_connection(&account.db_path)?;
    let target_event_id = get_message_event_id_by_num(&conn, &account.identity, msg_num)?;
    let target_b64 = event_id_to_base64(&target_event_id);

    let mut stmt = conn
        .prepare("SELECT emoji FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2")?;
    let emojis: Vec<String> = stmt
        .query_map(rusqlite::params![&account.identity, &target_b64], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    writeln!(out, "REACTIONS for message {}:", msg_num)?;
    if emojis.is_empty() {
        writeln!(out, "  (none)")?;
    } else {
        for emoji in &emojis {
            writeln!(out, "  {}", emoji)?;
        }
    }

    Ok(())
}

fn cmd_delete(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        writeln!(out, "Usage: delete <msg-num>")?;
        return Ok(());
    }

    let msg_num: usize = args[0].parse().map_err(|_| "Invalid message number")?;

    let account = session.active_account().ok_or("No active account.")?;

    let conn = open_connection(&account.db_path)?;
    let target_event_id = get_message_event_id_by_num(&conn, &account.identity, msg_num)?;

    let peer_shared_eid = account.peer_shared_event_id.ok_or("No signing key.")?;
    let peer_shared_key = account
        .peer_shared_key
        .as_ref()
        .ok_or("No signing key.")?
        .clone();
    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms: now_ms(),
        target_event_id,
        author_id: account.author_id,
        signed_by: peer_shared_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    create_signed_event_sync(
        &conn,
        &account.identity,
        &del,
        &peer_shared_key,
    )?;

    writeln!(out, "Deleted message {}", msg_num)?;

    Ok(())
}

fn cmd_invite(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    let workspace_key = account
        .workspace_key
        .as_ref()
        .ok_or("No workspace key. Only workspace creators can invite.")?
        .clone();
    let workspace_id = account.workspace_id.ok_or("No network event ID.")?;

    let conn = open_connection(&account.db_path)?;
    let invite =
        identity_ops::create_user_invite(&conn, &account.identity, &workspace_key, &workspace_id)?;
    let pending_spki = expected_invite_bootstrap_spki_from_invite_key(&invite.invite_key)?;
    crate::db::transport_trust::record_pending_invite_bootstrap_trust(
        &conn,
        &account.identity,
        &event_id_to_base64(&invite.invite_event_id),
        &event_id_to_base64(&workspace_id),
        &pending_spki,
    )?;

    let bootstrap_spki = decode_spki_hex(&account.identity)?;
    let bootstrap_addr = resolve_bootstrap_addr(args)?;
    let invite_link = create_invite_link(&invite, &bootstrap_addr, &bootstrap_spki)?;
    let invite_num = session.add_invite(invite_link.clone());

    writeln!(out, "Created invite #{}", invite_num)?;
    writeln!(out, "  link: {}", invite_link)?;

    Ok(())
}

/// In the interactive REPL all accounts live in one process — nobody is
/// running `poc-7 sync`.  This spins up a temporary QUIC sync endpoint for
/// the inviter's account so the joiner can connect and run a normal
/// negentropy sync session, exactly as it would against a real remote peer.
/// Returns the endpoint's bound address and a handle to close it afterward.
fn start_temp_sync_endpoint(
    inviter_db_path: &str,
    inviter_identity: &str,
    invite_key: &ed25519_dalek::SigningKey,
) -> Result<(std::net::SocketAddr, quinn::Endpoint), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use crate::transport::{create_dual_endpoint, AllowedPeers, DualConnection, peer_identity_from_connection};
    use crate::transport_identity::ensure_transport_cert;

    let conn = open_connection(inviter_db_path)?;
    let (_, cert, key) = ensure_transport_cert(&conn)?;

    // The joiner will present a cert derived from the invite key.
    let joiner_spki = expected_invite_bootstrap_spki_from_invite_key(invite_key)?;
    let allowed = Arc::new(AllowedPeers::from_fingerprints(vec![joiner_spki]));

    let endpoint = create_dual_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert,
        key,
        allowed,
    )?;
    let local_addr = endpoint.local_addr()?;

    let db_path = inviter_db_path.to_string();
    let recorded_by = inviter_identity.to_string();
    let ep = endpoint.clone();

    // Spawn on a separate thread with its own runtime because
    // run_sync_responder_dual uses non-Send types (rusqlite).
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create temp sync runtime");
        rt.block_on(async move {
            let connection = match ep.accept().await {
                Some(incoming) => match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Temp sync endpoint: connection failed: {}", e);
                        return;
                    }
                },
                None => return,
            };

            let peer_id = peer_identity_from_connection(&connection)
                .unwrap_or_default();

            // Accept 2 bi-directional streams (control + data)
            let (ctrl_send, ctrl_recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Temp sync endpoint: control stream failed: {}", e);
                    return;
                }
            };
            let (data_send, data_recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Temp sync endpoint: data stream failed: {}", e);
                    return;
                }
            };
            let conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

            if let Err(e) = crate::sync::engine::run_sync_responder_dual(
                conn, &db_path, 30, &peer_id, &recorded_by, None,
            ).await {
                tracing::warn!("Temp sync endpoint: sync error: {}", e);
            }
        });
    });

    Ok((local_addr, endpoint))
}

fn cmd_accept_invite(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let username = parse_named_arg(args, "--username").unwrap_or("user");
    let devicename = parse_named_arg(args, "--devicename").unwrap_or("device");
    let invite_ref = parse_named_arg(args, "--invite").unwrap_or("1");
    let (invite_link, invite_num) = match resolve_invite_ref(session, invite_ref) {
        Ok(v) => v,
        Err(e) => {
            writeln!(out, "{}", e)?;
            return Ok(());
        }
    };

    // Validate invite kind before creating account
    let invite = match parse_invite_link(&invite_link) {
        Ok(v) => v,
        Err(e) => {
            writeln!(out, "Invalid invite link: {}", e)?;
            return Ok(());
        }
    };
    if invite.kind != InviteLinkKind::User {
        writeln!(out, "This is not a user invite link.")?;
        writeln!(
            out,
            "  hint: use 'accept-link' for quiet://link/... invites"
        )?;
        return Ok(());
    }

    let workspace_id = invite.workspace_id;
    let inviter = session
        .accounts
        .iter()
        .find(|a| a.workspace_id == Some(workspace_id));
    let workspace_name = inviter.and_then(|a| a.workspace_name.clone());

    // If the inviter is in this session, start a temp sync endpoint so
    // the joiner can fetch prerequisite events via real QUIC.
    let invite_key = invite.invite_signing_key();
    let (effective_link, _temp_endpoint) = if let Some(inviter) = inviter {
        let (addr, ep) = start_temp_sync_endpoint(
            &inviter.db_path,
            &inviter.identity,
            &invite_key,
        )?;
        let rewritten = crate::invite_link::rewrite_bootstrap_addr(
            &invite_link,
            &addr.to_string(),
        )?;
        (rewritten, Some(ep))
    } else {
        (invite_link.clone(), None)
    };

    // Create account — svc_accept_invite will replace the random cert with a
    // deterministic one derived from the invite key (DELETE + INSERT).
    let mut account = Account::new(username, devicename);

    // Delegate to service layer: bootstrap sync + identity chain creation
    let result = tokio::task::block_in_place(|| {
        session.rt.block_on(crate::service::svc_accept_invite(
            &account.db_path,
            &effective_link,
            username,
            devicename,
        ))
    })
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("{}", e).into()
    })?;

    // Shut down temp sync endpoint if we started one
    if let Some(ep) = _temp_endpoint {
        ep.close(0u32.into(), b"bootstrap done");
    }

    // Update account state from service result
    account.identity = result.peer_id;
    account.workspace_id = Some(workspace_id);
    account.workspace_name = workspace_name;

    // Load keys from DB for interactive signing (service layer persisted them)
    let conn = open_connection(&account.db_path)?;
    if let Ok(Some((psf_eid, psf_key))) = crate::service::load_local_peer_signer_pub(&conn, &account.identity) {
        account.peer_shared_event_id = Some(psf_eid);
        account.peer_shared_key = Some(psf_key.clone());
        account
            .signing_keys
            .insert(event_id_to_base64(&psf_eid), psf_key);
    }

    let user_id = account.short_user_id();
    let peer_id = account.short_peer_id();
    session.accounts.push(account);
    session.active = session.accounts.len() - 1;
    let invite_label = invite_num
        .map(|n| format!("#{}", n))
        .unwrap_or_else(|| "link".to_string());

    writeln!(
        out,
        "Accepted invite {} as {} ({}) {} {}",
        invite_label, username, devicename, user_id, peer_id
    )?;

    Ok(())
}

fn cmd_link(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    let user_key = account.user_key.as_ref().ok_or("No user key.")?.clone();
    let user_event_id = account.user_event_id.ok_or("No user event ID.")?;
    let workspace_id = account.workspace_id.ok_or("No network event ID.")?;

    let conn = open_connection(&account.db_path)?;
    let invite = identity_ops::create_device_link_invite(
        &conn,
        &account.identity,
        &user_key,
        &user_event_id,
        &workspace_id,
    )?;
    let pending_spki = expected_invite_bootstrap_spki_from_invite_key(&invite.invite_key)?;
    crate::db::transport_trust::record_pending_invite_bootstrap_trust(
        &conn,
        &account.identity,
        &event_id_to_base64(&invite.invite_event_id),
        &event_id_to_base64(&workspace_id),
        &pending_spki,
    )?;

    let bootstrap_spki = decode_spki_hex(&account.identity)?;
    let bootstrap_addr = resolve_bootstrap_addr(args)?;
    let invite_link = create_invite_link(&invite, &bootstrap_addr, &bootstrap_spki)?;
    let invite_num = session.add_invite(invite_link.clone());

    writeln!(out, "Created device link invite #{}", invite_num)?;
    writeln!(out, "  link: {}", invite_link)?;

    Ok(())
}

fn cmd_accept_link(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let devicename = parse_named_arg(args, "--devicename").unwrap_or("device2");
    let invite_ref = parse_named_arg(args, "--invite").unwrap_or("1");
    let (invite_link, invite_num) = match resolve_invite_ref(session, invite_ref) {
        Ok(v) => v,
        Err(e) => {
            writeln!(out, "{}", e)?;
            return Ok(());
        }
    };
    let invite = match parse_invite_link(&invite_link) {
        Ok(v) => v,
        Err(e) => {
            writeln!(out, "Invalid invite link: {}", e)?;
            return Ok(());
        }
    };
    if invite.kind != InviteLinkKind::DeviceLink {
        writeln!(out, "This is not a device link invite.")?;
        writeln!(
            out,
            "  hint: use 'accept-invite' for quiet://invite/... links"
        )?;
        return Ok(());
    }

    let device_invite_key = invite.invite_signing_key();
    let device_invite_event_id = invite.invite_event_id;
    let workspace_id = invite.workspace_id;
    let inviter = session
        .accounts
        .iter()
        .find(|a| a.workspace_id == Some(workspace_id));
    let workspace_name = inviter.and_then(|a| a.workspace_name.clone());

    // Get the username from the inviting account for the device link.
    let username = match &invite.invite_type {
        InviteType::DeviceLink { .. } => {
            let mut found_name = "user".to_string();
            for acct in &session.accounts {
                if let InviteType::DeviceLink { user_event_id } = &invite.invite_type {
                    if acct.user_event_id == Some(*user_event_id) {
                        found_name = acct.user_name.clone();
                        break;
                    }
                }
            }
            found_name
        }
        InviteType::User => "user".to_string(),
    };

    // Start temp sync endpoint if inviter is in this session
    let (_effective_link, _temp_endpoint) = if let Some(inviter) = inviter {
        let (addr, ep) = start_temp_sync_endpoint(
            &inviter.db_path,
            &inviter.identity,
            &device_invite_key,
        )?;
        let rewritten = crate::invite_link::rewrite_bootstrap_addr(
            &invite_link,
            &addr.to_string(),
        )?;
        (rewritten, Some(ep))
    } else {
        (invite_link.clone(), None)
    };

    // Re-parse the effective link to get the updated bootstrap addr
    let effective_invite = parse_invite_link(&_effective_link)?;

    let mut account = Account::new(&username, devicename);
    account.identity =
        install_invite_bootstrap_transport_identity(&account.db_path, &device_invite_key)?;
    account.workspace_id = Some(workspace_id);
    account.workspace_name = workspace_name;

    // Bootstrap sync: fetch prerequisite events from inviter via real QUIC
    let bootstrap_addr: std::net::SocketAddr = effective_invite
        .bootstrap_addr
        .parse()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("Invalid bootstrap address: {}", e).into()
        })?;
    tokio::task::block_in_place(|| {
        session.rt.block_on(
            crate::sync::bootstrap::bootstrap_sync_from_invite(
                &account.db_path,
                &account.identity,
                bootstrap_addr,
                &effective_invite.bootstrap_spki_fingerprint,
                15,
            ),
        )
    })?;

    // Shut down temp sync endpoint
    if let Some(ep) = _temp_endpoint {
        ep.close(0u32.into(), b"bootstrap done");
    }

    let conn = open_connection(&account.db_path)?;

    let link = identity_ops::accept_device_link(
        &conn,
        &account.identity,
        &device_invite_key,
        &device_invite_event_id,
        workspace_id,
    )?;

    crate::db::transport_trust::record_invite_bootstrap_trust(
        &conn,
        &account.identity,
        &event_id_to_base64(&link.invite_accepted_event_id),
        &event_id_to_base64(&device_invite_event_id),
        &event_id_to_base64(&workspace_id),
        &invite.bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
    )?;

    account.store_link_keys(&link);

    let peer_id = account.short_peer_id();
    session.accounts.push(account);
    session.active = session.accounts.len() - 1;
    let invite_label = invite_num
        .map(|n| format!("#{}", n))
        .unwrap_or_else(|| "link".to_string());

    writeln!(
        out,
        "Accepted device link {} as {} ({}) {}",
        invite_label, username, devicename, peer_id
    )?;

    Ok(())
}

fn cmd_switch(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        writeln!(out, "Usage: switch <account-num>")?;
        return Ok(());
    }

    let num: usize = args[0].parse().map_err(|_| "Invalid account number")?;
    if num == 0 || num > session.accounts.len() {
        writeln!(
            out,
            "Invalid account number. Available: 1-{}",
            session.accounts.len()
        )?;
        return Ok(());
    }

    session.active = num - 1;
    let account = &session.accounts[session.active];
    writeln!(
        out,
        "Switched to account {}: {} ({})",
        num, account.user_name, account.device_name
    )?;

    Ok(())
}

fn cmd_accounts(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    writeln!(out, "ACCOUNTS:")?;
    if session.accounts.is_empty() {
        writeln!(out, "  (none)")?;
    } else {
        for (i, account) in session.accounts.iter().enumerate() {
            let marker = if i == session.active { "*" } else { " " };
            writeln!(
                out,
                "  {}{} {} ({}) - {}, {}",
                marker,
                i + 1,
                account.user_name,
                account.device_name,
                account.short_user_id(),
                account.short_peer_id()
            )?;
        }
    }

    Ok(())
}

fn cmd_channels(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let active_channel = session
        .active_account()
        .map(|a| a.active_channel)
        .unwrap_or([0u8; 32]);

    writeln!(out, "CHANNELS:")?;
    for (i, ch) in session.channels.iter().enumerate() {
        let marker = if ch.id == active_channel { "*" } else { " " };
        writeln!(out, "  {}{} #{}", marker, i + 1, ch.name)?;
    }

    Ok(())
}

fn cmd_new_channel(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        writeln!(out, "Usage: new-channel <name>")?;
        return Ok(());
    }

    let name = args.join(" ");
    let id: [u8; 32] = rand::random();

    session.channels.push(ChannelInfo {
        name: name.clone(),
        id,
    });

    let ch_num = session.channels.len();
    writeln!(out, "Created channel #{}: {}", ch_num, name)?;

    Ok(())
}

fn cmd_channel(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        writeln!(out, "Usage: channel <num>")?;
        return Ok(());
    }

    let num: usize = args[0].parse().map_err(|_| "Invalid channel number")?;
    if num == 0 || num > session.channels.len() {
        writeln!(
            out,
            "Invalid channel number. Available: 1-{}",
            session.channels.len()
        )?;
        return Ok(());
    }

    let channel_id = session.channels[num - 1].id;
    let channel_name = session.channels[num - 1].name.clone();

    if let Some(account) = session.active_account_mut() {
        account.active_channel = channel_id;
    }

    writeln!(out, "Switched to channel #{}: {}", num, channel_name)?;

    Ok(())
}

fn cmd_users(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    let conn = open_connection(&account.db_path)?;

    let mut stmt = conn.prepare("SELECT event_id, public_key FROM users WHERE recorded_by = ?1")?;
    let users: Vec<(String, Vec<u8>)> = stmt
        .query_map(rusqlite::params![&account.identity], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    writeln!(out, "USERS:")?;
    if users.is_empty() {
        writeln!(out, "  (none)")?;
    } else {
        for (i, (eid, _pubkey)) in users.iter().enumerate() {
            writeln!(out, "  {}. user_{}", i + 1, &eid[..8])?;
        }
    }

    Ok(())
}

fn cmd_keys(
    session: &Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    let summary = args.contains(&"--summary");
    let conn = open_connection(&account.db_path)?;

    if summary {
        let user_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
                rusqlite::params![&account.identity],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let peer_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
                rusqlite::params![&account.identity],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let admin_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
                rusqlite::params![&account.identity],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let transport_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
                rusqlite::params![&account.identity],
                |row| row.get(0),
            )
            .unwrap_or(0);

        writeln!(out, "KEYS SUMMARY:")?;
        writeln!(out, "  Users: {}", user_count)?;
        writeln!(out, "  Peers: {}", peer_count)?;
        writeln!(out, "  Admins: {}", admin_count)?;
        writeln!(out, "  TransportKeys: {}", transport_count)?;
    } else {
        writeln!(out, "KEYS:")?;

        // Users
        let mut stmt = conn.prepare("SELECT event_id FROM users WHERE recorded_by = ?1")?;
        let users: Vec<String> = stmt
            .query_map(rusqlite::params![&account.identity], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        writeln!(out, "  Users: {}", users.len())?;
        for eid in &users {
            writeln!(out, "    {}", &eid[..eid.len().min(12)])?;
        }

        // Peers
        let mut stmt = conn.prepare("SELECT event_id FROM peers_shared WHERE recorded_by = ?1")?;
        let peers: Vec<String> = stmt
            .query_map(rusqlite::params![&account.identity], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        writeln!(out, "  Peers: {}", peers.len())?;
        for eid in &peers {
            writeln!(out, "    {}", &eid[..eid.len().min(12)])?;
        }

        // Admins
        let mut stmt = conn.prepare("SELECT event_id FROM admins WHERE recorded_by = ?1")?;
        let admins: Vec<String> = stmt
            .query_map(rusqlite::params![&account.identity], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        writeln!(out, "  Admins: {}", admins.len())?;
        for eid in &admins {
            writeln!(out, "    {}", &eid[..eid.len().min(12)])?;
        }
    }

    Ok(())
}

fn cmd_workspaces(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    let conn = open_connection(&account.db_path)?;

    let mut stmt =
        conn.prepare("SELECT event_id, workspace_id FROM workspaces WHERE recorded_by = ?1")?;
    let workspaces: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![&account.identity], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    writeln!(out, "WORKSPACES:")?;
    if workspaces.is_empty() {
        writeln!(out, "  (none)")?;
    } else {
        let active_workspace_id = account.workspace_id.map(|id| event_id_to_base64(&id));
        for (i, (eid, workspace_id_b64)) in workspaces.iter().enumerate() {
            let label = if active_workspace_id.as_deref() == Some(workspace_id_b64.as_str()) {
                account
                    .workspace_name
                    .clone()
                    .unwrap_or_else(|| workspace_id_b64.clone())
            } else {
                workspace_id_b64.clone()
            };
            writeln!(out, "  {}. {} ({})", i + 1, label, &eid[..eid.len().min(8)])?;
        }
    }

    Ok(())
}

fn cmd_status(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    let conn = open_connection(&account.db_path)?;

    let events_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&account.identity],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let reactions_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![&account.identity],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Network name
    let network_name = account
        .workspace_name
        .clone()
        .or_else(|| account.workspace_id.map(|nid| event_id_to_base64(&nid)))
        .unwrap_or_else(|| "(none)".to_string());

    // Channel name
    let ch_name = session
        .channels
        .iter()
        .find(|c| c.id == account.active_channel)
        .map(|c| format!("#{}", c.name))
        .unwrap_or_else(|| "(none)".to_string());

    writeln!(out, "STATUS ({}):", account.user_name)?;
    writeln!(out, "  Events:    {}", events_count)?;
    writeln!(out, "  Messages:  {}", messages_count)?;
    writeln!(out, "  Reactions: {}", reactions_count)?;
    writeln!(out, "  Workspace: {}", network_name)?;
    writeln!(out, "  Channel:   {}", ch_name)?;

    Ok(())
}

fn cmd_identity(
    session: &Session,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let account = session.active_account().ok_or("No active account.")?;

    writeln!(out, "IDENTITY:")?;
    writeln!(out, "  Transport: {}", account.identity)?;
    writeln!(out, "  User: {}", account.short_user_id())?;
    writeln!(out, "  Peer: {}", account.short_peer_id())?;

    Ok(())
}

fn cmd_ban(
    session: &mut Session,
    args: &[&str],
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        writeln!(out, "Usage: ban <user-num>")?;
        return Ok(());
    }

    let user_num: usize = args[0].parse().map_err(|_| "Invalid user number")?;

    let account = session.active_account().ok_or("No active account.")?;

    let peer_shared_key = account
        .peer_shared_key
        .as_ref()
        .ok_or("No peer shared key.")?
        .clone();
    let peer_shared_event_id = account
        .peer_shared_event_id
        .ok_or("No peer shared event ID.")?;

    let conn = open_connection(&account.db_path)?;

    // Look up the user event by number
    let mut stmt = conn.prepare("SELECT event_id FROM users WHERE recorded_by = ?1")?;
    let users: Vec<String> = stmt
        .query_map(rusqlite::params![&account.identity], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if user_num == 0 || user_num > users.len() {
        writeln!(out, "Invalid user number. Available: 1-{}", users.len())?;
        return Ok(());
    }

    let target_eid_b64 = &users[user_num - 1];
    let target_event_id =
        crate::crypto::event_id_from_base64(target_eid_b64).ok_or("Invalid event ID")?;

    // Find peer_shared events associated with this user
    // For now, create UserRemoved targeting the user event
    let ur_evt = ParsedEvent::UserRemoved(UserRemovedEvent {
        created_at_ms: now_ms(),
        target_event_id,
        signed_by: peer_shared_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });
    create_signed_event_sync(
        &conn,
        &account.identity,
        &ur_evt,
        &peer_shared_key,
    )?;

    writeln!(out, "Banned user {}", user_num)?;

    Ok(())
}

fn cmd_help(out: &mut impl Write) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    writeln!(out, "COMMANDS:")?;
    writeln!(out)?;
    writeln!(out, "  Workspace setup:")?;
    writeln!(
        out,
        "    new-workspace --name <name> --username <username> --devicename <device>"
    )?;
    writeln!(out)?;
    writeln!(out, "  Joining/linking:")?;
    writeln!(
        out,
        "    invite --bootstrap <host:port>  Create invite for new user"
    )?;
    writeln!(
        out,
        "    accept-invite --username <name> --devicename <device> --invite <n|link>"
    )?;
    writeln!(
        out,
        "    link --bootstrap <host:port>    Create device link invite"
    )?;
    writeln!(
        out,
        "    accept-link --devicename <device> --invite <n|link>"
    )?;
    writeln!(out)?;
    writeln!(out, "  Account management:")?;
    writeln!(
        out,
        "    switch <n>                       Select account #n"
    )?;
    writeln!(
        out,
        "    accounts                         List all accounts"
    )?;
    writeln!(
        out,
        "    users                            List all users in workspace"
    )?;
    writeln!(
        out,
        "    identity                         Show identity info"
    )?;
    writeln!(out)?;
    writeln!(out, "  Channels:")?;
    writeln!(
        out,
        "    channel <n>                      Select channel #n"
    )?;
    writeln!(
        out,
        "    new-channel <name>               Create new channel"
    )?;
    writeln!(
        out,
        "    channels                         List all channels"
    )?;
    writeln!(out)?;
    writeln!(out, "  Messaging:")?;
    writeln!(out, "    send <message>                   Send message")?;
    writeln!(out, "    messages                         List messages")?;
    writeln!(
        out,
        "    delete <n>                       Delete message #n"
    )?;
    writeln!(
        out,
        "    react <n> <emoji>                React to message #n"
    )?;
    writeln!(
        out,
        "    reactions <n>                    Show reactions on message #n"
    )?;
    writeln!(out)?;
    writeln!(out, "  Admin:")?;
    writeln!(out, "    ban <n>                          Remove user #n")?;
    writeln!(out)?;
    writeln!(out, "  Other:")?;
    writeln!(
        out,
        "    keys [--summary]                 Show cryptographic keys"
    )?;
    writeln!(out, "    workspaces                       List workspaces")?;
    writeln!(
        out,
        "    status                           Show database stats"
    )?;
    writeln!(out, "    help                             Show this help")?;
    writeln!(out, "    quit                             Exit")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn get_message_event_id_by_num(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    msg_num: usize,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT message_id FROM messages WHERE recorded_by = ?1 ORDER BY created_at ASC, rowid ASC",
    )?;
    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if msg_num == 0 || msg_num > ids.len() {
        return Err(format!(
            "Invalid message number {}. Available: 1-{}",
            msg_num,
            ids.len()
        )
        .into());
    }

    crate::crypto::event_id_from_base64(&ids[msg_num - 1])
        .ok_or_else(|| format!("Invalid event ID for message {}", msg_num).into())
}

