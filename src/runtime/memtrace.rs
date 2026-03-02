use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Emit low-memory instrumentation to tracing and (optionally) an append-only file.
pub fn emit(line: &str, file_path: Option<&str>) {
    tracing::info!("{}", line);

    let Some(path) = file_path else {
        return;
    };

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{} {}", ts_ms, line);
    }
}
