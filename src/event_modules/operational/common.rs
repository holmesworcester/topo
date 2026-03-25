use std::ops::Range;

use super::super::layout::common::{read_text_slot, write_text_slot};
use super::super::EventError;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::ContextSnapshot;

pub(crate) fn expect_wire(
    blob: &[u8],
    expected_type: u8,
    expected_len: usize,
) -> Result<(), EventError> {
    if blob.len() < expected_len {
        return Err(EventError::TooShort {
            expected: expected_len,
            actual: blob.len(),
        });
    }
    if blob.len() > expected_len {
        return Err(EventError::TrailingData {
            expected: expected_len,
            actual: blob.len(),
        });
    }
    if blob.first().copied() != Some(expected_type) {
        return Err(EventError::WrongType {
            expected: expected_type,
            actual: blob.first().copied().unwrap_or_default(),
        });
    }
    Ok(())
}

pub(crate) fn read_created_at_ms(blob: &[u8], created_at_range: Range<usize>) -> u64 {
    u64::from_le_bytes(blob[created_at_range].try_into().unwrap())
}

pub(crate) fn write_header(
    buf: &mut [u8],
    type_code: u8,
    created_at_range: Range<usize>,
    created_at_ms: u64,
) {
    buf[0] = type_code;
    buf[created_at_range].copy_from_slice(&created_at_ms.to_le_bytes());
}

pub(crate) fn fresh_blob(
    type_code: u8,
    wire_size: usize,
    created_at_range: Range<usize>,
    created_at_ms: u64,
) -> Vec<u8> {
    let mut buf = vec![0u8; wire_size];
    write_header(&mut buf, type_code, created_at_range, created_at_ms);
    buf
}

pub(crate) fn read_text(slot: &[u8]) -> Result<String, EventError> {
    read_text_slot(slot).map_err(EventError::TextSlot)
}

pub(crate) fn read_optional_text(slot: &[u8]) -> Result<Option<String>, EventError> {
    let raw = read_text(slot)?;
    if raw.is_empty() {
        Ok(None)
    } else {
        Ok(Some(raw))
    }
}

pub(crate) fn write_text(slot: &mut [u8], value: &str) -> Result<(), EventError> {
    write_text_slot(value, slot).map_err(EventError::TextSlot)
}

pub(crate) fn write_optional_text(slot: &mut [u8], value: Option<&str>) -> Result<(), EventError> {
    write_text(slot, value.unwrap_or(""))
}

pub(crate) fn read_event_id(slot: &[u8]) -> [u8; 32] {
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(slot);
    event_id
}

pub(crate) fn write_event_id(slot: &mut [u8], event_id: &[u8; 32]) {
    slot.copy_from_slice(event_id);
}

pub(crate) fn read_u64(slot: &[u8]) -> u64 {
    u64::from_le_bytes(slot.try_into().unwrap())
}

pub(crate) fn write_u64(slot: &mut [u8], value: u64) {
    slot.copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn read_i64(slot: &[u8]) -> i64 {
    i64::from_le_bytes(slot.try_into().unwrap())
}

pub(crate) fn write_i64(slot: &mut [u8], value: i64) {
    slot.copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn read_optional_i64(slot: &[u8], none_sentinel: i64) -> Option<i64> {
    let value = read_i64(slot);
    (value != none_sentinel).then_some(value)
}

pub(crate) fn write_optional_i64(slot: &mut [u8], value: Option<i64>, none_sentinel: i64) {
    write_i64(slot, value.unwrap_or(none_sentinel));
}

pub(crate) fn read_flag(blob: &[u8], idx: usize) -> bool {
    blob[idx] != 0
}

pub(crate) fn write_flag(blob: &mut [u8], idx: usize, value: bool) {
    blob[idx] = value as u8;
}

pub(crate) fn build_client_state_basis_context(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    basis_event_id: &[u8; 32],
    event_name: &str,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let basis_event_id_b64 = event_id_to_base64(basis_event_id);
    let Some(snapshot) =
        super::client_lifecycle::load_snapshot_by_event_id(conn, recorded_by, &basis_event_id_b64)?
    else {
        return Ok(ContextSnapshot::default());
    };
    let latest = super::client_lifecycle::load_state(conn, recorded_by)?;
    let mut ctx = ContextSnapshot::default();
    ctx.client_runtime_snapshot = Some(snapshot.snapshot());
    if let Some(latest) = latest {
        if latest.latest_event_id != basis_event_id_b64 {
            ctx.client_runtime_basis_mismatch_reason = Some(format!(
                "{event_name} basis_event_id {} is stale; latest client event is {}",
                basis_event_id_b64, latest.latest_event_id
            ));
        }
    }
    Ok(ctx)
}

pub(crate) fn build_client_run_basis_context(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    basis_event_id: &[u8; 32],
    event_name: &str,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let basis_event_id_b64 = event_id_to_base64(basis_event_id);
    let Some(snapshot) =
        super::client_lifecycle::load_snapshot_by_event_id(conn, recorded_by, &basis_event_id_b64)?
    else {
        return Ok(ContextSnapshot::default());
    };
    let latest = super::client_lifecycle::load_run(conn, recorded_by, &snapshot.run_id)?;
    let mut ctx = ContextSnapshot::default();
    ctx.client_runtime_snapshot = latest.as_ref().map(|row| row.snapshot());
    if let Some(latest) = latest {
        if latest.latest_event_id != basis_event_id_b64 {
            ctx.client_runtime_basis_mismatch_reason = Some(format!(
                "{event_name} basis_event_id {} is stale; latest run event is {}",
                basis_event_id_b64, latest.latest_event_id
            ));
        }
    }
    Ok(ctx)
}

pub(crate) fn build_connection_plan_basis_context(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    basis_event_id: &[u8; 32],
    event_name: &str,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let basis_event_id_b64 = event_id_to_base64(basis_event_id);
    let Some(snapshot) = super::connection_planned::load_snapshot_by_event_id(
        conn,
        recorded_by,
        &basis_event_id_b64,
    )?
    else {
        return Ok(ContextSnapshot::default());
    };
    let latest = super::connection_planned::load(conn, &snapshot.connection_id)?;
    let mut ctx = ContextSnapshot::default();
    ctx.connection_plan_snapshot = latest.as_ref().map(|row| row.snapshot());
    if let Some(latest) = latest {
        if latest.latest_event_id != basis_event_id_b64 {
            ctx.connection_plan_basis_mismatch_reason = Some(format!(
                "{event_name} basis_event_id {} is stale; latest plan event is {}",
                basis_event_id_b64, latest.latest_event_id
            ));
        }
    }
    Ok(ctx)
}

pub(crate) fn build_inbound_connection_basis_context(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    basis_event_id: &[u8; 32],
    event_name: &str,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let basis_event_id_b64 = event_id_to_base64(basis_event_id);
    let Some(snapshot) = super::inbound_connection_authenticated::load_snapshot_by_event_id(
        conn,
        recorded_by,
        &basis_event_id_b64,
    )?
    else {
        return Ok(ContextSnapshot::default());
    };
    let latest =
        super::inbound_connection_authenticated::load(conn, recorded_by, &snapshot.connection_id)?;
    let mut ctx = ContextSnapshot::default();
    ctx.inbound_connection_snapshot = latest.as_ref().map(|row| row.snapshot());
    if let Some(latest) = latest {
        if latest.latest_event_id != basis_event_id_b64 {
            ctx.inbound_connection_basis_mismatch_reason = Some(format!(
                "{event_name} basis_event_id {} is stale; latest inbound event is {}",
                basis_event_id_b64, latest.latest_event_id
            ));
        }
    }
    Ok(ctx)
}

pub(crate) fn build_sync_round_basis_context(
    conn: &rusqlite::Connection,
    recorded_by: &str,
    basis_event_id: &[u8; 32],
    event_name: &str,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let basis_event_id_b64 = event_id_to_base64(basis_event_id);
    let Some(snapshot) = super::sync_round_started::load_snapshot_by_event_id(
        conn,
        recorded_by,
        &basis_event_id_b64,
    )?
    else {
        return Ok(ContextSnapshot::default());
    };
    let latest = super::sync_round_started::load_round(conn, recorded_by, &snapshot.round_id)?;
    let mut ctx = ContextSnapshot::default();
    ctx.sync_round_snapshot = Some(snapshot.snapshot());
    if let Some(latest) = latest {
        if latest.latest_event_id != basis_event_id_b64 {
            ctx.sync_round_basis_mismatch_reason = Some(format!(
                "{event_name} basis_event_id {} is stale; latest round event is {}",
                basis_event_id_b64, latest.latest_event_id
            ));
        }
    }
    Ok(ctx)
}
