use crate::crypto::event_id_to_base64;
use crate::projection::contract::ContextSnapshot;

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
