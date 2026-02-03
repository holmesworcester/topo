use tracing::{debug, warn};

use crate::crypto::{hash_event, event_id_to_base64};
use crate::db::{incoming::IncomingQueue, shareable::Shareable, store::Store};
use crate::wire::{Envelope, ENVELOPE_SIZE};

/// Run ingest job once (for single-threaded operation)
pub fn ingest_once(db: &rusqlite::Connection, batch_size: usize) {
    let incoming = IncomingQueue::new(db);
    let store = Store::new(db);
    let shareable = Shareable::new(db);

    // Drain incoming queue
    let items = match incoming.drain(batch_size) {
        Ok(items) => items,
        Err(e) => {
            warn!("Failed to drain incoming: {}", e);
            return;
        }
    };

    if items.is_empty() {
        return;
    }

    debug!("Ingesting {} items", items.len());

    // Store each blob
    let mut store_batch = Vec::new();

    for item in &items {
        if item.blob.len() != ENVELOPE_SIZE {
            warn!("Invalid blob size: {}", item.blob.len());
            continue;
        }

        let event_id = hash_event(&item.blob);
        store_batch.push((event_id, item.blob.clone()));
    }

    // Batch writes
    if let Err(e) = store.put_batch(&store_batch) {
        warn!("Failed to store batch: {}", e);
    }

    // Insert into shareable
    for (event_id, _) in &store_batch {
        if let Err(e) = shareable.insert(event_id) {
            warn!("Failed to insert shareable: {}", e);
        }
    }

    debug!("Ingested {} events", items.len());
}

/// Run projection job once - parse events and write to messages table
pub fn project_once(db: &rusqlite::Connection, batch_size: usize) {
    // Get unprojected events (events in store but not in messages)
    let query = "
        SELECT s.id, s.blob FROM store s
        LEFT JOIN messages m ON s.id = m.message_id
        WHERE m.message_id IS NULL
        LIMIT ?1
    ";

    let mut stmt = match db.prepare(query) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to prepare projection query: {}", e);
            return;
        }
    };

    let rows: Vec<(String, Vec<u8>)> = match stmt.query_map([batch_size as i64], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            warn!("Failed to query unprojected events: {}", e);
            return;
        }
    };

    if rows.is_empty() {
        return;
    }

    debug!("Projecting {} events", rows.len());

    let mut insert_stmt = match db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to prepare insert statement: {}", e);
            return;
        }
    };

    for (message_id, blob) in rows {
        if blob.len() != ENVELOPE_SIZE {
            continue;
        }

        // Parse the envelope
        let (_, envelope) = match Envelope::parse(&blob) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let channel_id = event_id_to_base64(&envelope.payload.channel_id);
        let author_id = event_id_to_base64(&envelope.payload.author_id);
        let content = &envelope.payload.content;
        let created_at = envelope.payload.created_at_ms as i64;

        if let Err(e) = insert_stmt.execute(rusqlite::params![
            message_id,
            channel_id,
            author_id,
            content,
            created_at
        ]) {
            warn!("Failed to insert message: {}", e);
        }
    }

    debug!("Projected batch");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables, incoming::IncomingQueue};
    use crate::wire::Envelope;

    #[test]
    fn test_ingest_and_project() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Create a test event
        let envelope = Envelope::new_message(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            "Hello, world!".to_string(),
        );
        let blob = envelope.encode();

        // Add to incoming queue
        let incoming = IncomingQueue::new(&conn);
        incoming.push(&blob).unwrap();

        // Run ingest
        ingest_once(&conn, 100);

        // Verify event is in store
        let store = Store::new(&conn);
        let event_id = hash_event(&blob);
        assert!(store.exists(&event_id).unwrap());

        // Verify event is shareable
        let shareable = Shareable::new(&conn);
        assert_eq!(shareable.count().unwrap(), 1);

        // Run projection
        project_once(&conn, 100);

        // Verify message is projected
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages",
            [],
            |row| row.get(0)
        ).unwrap();
        assert_eq!(count, 1);

        // Verify content
        let content: String = conn.query_row(
            "SELECT content FROM messages LIMIT 1",
            [],
            |row| row.get(0)
        ).unwrap();
        assert_eq!(content, "Hello, world!");
    }
}
