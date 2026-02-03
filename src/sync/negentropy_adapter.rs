//! Negentropy storage adapter for loading items from SQLite

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::{Connection, params};

use crate::crypto::{event_id_from_base64, EventId};
use crate::db::store::Store;
use crate::wire::Envelope;

/// A negentropy item: (timestamp, event_id)
#[derive(Debug, Clone)]
pub struct NegentropyItem {
    pub timestamp: u64,
    pub id: EventId,
}

/// Load all shareable events as negentropy items
/// Uses the event's created_at timestamp from the blob for cross-peer consistency
pub fn load_negentropy_items(conn: &Connection) -> Result<Vec<NegentropyItem>, rusqlite::Error> {
    let store = Store::new(conn);

    let mut stmt = conn.prepare(
        "SELECT id FROM shareable_events ORDER BY stored_at, id"
    )?;

    let rows = stmt.query_map([], |row| {
        let id_str: String = row.get(0)?;
        Ok(id_str)
    })?;

    let mut items = Vec::new();
    for row in rows {
        let id_str = row?;
        if let Some(event_id) = event_id_from_base64(&id_str) {
            // Get the blob to extract the created_at timestamp
            if let Ok(Some(blob)) = store.get(&event_id) {
                if let Some(timestamp) = Envelope::extract_created_at(&blob) {
                    items.push(NegentropyItem {
                        timestamp,
                        id: event_id,
                    });
                }
            }
        }
    }

    // Sort by (timestamp, id) for negentropy
    items.sort_by(|a, b| {
        a.timestamp.cmp(&b.timestamp)
            .then_with(|| a.id.cmp(&b.id))
    });

    Ok(items)
}

/// Build a NegentropyStorageVector from items
pub fn build_negentropy_storage(items: &[NegentropyItem]) -> Result<NegentropyStorageVector, negentropy::Error> {
    let mut storage = NegentropyStorageVector::with_capacity(items.len());

    for item in items {
        let id = Id::from_byte_array(item.id);
        storage.insert(item.timestamp, id)?;
    }

    storage.seal()?;
    Ok(storage)
}

/// Convert negentropy Id to our EventId
pub fn neg_id_to_event_id(id: &Id) -> EventId {
    *id.as_bytes()
}

/// Convert our EventId to negentropy Id
pub fn event_id_to_neg_id(id: &EventId) -> Id {
    Id::from_byte_array(*id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables, shareable::Shareable};
    use crate::wire::Envelope;

    #[test]
    fn test_load_negentropy_items() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let store = Store::new(&conn);
        let shareable = Shareable::new(&conn);

        // Create some test events
        for i in 0..5 {
            let envelope = Envelope::new_message(
                [i as u8; 32],
                [1u8; 32],
                [2u8; 32],
                None,
                format!("Test message {}", i),
            );
            let blob = envelope.encode();
            let event_id = hash_event(&blob);

            store.put(&event_id, &blob).unwrap();
            shareable.insert(&event_id, None).unwrap();
        }

        let items = load_negentropy_items(&conn).unwrap();
        assert_eq!(items.len(), 5);

        // Verify items are sorted
        for i in 1..items.len() {
            let prev = &items[i - 1];
            let curr = &items[i];
            assert!(
                (prev.timestamp, &prev.id) <= (curr.timestamp, &curr.id),
                "Items should be sorted by (timestamp, id)"
            );
        }
    }

    #[test]
    fn test_build_negentropy_storage() {
        use negentropy::NegentropyStorageBase;

        let items = vec![
            NegentropyItem { timestamp: 1000, id: [1u8; 32] },
            NegentropyItem { timestamp: 2000, id: [2u8; 32] },
            NegentropyItem { timestamp: 3000, id: [3u8; 32] },
        ];

        let storage = build_negentropy_storage(&items).unwrap();
        // Storage should be sealed and ready for use
        assert!(storage.size().unwrap() == 3);
    }

    #[test]
    fn test_id_conversion() {
        let event_id: EventId = [42u8; 32];
        let neg_id = event_id_to_neg_id(&event_id);
        let back = neg_id_to_event_id(&neg_id);
        assert_eq!(event_id, back);
    }
}
