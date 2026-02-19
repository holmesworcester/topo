//! Fake TransportIdentityAdapter for testing intent emission without
//! real cert/key materialisation.

use std::cell::RefCell;

use rusqlite::Connection;
use topo::contracts::transport_identity_contract::{
    TransportIdentityAdapter, TransportIdentityError, TransportIdentityIntent,
};

/// Records intents applied through the adapter for later assertion.
pub struct FakeTransportIdentityAdapter {
    intents: RefCell<Vec<TransportIdentityIntent>>,
    /// Fixed peer_id to return from apply_intent.
    pub return_peer_id: String,
}

impl FakeTransportIdentityAdapter {
    pub fn new(return_peer_id: &str) -> Self {
        Self {
            intents: RefCell::new(Vec::new()),
            return_peer_id: return_peer_id.to_string(),
        }
    }

    pub fn applied_intents(&self) -> Vec<TransportIdentityIntent> {
        self.intents.borrow().clone()
    }
}

impl TransportIdentityAdapter for FakeTransportIdentityAdapter {
    fn apply_intent(
        &self,
        _conn: &Connection,
        intent: TransportIdentityIntent,
    ) -> Result<String, TransportIdentityError> {
        self.intents.borrow_mut().push(intent);
        Ok(self.return_peer_id.clone())
    }
}
