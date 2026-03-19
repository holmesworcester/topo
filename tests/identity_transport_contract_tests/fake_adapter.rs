//! Fake `TransportIdentityMaterializer` for testing spec emission without
//! real cert/key materialisation.

use std::cell::RefCell;

use rusqlite::Connection;
use topo::contracts::transport_identity_contract::{
    TransportIdentityError, TransportIdentityMaterializer, TransportIdentitySpec,
};

/// Records specs applied through the materializer for later assertion.
pub struct FakeTransportIdentityMaterializer {
    intents: RefCell<Vec<TransportIdentitySpec>>,
    /// Fixed peer_id to return from materialize.
    pub return_peer_id: String,
}

impl FakeTransportIdentityMaterializer {
    pub fn new(return_peer_id: &str) -> Self {
        Self {
            intents: RefCell::new(Vec::new()),
            return_peer_id: return_peer_id.to_string(),
        }
    }

    pub fn applied_intents(&self) -> Vec<TransportIdentitySpec> {
        self.intents.borrow().clone()
    }
}

impl TransportIdentityMaterializer for FakeTransportIdentityMaterializer {
    fn materialize(
        &self,
        _conn: &Connection,
        spec: TransportIdentitySpec,
    ) -> Result<String, TransportIdentityError> {
        self.intents.borrow_mut().push(spec);
        Ok(self.return_peer_id.clone())
    }
}
