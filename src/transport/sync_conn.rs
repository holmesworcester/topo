use async_trait::async_trait;

use crate::sync::SyncMessage;
use crate::transport::connection::ConnectionError;

#[async_trait]
pub trait SyncConnection: Send {
    async fn send(&mut self, msg: &SyncMessage) -> Result<(), ConnectionError>;
    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError>;
    async fn flush(&mut self) -> Result<(), ConnectionError>;
    async fn recv(&mut self) -> Result<SyncMessage, ConnectionError>;
}
