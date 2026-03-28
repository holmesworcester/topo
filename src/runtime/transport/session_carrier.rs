use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// Transport connection operations needed by session setup.
#[async_trait]
pub trait SessionCarrier: Clone + Send + Sync + 'static {
    type BiSend: AsyncWrite + Unpin + Send + 'static;
    type BiRecv: AsyncRead + Unpin + Send + 'static;

    async fn open_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String>;
    async fn accept_bi(&self) -> Result<(Self::BiSend, Self::BiRecv), String>;
    fn close_with_reason(&self, error_code: u32, reason: &[u8]);
}
