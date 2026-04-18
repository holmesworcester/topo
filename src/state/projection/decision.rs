#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionDecision {
    Valid,
    BlockOnMissingDeps { missing: Vec<[u8; 32]> },
    Reject { reason: String },
    AlreadyProcessed,
}
