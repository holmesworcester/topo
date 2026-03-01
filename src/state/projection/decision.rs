#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionDecision {
    Valid,
    Block { missing: Vec<[u8; 32]> },
    Reject { reason: String },
    AlreadyProcessed,
}
