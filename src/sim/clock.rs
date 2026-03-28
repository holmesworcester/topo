#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct SimTime(pub u64);

impl SimTime {
    pub fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub fn millis(self) -> u64 {
        self.0
    }

    pub fn advance_by(self, delta_ms: u64) -> Self {
        Self(self.0.saturating_add(delta_ms))
    }
}
