use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaSubMode {
    Delivery,
    Backup,
}

impl ReplicaSubMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "delivery" => Some(Self::Delivery),
            "backup" => Some(Self::Backup),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivery => "delivery",
            Self::Backup => "backup",
        }
    }

    fn as_code(self) -> u8 {
        match self {
            Self::Delivery => 0,
            Self::Backup => 1,
        }
    }

    fn from_code(value: u8) -> Self {
        if value == Self::Backup.as_code() {
            return Self::Backup;
        }
        Self::Delivery
    }
}

#[derive(Clone)]
pub struct ReplicaModeState {
    inner: Arc<AtomicU8>,
}

impl ReplicaModeState {
    pub fn new(initial: ReplicaSubMode) -> Self {
        Self {
            inner: Arc::new(AtomicU8::new(initial.as_code())),
        }
    }

    pub fn get(&self) -> ReplicaSubMode {
        ReplicaSubMode::from_code(self.inner.load(Ordering::Relaxed))
    }

    pub fn set(&self, mode: ReplicaSubMode) {
        self.inner.store(mode.as_code(), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplicaModeState, ReplicaSubMode};

    #[test]
    fn parse_mode_variants() {
        assert_eq!(
            ReplicaSubMode::parse("delivery"),
            Some(ReplicaSubMode::Delivery)
        );
        assert_eq!(
            ReplicaSubMode::parse("backup"),
            Some(ReplicaSubMode::Backup)
        );
        assert_eq!(
            ReplicaSubMode::parse("BACKUP"),
            Some(ReplicaSubMode::Backup)
        );
        assert_eq!(ReplicaSubMode::parse("bad"), None);
    }

    #[test]
    fn state_reads_and_writes_modes() {
        let state = ReplicaModeState::new(ReplicaSubMode::Delivery);
        assert_eq!(state.get().as_str(), "delivery");
        state.set(ReplicaSubMode::Backup);
        assert_eq!(state.get().as_str(), "backup");
    }
}
