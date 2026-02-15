use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaSubMode {
    Delivery,
    Backup,
    Volume,
}

impl ReplicaSubMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "delivery" | "slave-delivery" => Some(Self::Delivery),
            "backup" | "slave-backup" => Some(Self::Backup),
            "volume" | "slave-volume" => Some(Self::Volume),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivery => "delivery",
            Self::Backup => "backup",
            Self::Volume => "volume",
        }
    }

    pub fn as_node_mode(self) -> &'static str {
        match self {
            Self::Delivery => "slave-delivery",
            Self::Backup => "slave-backup",
            Self::Volume => "slave-volume",
        }
    }

    pub fn allows_client_reads(self) -> bool {
        self == Self::Delivery
    }

    fn as_code(self) -> u8 {
        match self {
            Self::Delivery => 0,
            Self::Backup => 1,
            Self::Volume => 2,
        }
    }

    fn from_code(value: u8) -> Self {
        if value == Self::Volume.as_code() {
            return Self::Volume;
        }
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
            ReplicaSubMode::parse("slave-delivery"),
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
        assert_eq!(
            ReplicaSubMode::parse("slave-volume"),
            Some(ReplicaSubMode::Volume)
        );
        assert_eq!(
            ReplicaSubMode::parse("volume"),
            Some(ReplicaSubMode::Volume)
        );
        assert_eq!(ReplicaSubMode::parse("bad"), None);
    }

    #[test]
    fn state_reads_and_writes_modes() {
        let state = ReplicaModeState::new(ReplicaSubMode::Delivery);
        assert_eq!(state.get().as_str(), "delivery");
        state.set(ReplicaSubMode::Backup);
        assert_eq!(state.get().as_str(), "backup");
        state.set(ReplicaSubMode::Volume);
        assert_eq!(state.get().as_node_mode(), "slave-volume");
    }

    #[test]
    fn only_delivery_mode_allows_client_reads() {
        assert!(ReplicaSubMode::Delivery.allows_client_reads());
        assert!(!ReplicaSubMode::Backup.allows_client_reads());
        assert!(!ReplicaSubMode::Volume.allows_client_reads());
    }

    #[test]
    fn mode_string_helpers_cover_all_variants() {
        assert_eq!(ReplicaSubMode::Delivery.as_node_mode(), "slave-delivery");
        assert_eq!(ReplicaSubMode::Backup.as_node_mode(), "slave-backup");
        assert_eq!(ReplicaSubMode::Volume.as_str(), "volume");
    }
}
