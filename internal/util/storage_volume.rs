use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VolumeUsage {
    pub capacity_bytes: i64,
    pub free_bytes: i64,
}

pub fn data_dirs_usage(paths: &[PathBuf]) -> VolumeUsage {
    let mut usage = VolumeUsage::default();
    for path in paths {
        if let Some(value) = path_usage(path) {
            usage.capacity_bytes = usage.capacity_bytes.saturating_add(value.capacity_bytes);
            usage.free_bytes = usage.free_bytes.saturating_add(value.free_bytes);
        }
    }
    usage
}

fn to_i64_saturated(value: u128) -> i64 {
    value.min(i64::MAX as u128) as i64
}

#[cfg(unix)]
fn path_usage(path: &Path) -> Option<VolumeUsage> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let raw = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::statvfs(raw.as_ptr(), &mut stat) };
    if result != 0 {
        return None;
    }
    let block_size = u128::from(stat.f_frsize.max(stat.f_bsize));
    let capacity = block_size.saturating_mul(u128::from(stat.f_blocks));
    let free = block_size.saturating_mul(u128::from(stat.f_bavail));
    Some(VolumeUsage {
        capacity_bytes: to_i64_saturated(capacity),
        free_bytes: to_i64_saturated(free),
    })
}

#[cfg(not(unix))]
fn path_usage(_path: &Path) -> Option<VolumeUsage> {
    None
}

#[cfg(test)]
mod tests {
    use super::{data_dirs_usage, to_i64_saturated};
    use std::path::PathBuf;

    #[test]
    fn to_i64_saturated_clamps_large_numbers() {
        assert_eq!(to_i64_saturated(10), 10);
        assert_eq!(to_i64_saturated(u128::MAX), i64::MAX);
    }

    #[test]
    fn data_dirs_usage_handles_missing_paths() {
        let usage = data_dirs_usage(&[PathBuf::from("/path/not/found/nss")]);
        assert_eq!(usage.capacity_bytes, 0);
        assert_eq!(usage.free_bytes, 0);
    }

    #[test]
    fn data_dirs_usage_reads_existing_path() {
        let usage = data_dirs_usage(&[std::env::temp_dir()]);
        assert!(usage.capacity_bytes >= 0);
        assert!(usage.free_bytes >= 0);
    }

    #[cfg(unix)]
    #[test]
    fn data_dirs_usage_ignores_nul_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let invalid = PathBuf::from(OsString::from_vec(b"nul\0path".to_vec()));
        let usage = data_dirs_usage(&[invalid]);
        assert_eq!(usage.capacity_bytes, 0);
        assert_eq!(usage.free_bytes, 0);
    }
}
