use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use crc32c::crc32c;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgo {
    Crc32c,
    Sha256,
    Both,
}

impl ChecksumAlgo {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "crc32c" => Some(Self::Crc32c),
            "sha256" => Some(Self::Sha256),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Crc32c => "crc32c",
            Self::Sha256 => "sha256",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Checksum {
    pub algo: ChecksumAlgo,
    pub value: Vec<u8>,
}

impl Checksum {
    pub fn compute(algo: ChecksumAlgo, data: &[u8]) -> Self {
        let value = compute_value(algo, data);
        Self { algo, value }
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Self::compute(self.algo, data);
        computed.value == self.value
    }

    pub fn to_base64(&self) -> String {
        Base64.encode(&self.value)
    }
}

fn compute_value(algo: ChecksumAlgo, data: &[u8]) -> Vec<u8> {
    match algo {
        ChecksumAlgo::Crc32c => crc32c(data).to_be_bytes().to_vec(),
        ChecksumAlgo::Sha256 => compute_sha256(data),
        ChecksumAlgo::Both => {
            let mut combined = crc32c(data).to_be_bytes().to_vec();
            combined.extend_from_slice(&compute_sha256(data));
            combined
        }
    }
}

fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn parse_checksum(algo: &str, value_b64: &str) -> Result<Checksum, String> {
    let algo = ChecksumAlgo::parse(algo).ok_or_else(|| "invalid checksum algo".to_string())?;
    let value = Base64
        .decode(value_b64.as_bytes())
        .map_err(|_| "invalid checksum value")?;
    Ok(Checksum { algo, value })
}

#[cfg(test)]
mod tests {
    use super::{parse_checksum, Checksum, ChecksumAlgo};

    #[test]
    fn checksum_verify_crc32c() {
        let data = b"hello world";
        let checksum = Checksum::compute(ChecksumAlgo::Crc32c, data);
        assert_eq!(checksum.value.len(), 4);
        assert!(checksum.verify(data));
        assert!(!checksum.verify(b"hello world!"));
    }

    #[test]
    fn checksum_verify_sha256() {
        let data = b"hello world";
        let checksum = Checksum::compute(ChecksumAlgo::Sha256, data);
        assert_eq!(checksum.value.len(), 32);
        assert!(checksum.verify(data));
        assert!(!checksum.verify(b"hello world!"));
    }

    #[test]
    fn checksum_verify_both() {
        let data = b"hello world";
        let checksum = Checksum::compute(ChecksumAlgo::Both, data);
        assert_eq!(checksum.value.len(), 36);
        assert!(checksum.verify(data));
        assert!(!checksum.verify(b"hello world!"));
    }

    #[test]
    fn parse_checksum_roundtrip() {
        let data = b"hello world";
        let checksum = Checksum::compute(ChecksumAlgo::Sha256, data);
        let encoded = checksum.to_base64();
        let parsed = parse_checksum(checksum.algo.as_str(), &encoded).expect("parse checksum");
        assert!(parsed.verify(data));
    }

    #[test]
    fn checksum_algo_parses_and_formats_all_variants() {
        assert_eq!(ChecksumAlgo::parse("crc32c"), Some(ChecksumAlgo::Crc32c));
        assert_eq!(ChecksumAlgo::parse("both"), Some(ChecksumAlgo::Both));
        assert_eq!(ChecksumAlgo::parse("unknown"), None);
        assert_eq!(ChecksumAlgo::Crc32c.as_str(), "crc32c");
        assert_eq!(ChecksumAlgo::Both.as_str(), "both");
    }

    #[test]
    fn parse_checksum_rejects_invalid_inputs() {
        let err = parse_checksum("invalid", "aaaa").unwrap_err();
        assert_eq!(err, "invalid checksum algo");

        let err = parse_checksum("sha256", "not-base64").unwrap_err();
        assert_eq!(err, "invalid checksum value");
    }
}
