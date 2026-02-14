use crate::util::config::Config;
use crate::util::crypto;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;

const ENVELOPE_MAGIC: &[u8] = b"NSSCHNK1";
const DEFAULT_ACTIVE_KEY_ID: &str = "default";

const ENV_ENABLED: &str = "NSS_CHUNK_ENCRYPTION_ENABLED";
const ENV_ALLOW_PLAINTEXT_READ: &str = "NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ";
const ENV_ACTIVE_KEY_ID: &str = "NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID";
const ENV_KEYS: &str = "NSS_CHUNK_ENCRYPTION_KEYS";
const ENV_KEY_BASE64: &str = "NSS_CHUNK_ENCRYPTION_KEY_BASE64";

#[derive(Clone, Debug)]
pub struct ChunkEncryption {
    active_key_id: String,
    keys: Arc<HashMap<String, Vec<u8>>>,
    allow_plaintext_read: bool,
}

pub fn load_chunk_encryption(config: &Config) -> Result<Option<ChunkEncryption>, String> {
    if !parse_bool_env(ENV_ENABLED, true)? {
        return Ok(None);
    }
    let active_key_id = env_or_default(ENV_ACTIVE_KEY_ID, DEFAULT_ACTIVE_KEY_ID);
    let allow_plaintext_read = parse_bool_env(ENV_ALLOW_PLAINTEXT_READ, true)?;
    let keys = parse_keyring(config, &active_key_id)?;
    Ok(Some(ChunkEncryption {
        active_key_id,
        keys: Arc::new(keys),
        allow_plaintext_read,
    }))
}

impl ChunkEncryption {
    pub fn new(
        active_key_id: String,
        keys: HashMap<String, Vec<u8>>,
        allow_plaintext_read: bool,
    ) -> Result<Self, String> {
        if keys.is_empty() {
            return Err("chunk encryption keys must not be empty".into());
        }
        if !keys.contains_key(&active_key_id) {
            return Err(format!(
                "chunk encryption active key '{active_key_id}' not found in keyring"
            ));
        }
        Ok(Self {
            active_key_id,
            keys: Arc::new(keys),
            allow_plaintext_read,
        })
    }

    pub fn is_envelope(payload: &[u8]) -> bool {
        payload.starts_with(ENVELOPE_MAGIC)
    }

    pub fn allow_plaintext_read(&self) -> bool {
        self.allow_plaintext_read
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.active_key()?;
        let ciphertext = crypto::encrypt_secret(key, plaintext)?;
        encode_envelope(&self.active_key_id, &ciphertext)
    }

    pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let envelope = parse_envelope(payload)?;
        let key = self.resolve_key(envelope.key_id)?;
        crypto::decrypt_secret(key, envelope.ciphertext)
    }

    fn active_key(&self) -> Result<&[u8], String> {
        self.resolve_key(&self.active_key_id)
    }

    fn resolve_key(&self, key_id: &str) -> Result<&[u8], String> {
        self.keys
            .get(key_id)
            .map(|key| key.as_slice())
            .ok_or_else(|| format!("chunk encryption key '{key_id}' not found"))
    }
}

#[derive(Debug)]
struct ChunkEnvelope<'a> {
    key_id: &'a str,
    ciphertext: &'a [u8],
}

fn parse_keyring(config: &Config, active_key_id: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    if let Some(raw_keys) = read_optional_env(ENV_KEYS) {
        let keys = parse_keyring_entries(&raw_keys)?;
        if !keys.contains_key(active_key_id) {
            return Err(format!(
                "chunk encryption active key '{active_key_id}' not found in {ENV_KEYS}"
            ));
        }
        return Ok(keys);
    }
    if let Some(raw_key) = read_optional_env(ENV_KEY_BASE64) {
        let key = decode_32_byte_key(ENV_KEY_BASE64, &raw_key)?;
        let mut keys = HashMap::new();
        keys.insert(active_key_id.to_string(), key);
        return Ok(keys);
    }
    let mut keys = HashMap::new();
    keys.insert(
        active_key_id.to_string(),
        config.secret_encryption_key.clone(),
    );
    Ok(keys)
}

fn parse_keyring_entries(raw_keys: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let mut keys = HashMap::new();
    for entry in raw_keys
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (key_id, key) = parse_keyring_entry(entry)?;
        if keys.insert(key_id.clone(), key).is_some() {
            return Err(format!("duplicate chunk encryption key id '{key_id}'"));
        }
    }
    if keys.is_empty() {
        return Err(format!("{ENV_KEYS} must contain at least one key entry"));
    }
    Ok(keys)
}

fn parse_keyring_entry(entry: &str) -> Result<(String, Vec<u8>), String> {
    let (key_id_raw, key_raw) = entry
        .split_once(':')
        .ok_or_else(|| format!("invalid {ENV_KEYS} entry '{entry}'; expected key_id:base64_key"))?;
    let key_id = key_id_raw.trim();
    if key_id.is_empty() {
        return Err(format!(
            "invalid {ENV_KEYS} entry '{entry}'; key id is empty"
        ));
    }
    let key = decode_32_byte_key(ENV_KEYS, key_raw.trim())?;
    Ok((key_id.to_string(), key))
}

fn decode_32_byte_key(label: &str, raw: &str) -> Result<Vec<u8>, String> {
    let decoded = Base64
        .decode(raw.as_bytes())
        .map_err(|_| format!("{label} contains invalid base64"))?;
    if decoded.len() != 32 {
        return Err(format!("{label} key must decode to 32 bytes"));
    }
    Ok(decoded)
}

fn encode_envelope(key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key_id_bytes = key_id.as_bytes();
    if key_id_bytes.is_empty() {
        return Err("chunk encryption key id must not be empty".into());
    }
    if key_id_bytes.len() > u8::MAX as usize {
        return Err("chunk encryption key id must be <= 255 bytes".into());
    }
    let mut out =
        Vec::with_capacity(ENVELOPE_MAGIC.len() + 1 + key_id_bytes.len() + ciphertext.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.push(key_id_bytes.len() as u8);
    out.extend_from_slice(key_id_bytes);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

fn parse_envelope(payload: &[u8]) -> Result<ChunkEnvelope<'_>, String> {
    if !ChunkEncryption::is_envelope(payload) {
        return Err("chunk payload is not encrypted".into());
    }
    let key_len_pos = ENVELOPE_MAGIC.len();
    if payload.len() <= key_len_pos {
        return Err("chunk payload header is truncated".into());
    }
    let key_len = payload[key_len_pos] as usize;
    let key_start = key_len_pos + 1;
    let key_end = key_start + key_len;
    if payload.len() < key_end {
        return Err("chunk payload key id is truncated".into());
    }
    let key_id = std::str::from_utf8(&payload[key_start..key_end])
        .map_err(|_| "chunk payload key id is not valid utf-8".to_string())?;
    let ciphertext = &payload[key_end..];
    if ciphertext.is_empty() {
        return Err("chunk payload ciphertext is empty".into());
    }
    Ok(ChunkEnvelope { key_id, ciphertext })
}

fn parse_bool_env(key: &str, default_value: bool) -> Result<bool, String> {
    match env::var(key) {
        Ok(raw) => parse_bool_value(&raw).ok_or_else(|| format!("{key} must be true/false")),
        Err(_) => Ok(default_value),
    }
}

fn parse_bool_value(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn env_or_default(key: &str, default_value: &str) -> String {
    env::var(key).unwrap_or_else(|_| default_value.to_string())
}

fn read_optional_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        encode_envelope, load_chunk_encryption, parse_bool_env, parse_envelope,
        parse_keyring_entries, ChunkEncryption, ENV_ACTIVE_KEY_ID, ENV_ALLOW_PLAINTEXT_READ,
        ENV_ENABLED, ENV_KEYS, ENV_KEY_BASE64,
    };
    use crate::test_support;
    use crate::util::crypto;
    use base64::engine::general_purpose::STANDARD as Base64;
    use base64::Engine;
    use std::collections::HashMap;
    use std::env;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        entries: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
            }
        }

        fn set(&mut self, key: &str, value: &str) {
            let prev = env::var(key).ok();
            self.entries.push((key.to_string(), prev));
            env::set_var(key, value);
        }

        fn remove(&mut self, key: &str) {
            let prev = env::var(key).ok();
            self.entries.push((key.to_string(), prev));
            env::remove_var(key);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.entries.drain(..).rev() {
                if let Some(val) = value {
                    env::set_var(key, val);
                } else {
                    env::remove_var(key);
                }
            }
        }
    }

    fn base_config() -> crate::util::config::Config {
        let dir = PathBuf::from("/tmp/nss-chunk-encryption-tests");
        test_support::base_config("master", dir)
    }

    fn reset_chunk_env(guard: &mut EnvGuard) {
        guard.remove(ENV_ENABLED);
        guard.remove(ENV_ALLOW_PLAINTEXT_READ);
        guard.remove(ENV_ACTIVE_KEY_ID);
        guard.remove(ENV_KEYS);
        guard.remove(ENV_KEY_BASE64);
    }

    #[test]
    fn parse_keyring_entries_accepts_multiple_keys() {
        let raw = "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,\
v2:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let keys = parse_keyring_entries(raw).expect("keys");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("v1"));
        assert!(keys.contains_key("v2"));
    }

    #[test]
    fn parse_keyring_entries_rejects_duplicates() {
        let raw = "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,\
v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let err = parse_keyring_entries(raw).unwrap_err();
        assert!(err.contains("duplicate"));
    }

    #[test]
    fn parse_keyring_entries_rejects_malformed_entry() {
        let err = parse_keyring_entries("missing-separator").unwrap_err();
        assert!(err.contains("expected key_id:base64_key"));
    }

    #[test]
    fn parse_keyring_entries_rejects_invalid_base64_entry() {
        let err = parse_keyring_entries("v1:not-base64").unwrap_err();
        assert!(err.contains("invalid base64"));
    }

    #[test]
    fn parse_keyring_entries_rejects_empty_and_invalid_key_rows() {
        let empty = parse_keyring_entries(" , ").unwrap_err();
        assert!(empty.contains("at least one key entry"));
        let empty_key =
            parse_keyring_entries(":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap_err();
        assert!(empty_key.contains("key id is empty"));
        let short_key =
            parse_keyring_entries("v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==").unwrap_err();
        assert!(short_key.contains("decode to 32 bytes"));
    }

    #[test]
    fn parse_bool_env_rejects_invalid_values() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.set(ENV_ENABLED, "maybe");
        let err = parse_bool_env(ENV_ENABLED, true).unwrap_err();
        assert!(err.contains("true/false"));
    }

    #[test]
    fn parse_bool_env_uses_default_when_missing() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        guard.remove(ENV_ENABLED);
        let value = parse_bool_env(ENV_ENABLED, true).expect("value");
        assert!(value);
    }

    #[test]
    fn load_chunk_encryption_rejects_invalid_plaintext_flag() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "true");
        guard.set(ENV_ALLOW_PLAINTEXT_READ, "maybe");
        let config = base_config();
        let err = load_chunk_encryption(&config).unwrap_err();
        assert!(err.contains("true/false"));
    }

    #[test]
    fn chunk_encryption_requires_active_key() {
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), vec![1u8; 32]);
        let err = ChunkEncryption::new("v2".to_string(), keys, true).unwrap_err();
        assert!(err.contains("active key"));
    }

    #[test]
    fn chunk_encryption_rejects_empty_keyring() {
        let err = ChunkEncryption::new("v1".to_string(), HashMap::new(), true).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn chunk_encryption_roundtrip_uses_envelope() {
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), vec![3u8; 32]);
        let encryption = ChunkEncryption::new("v1".to_string(), keys, true).expect("enc");
        let payload = encryption.encrypt(b"hello").expect("encrypt");
        assert!(ChunkEncryption::is_envelope(&payload));
        let plaintext = encryption.decrypt(&payload).expect("decrypt");
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn encrypt_rejects_missing_active_key_in_invalid_state() {
        let encryption = ChunkEncryption {
            active_key_id: "missing".to_string(),
            keys: Arc::new(HashMap::new()),
            allow_plaintext_read: true,
        };
        let err = encryption.encrypt(b"hello").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn decrypt_rejects_unknown_key_id() {
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), vec![7u8; 32]);
        let encryption = ChunkEncryption::new("v1".to_string(), keys, true).expect("enc");
        let ciphertext = crypto::encrypt_secret(&[9u8; 32], b"payload").expect("cipher");
        let payload = encode_envelope("missing", &ciphertext).expect("envelope");
        let err = encryption.decrypt(&payload).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn decrypt_rejects_non_envelope_payload() {
        let mut keys = HashMap::new();
        keys.insert("v1".to_string(), vec![1u8; 32]);
        let encryption = ChunkEncryption::new("v1".to_string(), keys, true).expect("enc");
        let err = encryption.decrypt(b"plain").unwrap_err();
        assert!(err.contains("not encrypted"));
    }

    #[test]
    fn parse_envelope_rejects_invalid_payloads() {
        let err = parse_envelope(b"plain").unwrap_err();
        assert!(err.contains("not encrypted"));
        let err = parse_envelope(b"NSSCHNK1").unwrap_err();
        assert!(err.contains("header is truncated"));
        let err = parse_envelope(b"NSSCHNK1\x02a").unwrap_err();
        assert!(err.contains("key id is truncated"));
        let err = parse_envelope(b"NSSCHNK1\x01\xffx").unwrap_err();
        assert!(err.contains("utf-8"));
        let err = parse_envelope(b"NSSCHNK1\x01a").unwrap_err();
        assert!(err.contains("ciphertext is empty"));
    }

    #[test]
    fn encode_envelope_rejects_empty_and_long_key_ids() {
        let err = encode_envelope("", b"cipher").unwrap_err();
        assert!(err.contains("must not be empty"));
        let long_key = "k".repeat(256);
        let err = encode_envelope(&long_key, b"cipher").unwrap_err();
        assert!(err.contains("<= 255 bytes"));
    }

    #[test]
    fn load_chunk_encryption_respects_disabled_flag() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "false");
        let config = base_config();
        let encryption = load_chunk_encryption(&config).expect("policy");
        assert!(encryption.is_none());
    }

    #[test]
    fn load_chunk_encryption_uses_key_base64() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "true");
        guard.set(ENV_ACTIVE_KEY_ID, "rotated");
        guard.set(ENV_KEY_BASE64, &Base64.encode([5u8; 32]));
        let config = base_config();
        let encryption = load_chunk_encryption(&config)
            .expect("policy")
            .expect("enabled");
        let payload = encryption.encrypt(b"key-source").expect("encrypt");
        let plaintext = encryption.decrypt(&payload).expect("decrypt");
        assert_eq!(plaintext, b"key-source");
    }

    #[test]
    fn load_chunk_encryption_rejects_missing_active_key_in_keyring() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "true");
        guard.set(ENV_ACTIVE_KEY_ID, "active");
        guard.set(
            ENV_KEYS,
            "other:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        let config = base_config();
        let err = load_chunk_encryption(&config).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn load_chunk_encryption_rejects_invalid_env_key_payloads() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "true");
        guard.set(ENV_ACTIVE_KEY_ID, "v1");
        guard.set(ENV_KEYS, "v1:not-base64");
        let config = base_config();
        let err = load_chunk_encryption(&config).unwrap_err();
        assert!(err.contains("invalid base64"));

        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "true");
        guard.set(ENV_ACTIVE_KEY_ID, "v1");
        guard.set(ENV_KEY_BASE64, "not-base64");
        let err = load_chunk_encryption(&config).unwrap_err();
        assert!(err.contains("invalid base64"));
    }

    #[test]
    fn load_chunk_encryption_accepts_keyring_env() {
        let _lock = ENV_LOCK.lock().expect("lock");
        let mut guard = EnvGuard::new();
        reset_chunk_env(&mut guard);
        guard.set(ENV_ENABLED, "true");
        guard.set(ENV_ACTIVE_KEY_ID, "v1");
        guard.set(
            ENV_KEYS,
            "v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,\
v2:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        );
        let config = base_config();
        let encryption = load_chunk_encryption(&config)
            .expect("policy")
            .expect("enabled");
        let payload = encryption.encrypt(b"payload").expect("encrypt");
        let plain = encryption.decrypt(&payload).expect("decrypt");
        assert_eq!(plain, b"payload");
    }

    #[test]
    fn env_guard_restores_existing_value() {
        let _lock = ENV_LOCK.lock().expect("lock");
        env::set_var(ENV_ENABLED, "old");
        {
            let mut guard = EnvGuard::new();
            guard.set(ENV_ENABLED, "new");
            assert_eq!(env::var(ENV_ENABLED).expect("set"), "new");
        }
        assert_eq!(env::var(ENV_ENABLED).expect("restored"), "old");
        env::remove_var(ENV_ENABLED);
    }
}
