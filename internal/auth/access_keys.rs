use base64::Engine;
use rand::Rng;

pub fn generate_access_key_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("NSS{}", hex::encode(bytes))
}

pub fn generate_secret_access_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{generate_access_key_id, generate_secret_access_key};
    use base64::Engine;

    #[test]
    fn access_key_id_has_prefix_and_hex() {
        let key = generate_access_key_id();
        assert!(key.starts_with("NSS"));
        assert_eq!(key.len(), 35);
        assert!(key[3..].chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn secret_access_key_is_base64_32_bytes() {
        let secret = generate_secret_access_key();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(secret.as_bytes())
            .expect("decode");
        assert_eq!(decoded.len(), 32);
    }
}
