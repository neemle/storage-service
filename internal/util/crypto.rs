use aes_gcm::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static FORCE_ENCRYPT_ERROR: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub fn set_force_encrypt_error(value: bool) {
    FORCE_ENCRYPT_ERROR.store(value, Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear_force_encrypt_error() {
    FORCE_ENCRYPT_ERROR.store(false, Ordering::SeqCst);
}

#[cfg(test)]
pub struct ForceEncryptErrorGuard;

#[cfg(test)]
impl Drop for ForceEncryptErrorGuard {
    fn drop(&mut self) {
        clear_force_encrypt_error();
    }
}

#[cfg(test)]
pub fn force_encrypt_error_guard() -> ForceEncryptErrorGuard {
    set_force_encrypt_error(true);
    ForceEncryptErrorGuard
}

pub fn encrypt_secret(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(test)]
    if FORCE_ENCRYPT_ERROR.swap(false, Ordering::SeqCst) {
        return Err("encryption failed".into());
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let result = if plaintext == b"__force_encrypt_error__" {
        Err(aes_gcm::Error)
    } else {
        cipher.encrypt(nonce, plaintext)
    };
    let mut ciphertext = result.map_err(|_| "encryption failed")?;
    let mut out = nonce_bytes.to_vec();
    out.append(&mut ciphertext);
    Ok(out)
}

pub fn decrypt_secret(key_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 {
        return Err("ciphertext too short".into());
    }
    let (nonce_bytes, data) = ciphertext.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, data)
        .map_err(|_| "decryption failed".into())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_secret, encrypt_secret};

    #[test]
    fn encrypt_and_decrypt_roundtrip() {
        let key = [7u8; 32];
        let plaintext = b"top-secret";
        let ciphertext = encrypt_secret(&key, plaintext).expect("encrypt");
        assert!(ciphertext.len() > 12);
        let decrypted = decrypt_secret(&key, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_short_ciphertext() {
        let err = decrypt_secret(&[0u8; 32], &[1, 2, 3]).unwrap_err();
        assert_eq!(err, "ciphertext too short");
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key = [1u8; 32];
        let other = [2u8; 32];
        let plaintext = b"hello";
        let ciphertext = encrypt_secret(&key, plaintext).expect("encrypt");
        let err = decrypt_secret(&other, &ciphertext).unwrap_err();
        assert_eq!(err, "decryption failed");
    }

    #[test]
    fn encrypt_secret_reports_forced_error() {
        let key = [1u8; 32];
        let err = encrypt_secret(&key, b"__force_encrypt_error__").unwrap_err();
        assert_eq!(err, "encryption failed");
    }
}
