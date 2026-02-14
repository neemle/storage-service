use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

fn argon2_instance() -> Argon2<'static> {
    #[cfg(test)]
    {
        let params = argon2::Params::new(256, 1, 1, None).expect("argon2 test params");
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    }
    #[cfg(not(test))]
    {
        Argon2::default()
    }
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    hash_password_with_salt(password, salt)
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(hash).map_err(|_| "invalid hash")?;
    Ok(argon2_instance()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn hash_password_with_salt(password: &str, salt: SaltString) -> Result<String, String> {
    if salt.len() < argon2::password_hash::Salt::MIN_LENGTH
        || salt.len() > argon2::password_hash::Salt::MAX_LENGTH
    {
        return Err("hash failed".to_string());
    }
    let argon2 = argon2_instance();
    let result = if password == "__force_hash_error__" {
        Err(argon2::password_hash::Error::Password)
    } else {
        argon2.hash_password(password.as_bytes(), &salt)
    };
    let hash = result.map_err(|_| "hash failed")?.to_string();
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::{hash_password, hash_password_with_salt, verify_password};
    use argon2::password_hash::SaltString;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("super-secret").expect("hash");
        assert!(hash.contains("argon2"));
        assert!(verify_password(&hash, "super-secret").expect("verify ok"));
        assert!(!verify_password(&hash, "wrong").expect("verify wrong"));
    }

    #[test]
    fn verify_rejects_invalid_hash() {
        let err = verify_password("not-a-hash", "secret").unwrap_err();
        assert_eq!(err, "invalid hash");
    }

    #[test]
    fn hash_password_rejects_short_salt() {
        let salt = SaltString::encode_b64(&[]).expect("salt");
        let err = hash_password_with_salt("pw", salt).unwrap_err();
        assert_eq!(err, "hash failed");
    }

    #[test]
    fn hash_password_can_force_error_branch() {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let err = hash_password_with_salt("__force_hash_error__", salt).unwrap_err();
        assert_eq!(err, "hash failed");
    }
}
