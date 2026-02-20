use aes_gcm::aead::generic_array::sequence::GenericSequence;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use hex;
use rand::random;
use serde_json::Value;
use std::fs;
use std::path::Path;

use crate::error::LedgerError;
use crate::types::HashInfo;

pub fn encrypt_ledger(root_path: &str, password: &str) -> Result<(), LedgerError> {
    // Generate and store password hash
    let (salt, hash) = generate_password_hash(password)?;

    // Update hash info
    let hash_info = HashInfo {
        algorithm: "argon2".to_string(),
        salt: hex::encode(salt),
        iterations: 3,
        hash: hash.to_string(),
    };

    // Save hash info
    let hash_path = Path::new(root_path).join("hash.json");
    fs::write(hash_path, serde_json::to_string_pretty(&hash_info)?)?;

    // Encrypt ledger file
    let ledger_path = Path::new(root_path).join("ledger.json");
    let ledger_data = fs::read_to_string(ledger_path)?;

    let key = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::encode_borrowed(&salt))?;
    let cipher = Aes256Gcm::new_from_slice(key.hash.unwrap().as_bytes())?;
    let nonce = Nonce::generate(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, ledger_data.as_bytes())?;
    let encrypted_data = format!("{}:{}", hex::encode(nonce), hex::encode(encrypted));

    fs::write(ledger_path, encrypted_data)?;
    Ok(())
}

pub fn decrypt_ledger(root_path: &str, password: &str) -> Result<Value, LedgerError> {
    // Verify password
    verify_password(root_path, password)?;

    // Decrypt ledger
    let ledger_path = Path::new(root_path).join("ledger.json");
    let encrypted_data = fs::read_to_string(ledger_path)?;

    let parts: Vec<&str> = encrypted_data.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted data format".into());
    }

    let nonce = Nonce::from_slice(hex::decode(parts[0])?.as_slice());
    let ciphertext = hex::decode(parts[1])?;

    let hash_info = get_hash_info(root_path)?;
    let salt = hex::decode(&hash_info.salt)?;
    let key = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::encode_borrowed(&salt))?;
    let cipher = Aes256Gcm::new_from_slice(key.hash.unwrap().as_bytes())?;

    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(serde_json::from_slice(&decrypted)?)
}

fn generate_password_hash(
    password: &str,
) -> Result<(Vec<u8>, argon2::password_hash::Result<PasswordHash>), LedgerError> {
    let salt = random::<[u8; 16]>();
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &SaltString::encode_b64(&salt)?)?;
    Ok((salt.to_vec(), hash))
}

fn verify_password(root_path: &str, password: &str) -> Result<(), LedgerError> {
    let hash_info = get_hash_info(root_path)?;
    let salt = hex::decode(&hash_info.salt)?;
    let hash =
        Argon2::default().hash_password(password.as_bytes(), &SaltString::encode_b64(&salt)?)?;

    if hash.to_string() != hash_info.hash {
        return Err(LedgerError::InvalidPassword("Invalid password".to_string()));
    }
    Ok(())
}

fn get_hash_info(root_path: &str) -> Result<HashInfo, LedgerError> {
    let hash_path = Path::new(root_path).join("hash.json");
    let hash_content = fs::read_to_string(hash_path)?;
    Ok(serde_json::from_str(&hash_content)?)
}
