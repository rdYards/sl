use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
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
        salt: hex::encode(&salt),
        iterations: 3,
        hash: hash.to_string(),
    };

    // Save hash info
    let hash_path = Path::new(root_path).join("hash.json");
    fs::write(hash_path, serde_json::to_string_pretty(&hash_info)?)?;

    // Encrypt the ledger data
    let ledger_path = Path::new(root_path).join("ledger.json");
    let ledger_data = fs::read_to_string(ledger_path)?;
    let encrypted_path = Path::new(root_path).join("ledger.enc");
    encrypt_data(&encrypted_path, &ledger_data, password)?;

    Ok(())
}

pub fn decrypt_ledger(root_path: &str, password: &str) -> Result<Value, LedgerError> {
    verify_password(root_path, password)?; // Verify password

    // Get the encrypted ledger path
    let ledger_path = Path::new(root_path).join("ledger.enc");

    // Read and decrypt the data
    let decrypted = decrypt_data(&ledger_path, password)?;

    // Parse the decrypted JSON
    Ok(serde_json::from_str(&decrypted)?)
}

pub fn encrypt_data(path: &Path, data: &str, password: &str) -> Result<(), LedgerError> {
    // Generate and store password hash if not exists
    let hash_path = path.parent().unwrap().join("hash.json");
    if !hash_path.exists() {
        let (salt, hash) = generate_password_hash(password)?;
        let hash_info = HashInfo {
            algorithm: "argon2".to_string(),
            salt: hex::encode(&salt),
            iterations: 3,
            hash: hash.to_string(),
        };
        fs::write(&hash_path, serde_json::to_string_pretty(&hash_info)?)?;
    }

    // Verify password matches existing hash
    verify_password(path.parent().unwrap().to_str().unwrap(), password)?;

    // Encrypt the data
    let salt = hex::decode(&get_hash_info(path.parent().unwrap().to_str().unwrap())?.salt)?;
    let binding = SaltString::encode_b64(&salt)?;
    let key = Argon2::default().hash_password(password.as_bytes(), &binding)?;
    let cipher = Aes256Gcm::new_from_slice(key.hash.unwrap().as_bytes())?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);
    let encrypted = cipher.encrypt(&nonce, data.as_bytes())?;
    let encrypted_data = format!("{}:{}", hex::encode(nonce), hex::encode(encrypted));

    // Write to the specified path
    fs::write(path, encrypted_data)?;
    Ok(())
}

pub fn decrypt_data(path: &Path, password: &str) -> Result<String, LedgerError> {
    // Verify password
    verify_password(path.parent().unwrap().to_str().unwrap(), password)?;

    // Read encrypted data
    let encrypted_data = fs::read_to_string(path)?;

    let parts: Vec<&str> = encrypted_data.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted data format".into());
    }

    let binding = hex::decode(parts[0])?;
    let nonce = Nonce::from_slice(binding.as_slice());
    let ciphertext = hex::decode(parts[1])?;

    let hash_info = get_hash_info(path.parent().unwrap().to_str().unwrap())?;
    let salt = hex::decode(&hash_info.salt)?;
    let binding = SaltString::encode_b64(&salt)?;
    let key = Argon2::default().hash_password(password.as_bytes(), &binding)?;
    let cipher = Aes256Gcm::new_from_slice(key.hash.unwrap().as_bytes())?;

    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(String::from_utf8(decrypted)?)
}

pub fn generate_password_hash(password: &str) -> Result<(Vec<u8>, String), LedgerError> {
    let salt = random::<[u8; 16]>();
    let argon2 = Argon2::default();
    let binding = SaltString::encode_b64(&salt)?;
    let hash = argon2.hash_password(password.as_bytes(), &binding)?;
    Ok((salt.to_vec(), hash.to_string()))
}

pub fn verify_password(root_path: &str, password: &str) -> Result<(), LedgerError> {
    let hash_info = get_hash_info(root_path)?;
    let salt = hex::decode(&hash_info.salt)?;
    let encoded_salt = SaltString::encode_b64(&salt)?;
    let hash = Argon2::default().hash_password(password.as_bytes(), &encoded_salt)?;

    if hash.to_string() != hash_info.hash {
        return Err(LedgerError::InvalidPassword("Invalid password".to_string()));
    }
    Ok(())
}

pub fn get_hash_info(root_path: &str) -> Result<HashInfo, LedgerError> {
    let hash_path = Path::new(root_path).join("hash.json");
    let hash_content = fs::read_to_string(hash_path)?;
    Ok(serde_json::from_str(&hash_content)?)
}
