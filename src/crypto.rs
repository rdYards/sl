use aes_gcm::{
    AeadCore, Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use hex;
use rand::random;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::types::{HashInfo, LedgerEntry};
use crate::{SecureLedger, error::LedgerError};

// Structure to hold encrypted ledger data
#[derive(Serialize, Deserialize)]
pub struct EncryptedLedger {
    nonce: String,
    ciphertext: String,
    salt: String,
    hash: String,
}

// Encrypts the ledger data and saves it to disk
pub fn encrypt_ledger(
    root_path: &str,
    ledger: &[LedgerEntry],
    password: &str,
    hash_info: &HashInfo,
) -> Result<EncryptedLedger, LedgerError> {
    verify_password(root_path, password)?;
    
    let salt = hex::decode(&hash_info.salt)?;
    let encoded_salt = SaltString::encode_b64(&salt)?;
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &encoded_salt)?;

    // Use the hash as the encryption key (first 32 bytes)
    let binding = hash.hash.unwrap();
    let key = &binding.as_bytes()[..32];
    let cipher = Aes256Gcm::new_from_slice(key)?;

    // Serialize the ledger to JSON
    let ledger_json = serde_json::to_string(ledger)?;

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the ledger data
    let ciphertext = cipher.encrypt(&nonce, ledger_json.as_bytes())?;

    // Create the encrypted ledger structure
    let encrypted_ledger = EncryptedLedger {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        salt: hash_info.salt.clone(),
        hash: hash.to_string(),
    };

    // Save to disk
    let encrypted_path = Path::new(root_path).join("ledger.enc");
    fs::write(encrypted_path, serde_json::to_string(&encrypted_ledger)?)?;

    Ok(encrypted_ledger)
}

// Decrypts the ledger data from disk
pub fn decrypt_ledger(
    encrypted_data: &[u8],
    password: &str,
) -> Result<Vec<LedgerEntry>, LedgerError> {
    // Parse the encrypted ledger
    let encrypted_ledger: EncryptedLedger = serde_json::from_slice(encrypted_data)?;

    // Decode the salt and hash it with the password
    let salt = hex::decode(&encrypted_ledger.salt)?;
    let encoded_salt = SaltString::encode_b64(&salt)?;
    let hash = Argon2::default().hash_password(password.as_bytes(), &encoded_salt)?;

    // Verify the hash matches
    if hash.to_string() != encrypted_ledger.hash {
        return Err(LedgerError::InvalidPassword("Invalid password".to_string()));
    }

    // Use the hash as the decryption key (first 32 bytes)
    let binding = hash.hash.unwrap();
    let key = &binding.as_bytes()[..32];
    let cipher = Aes256Gcm::new_from_slice(key)?;

    // Decode the nonce and ciphertext
    let binding = hex::decode(&encrypted_ledger.nonce)?;
    let nonce = Nonce::from_slice(&binding);
    let ciphertext = hex::decode(&encrypted_ledger.ciphertext)?;

    // Decrypt the ledger data
    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref())?;

    // Deserialize the ledger
    let ledger: Vec<LedgerEntry> = serde_json::from_slice(&decrypted)?;

    Ok(ledger)
}

fn generate_password_hash(password: &str) -> Result<(Vec<u8>, String), LedgerError> {
    let salt = random::<[u8; 16]>();
    let argon2 = Argon2::default();
    let binding = SaltString::encode_b64(&salt)?;
    let hash = argon2.hash_password(password.as_bytes(), &binding)?;
    Ok((salt.to_vec(), hash.to_string()))
}

fn verify_password(root_path: &str, password: &str) -> Result<(), LedgerError> {
    let hash_info = get_hash_info(root_path)?;
    let salt = hex::decode(&hash_info.salt)?;
    let encoded_salt = SaltString::encode_b64(&salt)?;
    let hash = Argon2::default().hash_password(password.as_bytes(), &encoded_salt)?;

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

// Function to check entry hash when pushed to ledger
pub fn generate_entry_hash(entry: &LedgerEntry, salt: &str) -> Result<String, LedgerError> {
    let entry_json = serde_json::to_string(entry)?;
    let salt_bytes = hex::decode(salt)?;
    // Ensure salt is at least 16 bytes (128 bits) long
    if salt_bytes.len() < 16 {
        return Err(LedgerError::InvalidSalt(
            "Salt must be at least 16 bytes long".to_string(),
        ));
    }
    let encoded_salt = SaltString::encode_b64(&salt_bytes)?;
    let hash = Argon2::default().hash_password(entry_json.as_bytes(), &encoded_salt)?;
    Ok(hash.to_string())
}

// Function to hash entire ledger
pub fn generate_ledger_hash(ledger: &SecureLedger, salt: &str) -> Result<String, LedgerError> {
    let ledger_json = serde_json::to_string(&ledger.ledger)?;
    let salt_bytes = hex::decode(salt)?;
    let encoded_salt = SaltString::encode_b64(&salt_bytes)?;
    let hash = Argon2::default().hash_password(ledger_json.as_bytes(), &encoded_salt)?;
    Ok(hash.to_string())
}

// Simular to generate_ledger_hash() but used during ledger initialization.
// Checks entire ledger
pub fn check_loaded_with_ledger(
    ledger: &Vec<LedgerEntry>,
    salt: &str,
) -> Result<String, LedgerError> {
    let ledger_json = serde_json::to_string(&ledger)?;
    let salt_bytes = hex::decode(salt)?;
    let encoded_salt = SaltString::encode_b64(&salt_bytes)?;
    let hash = Argon2::default().hash_password(ledger_json.as_bytes(), &encoded_salt)?;
    Ok(hash.to_string())
}
