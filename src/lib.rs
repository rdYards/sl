pub mod crypto;
pub mod error;
pub mod ledger;
pub mod logging;
pub mod types;

use crate::crypto::*;
use crate::error::LedgerError;
use crate::types::HashInfo;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct SecureLedger {
    root_path: String,
    meta: types::MetaData,
    ledger: Vec<types::LedgerEntry>,
    hash_info: types::HashInfo,
}

impl SecureLedger {
    pub fn new(root_path: &str) -> Self {
        let meta = types::MetaData {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            description: "Secure ledger".to_string(),
        };

        SecureLedger {
            root_path: root_path.to_string(),
            meta,
            ledger: Vec::new(),
            hash_info: types::HashInfo {
                algorithm: "argon2".to_string(),
                salt: "".to_string(),
                iterations: 3,
                hash: "".to_string(),
            },
        }
    }

    pub fn initialize(&self, password: &str) -> Result<(), LedgerError> {
        // Create directory structure
        ledger::initialize(&self.root_path, &self.meta)?;

        // Create initial hash file
        let (salt, hash) = generate_password_hash(password)?;
        let hash_info = HashInfo {
            algorithm: "argon2".to_string(),
            salt: hex::encode(&salt),
            iterations: 3,
            hash: hash.to_string(),
        };
        let hash_path = Path::new(&self.root_path).join("hash.json");
        fs::write(hash_path, serde_json::to_string_pretty(&hash_info)?)?;

        // Create empty ledger.enc
        let ledger_path = Path::new(&self.root_path).join("ledger.enc");
        fs::write(ledger_path, "")?;

        Ok(())
    }

    pub fn encrypt_ledger(&self, password: &str) -> Result<(), LedgerError> {
        crypto::encrypt_ledger(&self.root_path, password)
    }

    pub fn decrypt_ledger(&self, password: &str) -> Result<Value, LedgerError> {
        crypto::decrypt_ledger(&self.root_path, password)
    }

    pub fn log_event(&self, event: &str) -> Result<(), LedgerError> {
        logging::log_event(&self.root_path, event)
    }

    pub fn add_entry(
        &mut self,
        entry: types::LedgerEntry,
        password: &str,
    ) -> Result<(), LedgerError> {
        verify_password(&self.root_path, password)?;
        self.ledger.push(entry);
        self.save_ledger(password)
    }

    fn save_ledger(&self, password: &str) -> Result<(), LedgerError> {
        // Create the ledger data structure
        let ledger_data = serde_json::json!({
            "entries": self.ledger,
            "meta": self.meta
        });

        // Encrypt directly without writing plaintext
        let ledger_str = serde_json::to_string(&ledger_data)?;
        let ledger_path = Path::new(&self.root_path).join("ledger.enc");
        encrypt_data(&ledger_path, &ledger_str, password)?;

        Ok(())
    }

    pub fn load_ledger(&mut self, password: &str) -> Result<(), LedgerError> {
        verify_password(&self.root_path, password)?;

        // Check if encrypted ledger exists
        let ledger_path = Path::new(&self.root_path).join("ledger.enc");
        if !ledger_path.exists() {
            return Ok(()); // No ledger file exists yet
        }

        // Decrypt and load directly
        let decrypted = decrypt_data(&ledger_path, password)?;
        let parsed: Value = serde_json::from_str(&decrypted)?;

        // Parse entries
        if let Some(entries_array) = parsed.get("entries").and_then(|e| e.as_array()) {
            self.ledger = entries_array
                .iter()
                .filter_map(|e| serde_json::from_value(e.clone()).ok())
                .collect();
        }

        // Parse meta
        if let Some(meta_value) = parsed.get("meta") {
            if let Ok(m) = serde_json::from_value(meta_value.clone()) {
                self.meta = m;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn test_initialization() -> Result<(), LedgerError> {
        let test_path = "./my_ledger_test_init.sl";
        let ledger = SecureLedger::new(test_path);

        // Clean up any existing test files
        if Path::new(test_path).exists() {
            fs::remove_dir_all(test_path)?;
        }

        // Initialize and verify
        ledger.initialize("test_password")?;
        assert!(
            Path::new(test_path).exists(),
            "Ledger directory should exist after initialization"
        );

        // Clean up
        fs::remove_dir_all(test_path)?;
        Ok(())
    }

    #[test]
    fn test_encryption_decryption() -> Result<(), LedgerError> {
        let test_path = "./my_ledger_test_crypto.sl";
        let mut ledger = SecureLedger::new(test_path);

        // Clean up any existing test files
        if Path::new(test_path).exists() {
            fs::remove_dir_all(test_path)?;
        }

        // Initialize ledger
        ledger.initialize("my_secure_password")?;
        ledger.log_event("Initialized")?;

        // Add some entries to the ledger (will auto-encrypt)
        let entry1 = types::LedgerEntry {
            id: "1".to_string(),
            data: "Initial entry".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let entry2 = types::LedgerEntry {
            id: "2".to_string(),
            data: "Second entry".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // The first add_entry will create the hash and encrypt
        ledger.add_entry(entry1, "my_secure_password")?;
        ledger.add_entry(entry2, "my_secure_password")?;
        ledger.log_event("Entries Added")?;

        // Verify encrypted file exists
        assert!(
            Path::new(test_path).join("ledger.enc").exists(),
            "Encrypted ledger file should exist"
        );

        // Verify NO plaintext file exists
        assert!(
            !Path::new(test_path).join("ledger.json").exists(),
            "Plaintext ledger file should not exist"
        );
        ledger.log_event("Pushed Encrypted Data")?;

        // Load and verify
        let mut loaded_ledger = SecureLedger::new(test_path);
        loaded_ledger.load_ledger("my_secure_password")?;
        assert_eq!(
            loaded_ledger.ledger.len(),
            2,
            "Should have exactly 2 entries"
        );

        // Test wrong password handling
        let wrong_password_result = loaded_ledger.load_ledger("wrong_password");
        assert!(
            wrong_password_result.is_err(),
            "Decryption with wrong password should fail"
        );

        // Clean up
        fs::remove_dir_all(test_path)?;
        Ok(())
    }

    #[test]
    fn test_logging() -> Result<(), LedgerError> {
        let test_path = "./my_ledger_test_log.sl";
        let ledger = SecureLedger::new(test_path);

        // Clean up any existing test files
        if Path::new(test_path).exists() {
            fs::remove_dir_all(test_path)?;
        }

        // Initialize ledger
        ledger.initialize("my_secure_password")?;

        // Log an event and verify
        ledger.log_event("Ledger initialized and encrypted")?;
        let log_path = Path::new(test_path).join("events.log");
        assert!(log_path.exists(), "Event log file should exist");
        let log_contents = fs::read_to_string(&log_path)?;
        assert!(
            log_contents.contains("Ledger initialized and encrypted"),
            "Log should contain our event message"
        );

        // Clean up
        fs::remove_dir_all(test_path)?;
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_persistent_ledger_creation() -> Result<(), LedgerError> {
        let test_path = "./persistent_ledger.sl";
        let mut ledger = SecureLedger::new(test_path);

        // Clean up any existing test files
        if Path::new(test_path).exists() {
            fs::remove_dir_all(test_path)?;
        }

        // Initialize ledger
        ledger.initialize("my_secure_password")?;

        // Add some entries to the ledger
        let entry1 = types::LedgerEntry {
            id: "1".to_string(),
            data: "Persistent entry 1".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let entry2 = types::LedgerEntry {
            id: "2".to_string(),
            data: "Persistent entry 2".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        ledger.add_entry(entry1, "my_secure_password")?;
        ledger.add_entry(entry2, "my_secure_password")?;

        // Log an event
        ledger.log_event("Created persistent ledger for export")?;

        // Do NOT clean up - this ledger is meant to be exported
        Ok(())
    }
}
