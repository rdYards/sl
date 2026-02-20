pub mod crypto;
pub mod error;
pub mod ledger;
pub mod logging;
pub mod types;

use crate::error::LedgerError;
use serde_json::Value;

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

    pub fn initialize(&self) -> Result<(), LedgerError> {
        ledger::initialize(&self.root_path, &self.meta)?;
        logging::log_event(&self.root_path, "Ledger initialized")?;
        Ok(())
    }

    // Add these missing methods:
    pub fn encrypt_ledger(&self, password: &str) -> Result<(), LedgerError> {
        crypto::encrypt_ledger(&self.root_path, password)
    }

    pub fn decrypt_ledger(&self, password: &str) -> Result<Value, LedgerError> {
        crypto::decrypt_ledger(&self.root_path, password)
    }

    pub fn log_event(&self, event: &str) -> Result<(), LedgerError> {
        logging::log_event(&self.root_path, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn test_initialization() -> Result<(), LedgerError> {
        // Test setup
        let test_path = "./my_ledger_test_init.sl";
        let ledger = SecureLedger::new(test_path);

        // Clean up any existing test files
        if Path::new(test_path).exists() {
            fs::remove_dir_all(test_path)?;
        }

        // Initialize and verify
        ledger.initialize()?;
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
        let ledger = SecureLedger::new(test_path);

        // Clean up any existing test files
        if Path::new(test_path).exists() {
            fs::remove_dir_all(test_path)?;
        }

        // Initialize ledger
        ledger.initialize()?;

        // Add some entries to the ledger
        let ledger_data = serde_json::json!({
            "entries": [
                {"id": "1", "data": "Initial entry", "timestamp": chrono::Utc::now().to_rfc3339()},
                {"id": "2", "data": "Second entry", "timestamp": chrono::Utc::now().to_rfc3339()}
            ]
        });

        // Save unencrypted ledger temporarily
        let ledger_path = Path::new(test_path).join("ledger.json");
        fs::write(&ledger_path, serde_json::to_string_pretty(&ledger_data)?)?;

        // Encrypt the ledger
        ledger.encrypt_ledger("my_secure_password")?;
        assert!(
            Path::new(test_path).join("ledger.enc").exists(),
            "Encrypted ledger file should exist"
        );

        // Decrypt and verify
        let decrypted = ledger.decrypt_ledger("my_secure_password")?;
        assert!(
            decrypted.get("entries").is_some(),
            "Decrypted data should contain entries"
        );
        if let Some(entries) = decrypted.get("entries").and_then(|e| e.as_array()) {
            assert_eq!(entries.len(), 2, "Should have exactly 2 entries");
        }

        // Test wrong password handling
        let wrong_password_result = ledger.decrypt_ledger("wrong_password");
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
        ledger.initialize()?;

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
}
