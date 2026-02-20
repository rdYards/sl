pub mod crypto;
pub mod error;
pub mod ledger;
pub mod logging;
pub mod types;

pub use ledger::SecureLedger;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use crate::error::LedgerError;

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
