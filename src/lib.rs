pub mod crypto;
pub mod error;
pub mod ledger;
pub mod logging;
pub mod types;

pub use ledger::SecureLedger;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LedgerError;
    use crate::logging::return_time;
    use crate::types::LedgerEntry;
    use std::{fs::File, io::Read, path::Path};
    use tempfile::tempdir;
    use zip::ZipArchive;

    #[test]
    fn test_intialize_ed() -> Result<(), LedgerError> {
        let temp_dir = tempdir()?;
        let binding = temp_dir.path().join("enc_test.sl");
        let test_path = binding.to_str().unwrap();
        let password = "secure_password";

        // Create a new ledger
        let mut ledger = SecureLedger::initialize(None, None)?;

        // Update metadata using update_meta
        ledger.update_meta(
            test_path,
            "Encryption Test",
            "Testing encryption/decryption",
        );

        // Add an entry
        let entry1 = LedgerEntry {
            id: "entry1".to_string(),
            data: "Sensitive data 1".to_string(),
            timestamp: return_time(),
        };
        ledger.add_entry(entry1, password)?;

        // Add another entry
        let entry2 = LedgerEntry {
            id: "entry2".to_string(),
            data: "Sensitive data 2".to_string(),
            timestamp: return_time(),
        };
        ledger.add_entry(entry2, password)?;

        // Remove an entry
        ledger.remove_entry("entry1", password)?;

        // Verify only one entry remains
        assert_eq!(ledger.ledger.len(), 1);
        assert_eq!(ledger.ledger[0].id, "entry2");

        // Save the ledger
        ledger.upload_to_sl(password)?;

        // Load it back to verify encryption/decryption worked
        let loaded_ledger = SecureLedger::initialize(Some(test_path), Some(password))?;
        assert_eq!(loaded_ledger.ledger.len(), 1);
        assert_eq!(loaded_ledger.ledger[0].id, "entry2");
        assert_eq!(loaded_ledger.ledger[0].data, "Sensitive data 2");

        Ok(())
    }

    #[test]
    fn test_logging() -> Result<(), LedgerError> {
        let temp_dir = tempdir()?;
        let binding = temp_dir.path().join("log_test.sl");
        let test_path = binding.to_str().unwrap();

        // Create a new ledger with write_on_change disabled to test logging
        let mut ledger = SecureLedger::initialize(None, None)?;
        ledger.meta.write_on_change = false;

        // Update metadata using update_meta
        ledger.update_meta(test_path, "Logging Test", "Testing error logging");

        // Get initial error log count
        let initial_log_count = ledger.error_log.len();

        // Perform operations that might generate logs
        ledger.add_entry(
            LedgerEntry {
                id: "log_test1".to_string(),
                data: "Test data".to_string(),
                timestamp: return_time(),
            },
            "password",
        )?;

        // Try to remove a non-existent entry (should generate error log)
        let result = ledger.remove_entry("non_existent", "password");
        assert!(result.is_err());

        // Save the ledger to persist logs
        ledger.upload_to_sl("password")?;

        // Load it back and verify logs were created
        let loaded_ledger = SecureLedger::initialize(Some(test_path), Some("password"))?;
        assert!(loaded_ledger.error_log.len() > initial_log_count);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_persistent_ledger_creation() -> Result<(), LedgerError> {
        // Get the current working directory (root of dev environment)
        let current_dir = std::env::current_dir()?;
        let binding = current_dir.join("persistent_test.sl");
        let test_path = binding.to_str().unwrap();

        // Create a ledger with persistent storage
        let mut ledger = SecureLedger::initialize(None, None)?;

        // Update metadata using update_meta
        ledger.update_meta(test_path, "Persistent Test", "This ledger should persist");

        // Add some entries
        for i in 0..3 {
            ledger.add_entry(
                LedgerEntry {
                    id: format!("persistent_{}", i),
                    data: format!("Persistent data {}", i),
                    timestamp: return_time(),
                },
                "persistent_password",
            )?;
        }

        // Save the ledger
        ledger.upload_to_sl("persistent_password")?;

        // Verify the file exists (for manual inspection)
        assert!(Path::new(test_path).exists());

        Ok(())
    }

    #[test]
    fn test_archive_structure() -> Result<(), LedgerError> {
        let temp_dir = tempdir()?;
        let binding = temp_dir.path().join("structure_test.sl");
        let test_path = binding.to_str().unwrap();
        let password = "structure_test_pw";

        // Create a test ledger
        let mut ledger = SecureLedger::initialize(None, None)?;

        // Update metadata using update_meta
        ledger.update_meta(test_path, "Structure Test", "Testing archive structure");

        // Add an entry to generate some content
        ledger.add_entry(
            LedgerEntry {
                id: "structure_test_entry".to_string(),
                data: "Test data for structure".to_string(),
                timestamp: return_time(),
            },
            password,
        )?;

        // Save the ledger
        ledger.upload_to_sl(password)?;

        // Open the zip archive to verify structure
        let file = File::open(test_path)?;
        let mut archive = ZipArchive::new(file)?;

        // Verify all required files exist
        assert!(archive.by_name("hash.json").is_ok());
        assert!(archive.by_name("meta.json").is_ok());
        assert!(archive.by_name("ledger.enc").is_ok());
        assert!(archive.by_name("event.log").is_ok());

        // Verify the files have content
        let mut hash_content = String::new();
        archive
            .by_name("hash.json")?
            .read_to_string(&mut hash_content)?;
        assert!(!hash_content.is_empty());

        let mut meta_content = String::new();
        archive
            .by_name("meta.json")?
            .read_to_string(&mut meta_content)?;
        assert!(!meta_content.is_empty());

        let mut ledger_content = Vec::new();
        archive
            .by_name("ledger.enc")?
            .read_to_end(&mut ledger_content)?;
        assert!(!ledger_content.is_empty());

        Ok(())
    }
}
