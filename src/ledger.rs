use std::fs;
use std::path::Path;
use crate::crypto;
use crate::logging;

use crate::error::LedgerError;
use crate::types::{MetaData, LedgerEntry, HashInfo};
use crate::crypto::*;
use serde_json::Value;

#[allow(dead_code)]
pub struct SecureLedger {
    root_path: String,
    meta: MetaData,
    pub ledger: Vec<LedgerEntry>,
    hash_info: HashInfo,
}

impl SecureLedger {
    pub fn new(root_path: &str) -> Self {
        let meta = MetaData {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            description: "Secure ledger".to_string(),
        };

        SecureLedger {
            root_path: root_path.to_string(),
            meta,
            ledger: Vec::new(),
            hash_info: HashInfo {
                algorithm: "argon2".to_string(),
                salt: "".to_string(),
                iterations: 3,
                hash: "".to_string(),
            },
        }
    }

    pub fn initialize(&self, password: &str) -> Result<(), LedgerError> {
        // Create directory structure
        initialize(&self.root_path, &self.meta)?;

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
        entry: LedgerEntry,
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

pub fn initialize(root_path: &str, meta: &MetaData) -> Result<(), LedgerError> {
    // Create directory structure
    fs::create_dir_all(root_path)?;

    // Create meta.json
    let meta_path = Path::new(root_path).join("meta.json");
    fs::write(meta_path, serde_json::to_string_pretty(meta)?)?;

    // Create empty hash.json
    let hash_path = Path::new(root_path).join("hash.json");
    fs::write(hash_path, "{}")?;

    // Create empty ledger.enc (encrypted)
    let ledger_path = Path::new(root_path).join("ledger.enc");
    fs::write(ledger_path, "")?;

    Ok(())
}