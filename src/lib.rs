pub mod crypto;
pub mod error;
pub mod ledger;
pub mod logging;
pub mod types;

use crate::error::LedgerError;
use std::fs;
use std::path::Path;
use serde_json::Value;

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

    #[test]
    fn it_works() -> Result<(), LedgerError> {
        let ledger = SecureLedger::new("./my_ledger.sl");
        ledger.initialize()?;

        // Add some entries to the ledger
        let mut ledger_data = serde_json::json!({
            "entries": [
                {"id": "1", "data": "Initial entry", "timestamp": chrono::Utc::now().to_rfc3339()}
            ]
        });

        // Save unencrypted ledger temporarily
        let ledger_path = Path::new("./my_ledger.sl").join("ledger.json");
        fs::write(ledger_path, serde_json::to_string_pretty(&ledger_data)?)?;

        // Encrypt the ledger
        ledger.encrypt_ledger("my_secure_password")?;

        // Log an event
        ledger.log_event("Ledger initialized and encrypted")?;

        // Later, to decrypt and use the ledger
        let decrypted = ledger.decrypt_ledger("my_secure_password")?;
        println!("Decrypted ledger: {:?}", decrypted);

        Ok(())
    }
}
