use std::fs;
use std::path::Path;

use crate::error::LedgerError;
use crate::types::MetaData;

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