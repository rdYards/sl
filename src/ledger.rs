use serde_json::Value;
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

    // Create logs directory
    let logs_path = Path::new(root_path).join("logs");
    fs::create_dir_all(logs_path)?;

    // Create empty ledger.json
    let ledger_path = Path::new(root_path).join("ledger.json");
    fs::write(ledger_path, "{}")?;

    // Create empty hash.json
    let hash_path = Path::new(root_path).join("hash.json");
    fs::write(hash_path, "{}")?;

    Ok(())
}

pub fn read_ledger(root_path: &str) -> Result<Value, LedgerError> {
    let ledger_path = Path::new(root_path).join("ledger.json");
    let content = fs::read_to_string(ledger_path)?;
    Ok(serde_json::from_str(&content)?)
}

pub fn write_ledger(root_path: &str, data: &Value) -> Result<(), LedgerError> {
    let ledger_path = Path::new(root_path).join("ledger.json");
    fs::write(ledger_path, serde_json::to_string_pretty(data)?)?;
    Ok(())
}