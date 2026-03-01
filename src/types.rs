use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MetaData {
    pub root_path: PathBuf,
    pub title: String,
    pub version: f32,
    pub created_at: String,
    pub last_modified: String,
    pub description: String,
    pub write_on_change: bool,
    pub ledger_hash: String
}

#[derive(Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: String,
    pub data: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct HashInfo {
    pub algorithm: String,
    pub salt: String,
    pub iterations: u32,
    pub hash: String,
}