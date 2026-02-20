use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MetaData {
    pub version: String,
    pub created_at: String,
    pub description: String,
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