use crate::crypto::*;
use crate::error::LedgerError;
use crate::types::{HashInfo, LedgerEntry, MetaData};
use std::{
    fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::crypto;
use crate::logging::return_time;

static VERSION: f32 = 0.5;

pub struct SecureLedger {
    pub meta: MetaData,
    pub ledger: Vec<LedgerEntry>,
    pub hash_info: HashInfo,
    pub error_log: Vec<String>,
}

impl SecureLedger {
    // Initalize based on file bath provided or not
    // If file path offered then load file instead
    // If no file offered then create new file
    pub fn initialize(file_path: Option<&str>, password: Option<&str>) -> std::io::Result<Self> {
        match file_path {
            Some(path) => {
                // Check if file exists
                if !Path::new(path).exists() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("File not found: {}", path),
                    ));
                }

                // Open the zip archive
                let file = File::open(path)?;
                let mut archive = ZipArchive::new(file)?;

                // Read hash.json
                let mut hash_content = String::new();
                archive
                    .by_name("hash.json")?
                    .read_to_string(&mut hash_content)?;
                let hash_info: HashInfo = serde_json::from_str(&hash_content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                // Read meta.json
                let mut meta_content = String::new();
                archive
                    .by_name("meta.json")?
                    .read_to_string(&mut meta_content)?;
                let meta: MetaData = serde_json::from_str(&meta_content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                // Read event.log and parse into Vec<String>
                let mut error_log_content = String::new();
                archive
                    .by_name("event.log")?
                    .read_to_string(&mut error_log_content)?;
                let error_log: Vec<String> =
                    error_log_content.lines().map(|s| s.to_string()).collect();

                // Read ledger.enc and decrypt
                let mut ledger_enc_file = archive.by_name("ledger.enc")?;
                let mut ledger_enc_content = Vec::new();
                ledger_enc_file.read_to_end(&mut ledger_enc_content)?;

                // Decrypt ledger if password is provided
                let ledger = match password {
                    Some(pw) => crypto::decrypt_ledger(&ledger_enc_content, pw)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Password required to decrypt ledger",
                        ));
                    }
                };

                Ok(SecureLedger {
                    meta,
                    ledger,
                    hash_info,
                    error_log,
                })
            }
            None => {
                // Create new instance with default values
                let meta = MetaData {
                    root_path: PathBuf::from(file_path.unwrap_or("")),
                    title: String::new(),
                    version: VERSION,
                    created_at: return_time(),
                    last_modified: return_time(),
                    description: String::new(),
                    write_on_change: false,
                    ledger_hash: String::new(),
                };

                let hash_info = HashInfo {
                    algorithm: "argon2".to_string(),
                    salt: String::new(),
                    iterations: 3,
                    hash: String::new(),
                };

                Ok(SecureLedger {
                    meta,
                    ledger: vec![],
                    hash_info,
                    error_log: vec![],
                })
            }
        }
    }

    // Must be run after initialize to fix file_path
    pub fn update_meta(&mut self, file_path: &str, title: &str, description: &str) {
        self.meta.root_path = PathBuf::from(file_path);
        self.meta.title = title.to_string();
        self.meta.last_modified = return_time();
        self.meta.description = description.to_string();
        self.meta.ledger_hash = return_ledger_hash();
    }

    pub fn add_entry(&mut self, entry: LedgerEntry, password: &str) -> Result<(), LedgerError> {
        self.ledger.push(entry);
        self.log_event("Entry added successfully")?;

        // Update the last modified time
        self.meta.last_modified = return_time();

        // Update the ledger hash
        // update_ledger_hash(password)?;

        // If write_on_change is enabled, save immediately
        if self.meta.write_on_change {
            self.upload_to_sl(password)?;
        }

        Ok(())
    }

    pub fn remove_entry(&mut self, id: &str, password: &str) -> Result<(), LedgerError> {
        // Find the entry with the given ID
        if let Some(pos) = self.ledger.iter().position(|e| e.id == id) {
            self.ledger.remove(pos);
            self.log_event("Entry removed successfully")?;

            // Update the last modified time
            self.meta.last_modified = return_time();

            // Update the ledger hash
            // self.update_ledger_hash(password)?;

            // If write_on_change is enabled, save immediately
            if self.meta.write_on_change {
                self.upload_to_sl(password)?;
            }

            Ok(())
        } else {
            Err(LedgerError::EntryNotFound(id.to_string()))
        }
    }

    pub fn search_entry(&self, query: &str) -> Vec<&LedgerEntry> {
        self.ledger
            .iter()
            .filter(|e| {
                e.id.contains(query) || e.data.contains(query) || e.timestamp.contains(query)
            })
            .collect()
    }

    pub fn upload_to_sl(&self, password: &str) -> Result<(), LedgerError> {
        let root_path = Path::new(&self.meta.root_path);

        // Handle case where path is a file (remove extension to get directory)
        let dir_path = if root_path.extension().is_some() {
            root_path.parent().unwrap_or_else(|| Path::new("."))
        } else {
            root_path
        };

        // Create a temporary directory
        let temp_dir = tempfile::tempdir()?;

        // Create directory if needed
        fs::create_dir_all(dir_path)?;

        // Write all individual files to temporary directory
        // Write hash.json
        let hash_path = temp_dir.path().join("hash.json");
        fs::write(&hash_path, serde_json::to_string(&self.hash_info)?)?;

        // Write meta.json
        let meta_path = temp_dir.path().join("meta.json");
        fs::write(&meta_path, serde_json::to_string(&self.meta)?)?;

        // Encrypt and write ledger.enc to temp directory
        encrypt_ledger(&temp_dir.path().to_string_lossy(), &self.ledger, password)?;

        // Prepare error log content if it exists
        if !self.error_log.is_empty() {
            let content = self.error_log.join("\n");
            let log_path = temp_dir.path().join("event.log");
            fs::write(&log_path, &content)?;
        }

        // Create a new zip archive
        let zip_path = Path::new(&self.meta.root_path);
        // Only add .sl if the path does not already end with .sl
        let zip_path = if zip_path.extension().and_then(|s| s.to_str()) == Some("sl") {
            zip_path.to_path_buf()
        } else {
            zip_path.with_extension("sl")
        };
        let file = File::create(&zip_path)?;
        let mut zip = ZipWriter::new(file);

        // Add files to archive from temp directory
        let mut add_file = |name: &str| -> Result<(), LedgerError> {
            let mut file = File::open(temp_dir.path().join(name))?;
            zip.start_file(name, SimpleFileOptions::default())?;
            std::io::copy(&mut file, &mut zip)?;
            Ok(())
        };

        add_file("hash.json")?;
        add_file("meta.json")?;
        add_file("ledger.enc")?;

        if !self.error_log.is_empty() {
            add_file("event.log")?;
        }

        zip.finish()?;

        // Drop the temp_dir to delete all temporary files
        drop(temp_dir);

        Ok(())
    }

    pub fn log_event(&mut self, event: &str) -> Result<(), LedgerError> {
        let timestamp = return_time();
        let log_entry = format!("{} - {}", timestamp, event);
        self.error_log.push(log_entry);
        Ok(())
    }

    pub fn log_error(&mut self, error: &str) -> Result<(), LedgerError> {
        self.log_event(&format!("ERROR: {}", error))?;
        Ok(())
    }

    pub fn log_warning(&mut self, error: &str) -> Result<(), LedgerError> {
        self.log_event(&format!("WARNING: {}", error))?;
        Ok(())
    }
}
