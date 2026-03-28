use crate::error::LedgerError;
use crate::tools::{return_time, return_time_simple};
use crate::types::{HashInfo, LedgerEntry, MetaData};
use crate::{crypto, crypto::*};
use rand::random;
use std::{
    fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

static VERSION: f32 = 0.3;

#[derive(Debug, Clone)]
pub struct SecureLedger {
    pub meta: MetaData,
    pub ledger: Vec<LedgerEntry>,
    hash_info: HashInfo,
    pub error_log: Vec<String>,
}

impl SecureLedger {
    // initialize if file_path is None then create new ledger
    // if file_path is Some then load file from path
    pub fn initialize(
        file_path: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self, LedgerError> {
        match file_path {
            Some(path) => {
                // Check if file exists
                if !Path::new(path).exists() {
                    return Err(LedgerError::EntryNotFound(format!(
                        "File not found: {}",
                        path
                    )));
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

                // If salt is empty, generate new one
                let hash_info = if hash_info.salt.is_empty() {
                    let salt = random::<[u8; 16]>();
                    HashInfo {
                        salt: hex::encode(salt),
                        ..hash_info
                    }
                } else {
                    hash_info
                };

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
                let error_log = match archive.by_name("event.log") {
                    Ok(mut file) => {
                        let mut error_log_content = String::new();
                        file.read_to_string(&mut error_log_content)?;
                        error_log_content.lines().map(|s| s.to_string()).collect()
                    }
                    Err(_) => vec![], // If file doesn't exist, use empty vector
                };

                // Read ledger.enc and decrypt
                let mut ledger_enc_file = archive.by_name("ledger.enc")?;
                let mut ledger_enc_content = Vec::new();
                ledger_enc_file.read_to_end(&mut ledger_enc_content)?;

                // Decrypt ledger if password is provided
                let ledger = match password {
                    Some(pw) => crypto::decrypt_ledger(&ledger_enc_content, pw)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
                    None => {
                        return Err(LedgerError::InvalidPassword(
                            "Password required to decrypt ledger".to_string(),
                        ));
                    }
                };

                // Verify ledger hash
                let current_hash = check_loaded_with_ledger(&ledger, &hash_info.salt)?;
                if current_hash != meta.ledger_hash {
                    return Err(LedgerError::EntryNotFound(
                        "Ledger hash verification failed - file may have been tampered with"
                            .to_string(),
                    ));
                }

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

                // Generate salt for new ledger
                let salt = random::<[u8; 16]>();
                let hash_info = HashInfo {
                    algorithm: "argon2".to_string(),
                    salt: hex::encode(salt),
                    iterations: 3,
                    hash: String::new(),
                };

                // Take Password and prep hash for ledger
                if let Some(pw) = password {
                    let salt = hex::decode(&hash_info.salt)?;
                    let encoded_salt = SaltString::encode_b64(&salt)?;
                    let argon2 = Argon2::default();
                    let hash = argon2.hash_password(pw.as_bytes(), &encoded_salt)?;
                    let mut new_hash_info = hash_info;
                    new_hash_info.hash = hash.to_string();
                    return Ok(SecureLedger {
                        meta,
                        ledger: vec![],
                        hash_info: new_hash_info,
                        error_log: vec![],
                    });
                } else {
                    return Err(LedgerError::InvalidPassword("No password provided to create Ledger".to_string()));
                }
            }
        }
    }

    // Must be run after initialize to fix file_path
    pub fn update_meta(
        &mut self,
        file_path: &str,
        title: &str,
        description: &str,
    ) -> Result<(), LedgerError> {
        self.meta.root_path = PathBuf::from(file_path);
        self.meta.title = title.to_string();
        self.meta.last_modified = return_time();
        self.meta.description = description.to_string();
        self.log_event("Metadata updated")?;
        Ok(())
    }

    pub fn create_entry(
        &mut self,
        password: &str,
        genre: String,
        data: String,
    ) -> Result<(), LedgerError> {
        // Id based on amoutn of Entries.
        let id = format!("{}-{}", self.ledger.len() + 1, return_time_simple());

        // Create Entry
        let entry = LedgerEntry {
            genre: genre,
            id: id,
            data: data,
            timestamp: return_time(),
        };

        // Add entry
        self.add_entry(entry, password)?;
        Ok(())
    }

    fn add_entry(&mut self, entry: LedgerEntry, password: &str) -> Result<(), LedgerError> {
        // Hash generate for each Entry marked in logs
        let entry_hash = generate_entry_hash(&entry, &self.hash_info.salt)?;
        self.log_event(&format!(
            "Entry {} added with hash: {}",
            entry.id, entry_hash
        ))?;

        self.ledger.push(entry);

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
            self.log_event(&format!("Entry {} removed", id))?;

            // Update the last modified time
            self.meta.last_modified = return_time();

            // If write_on_change is enabled, save immediately
            if self.meta.write_on_change {
                self.upload_to_sl(password)?;
            }

            Ok(())
        } else {
            self.log_event(&format!("Failed to remove entry {}", id))?;
            Err(LedgerError::EntryNotFound(id.to_string()))
        }
    }

    // Searched based on Contains
    pub fn search_entry(&self, query: &str) -> Vec<&LedgerEntry> {
        self.ledger
            .iter()
            .filter(|e| {
                e.id.contains(query) || e.data.contains(query) || e.timestamp.contains(query)
            })
            .collect()
    }

    pub fn upload_to_sl(&mut self, password: &str) -> Result<(), LedgerError> {
        let salt = hex::decode(&self.hash_info.salt)
            .map_err(|e| LedgerError::InvalidSalt(e.to_string()))?;
        if salt.len() != 16 {
            return Err(LedgerError::InvalidSalt(format!(
                "Salt length invalid: {} (must be 16 bytes)",
                salt.len()
            )));
        }
        let salt: [u8; 16] = salt.try_into().unwrap();
        let ledger_hash = generate_ledger_hash(self, &hex::encode(salt))?;
        self.meta.ledger_hash = ledger_hash;
        self.meta.last_modified = return_time();
        self.hash_info.salt = hex::encode(salt);

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
        // Write mimetype file first (must be first in ZIP archive)
        let mimetype_path = temp_dir.path().join("mimetype");
        fs::write(&mimetype_path, "application/secure-ledger")?;

        // Write hash.json
        let hash_path = temp_dir.path().join("hash.json");
        fs::write(&hash_path, serde_json::to_string(&self.hash_info)?)?;

        // Write meta.json
        let meta_path = temp_dir.path().join("meta.json");
        fs::write(&meta_path, serde_json::to_string(&self.meta)?)?;

        // Encrypt and write ledger.enc to temp directory
        encrypt_ledger(
            &temp_dir.path().to_string_lossy(),
            &self.ledger,
            password,
            &self.hash_info,
        )?;

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

        // Add mimetype file first (important for some archive readers)
        let mut mimetype_file = File::open(mimetype_path)?;
        zip.start_file("mimetype", SimpleFileOptions::default())?;
        std::io::copy(&mut mimetype_file, &mut zip)?;

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

    fn log_event(&mut self, event: &str) -> Result<(), LedgerError> {
        let timestamp = return_time();
        let log_entry = format!("{} - {}", timestamp, event);
        self.error_log.push(log_entry);
        Ok(())
    }

    fn log_error(&mut self, error: &str) -> Result<(), LedgerError> {
        self.log_event(&format!("ERROR: {}", error))?;
        Ok(())
    }

    fn log_warning(&mut self, error: &str) -> Result<(), LedgerError> {
        self.log_event(&format!("WARNING: {}", error))?;
        Ok(())
    }
}
