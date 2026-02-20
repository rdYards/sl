use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::LedgerError;

pub fn log_event(root_path: &str, event: &str) -> Result<(), LedgerError> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let log_file = Path::new(root_path).join("events.log");

    // Create or append to events.log
    let log_entry = format!("{}: {}\n", timestamp, event);

    // Append to the log file
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(log_file)?;

    file.write_all(log_entry.as_bytes())?;

    Ok(())
}

pub fn log_error(root_path: &str, error: &str) -> Result<(), LedgerError> {
    log_event(root_path, &format!("ERROR: {}", error))?;
    Ok(())
}
