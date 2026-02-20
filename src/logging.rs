use std::fs;
use std::path::Path;

use crate::error::LedgerError;

pub fn log_event(root_path: &str, event: &str) -> Result<(), LedgerError> {
    let logs_path = Path::new(root_path).join("logs");
    let timestamp = chrono::Utc::now().to_rfc3339();

    let log_entry = serde_json::json!({
        "timestamp": timestamp,
        "event": event,
        "user": "system"
    });

    let log_file = logs_path.join(format!("{}.json", timestamp.replace(":", "-")));
    fs::write(log_file, serde_json::to_string_pretty(&log_entry)?)?;

    Ok(())
}

pub fn log_error(root_path: &str, error: &str) -> Result<(), LedgerError> {
    log_event(root_path, &format!("ERROR: {}", error))?;
    Ok(())
}