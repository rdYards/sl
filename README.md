# Secure Ledger (sl)

A secure, encrypted ledger system for storing and managing sensitive data with cryptographic verification.

## Features

- **End-to-End Encryption**: All data is encrypted using AES-256-GCM with keys derived from Argon2 password hashing
- **Tamper Detection**: Cryptographic hashing ensures data integrity
- **Error Logging**: Comprehensive event logging for audit trails
- **Modular Design**: Separate components for crypto, ledger management, and error handling
- **Persistence**: Data is stored in encrypted ZIP archives

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
sl = { git = "https://github.com/rdYards/sl.git" }
```

## Usage

### Basic Example

```rust
use sl::SecureLedger;
use sl::types::LedgerEntry;
use std::path::Path;

fn main() {
    // Initialize a new ledger
    let mut ledger = SecureLedger::initialize(None, None).unwrap();

    // Set up metadata
    ledger.update_meta("my_ledger.sl", "My Secure Ledger", "Important documents");

    // Add an entry
    let entry = LedgerEntry {
        id: "doc1".to_string(),
        data: "Confidential information".to_string(),
        timestamp: sl::tools::return_time(),
    };

    let password = "my_secure_password";
    ledger.add_entry(entry, password).unwrap();

    // Save the ledger
    ledger.upload_to_sl(password).unwrap();

    // Load the ledger later
    let loaded_ledger = SecureLedger::initialize(Some(file_path), Some(password)).unwrap();
    println!("Loaded {} entries", loaded_ledger.ledger.len());
}
```

## Testing

Run the test suite:

```bash
cargo test
```


## License

[MIT License](LICENSE) (add your license here)