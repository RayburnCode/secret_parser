use crate::crypto::CryptoManager;
use crate::types::{Config, SecretStore};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub store_version: String,
    pub secrets_count: usize,
    pub compressed: bool,
    pub encrypted: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub metadata: BackupMetadata,
    pub data: Vec<u8>, // Can be plain JSON, compressed, or encrypted
}

pub struct BackupManager {
    config: Config,
}

impl BackupManager {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Create a backup of the secret store
    pub fn create_backup(
        &self,
        store: &SecretStore,
        crypto: &CryptoManager,
        description: Option<String>,
    ) -> Result<String> {
        let backup_path = self.get_backup_path()?;
        
        // Create backup directory if it doesn't exist
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize the store
        let json_data = serde_json::to_string_pretty(store)?;
        let data_bytes = json_data.as_bytes();

        // Compress the data
        let compressed_data = self.compress_data(data_bytes)?;

        // Encrypt the compressed data
        let encrypted_data = crypto.encrypt(&compressed_data)?;

        // Create backup metadata
        let metadata = BackupMetadata {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            store_version: store.version.clone(),
            secrets_count: store.secrets.len(),
            compressed: true,
            encrypted: true,
            description,
        };

        // Create backup file
        let backup_file = BackupFile {
            metadata,
            data: encrypted_data,
        };

        // Write backup to file
        let file = File::create(&backup_path)?;
        let mut writer = BufWriter::new(file);
        let backup_json = serde_json::to_string_pretty(&backup_file)?;
        writer.write_all(backup_json.as_bytes())?;
        writer.flush()?;

        // Clean old backups if configured
        self.cleanup_old_backups()?;

        Ok(backup_path.to_string_lossy().to_string())
    }

    /// Restore from a backup file
    pub fn restore_backup(
        &self,
        backup_path: &str,
        crypto: &CryptoManager,
    ) -> Result<SecretStore> {
        let path = Path::new(backup_path);
        if !path.exists() {
            return Err(anyhow!("Backup file does not exist: {}", backup_path));
        }

        // Read backup file
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let backup_file: BackupFile = serde_json::from_reader(reader)?;

        // Decrypt the data
        let decrypted_data = if backup_file.metadata.encrypted {
            crypto.decrypt(&backup_file.data)?
        } else {
            backup_file.data
        };

        // Decompress the data
        let decompressed_data = if backup_file.metadata.compressed {
            self.decompress_data(&decrypted_data)?
        } else {
            decrypted_data
        };

        // Deserialize the store
        let json_str = String::from_utf8(decompressed_data)?;
        let store: SecretStore = serde_json::from_str(&json_str)?;

        Ok(store)
    }

    /// List available backups
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        let backup_dir = self.get_backup_dir()?;
        if !backup_dir.exists() {
            return Ok(Vec::new());
        }

        let mut backups = Vec::new();

        for entry in fs::read_dir(&backup_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("bak") {
                if let Ok(info) = self.get_backup_info(&path) {
                    backups.push(info);
                }
            }
        }

        // Sort by creation date (newest first)
        backups.sort_by(|a, b| b.metadata.created_at.cmp(&a.metadata.created_at));

        Ok(backups)
    }

    /// Get information about a specific backup
    pub fn get_backup_info(&self, backup_path: &Path) -> Result<BackupInfo> {
        let file = File::open(backup_path)?;
        let reader = BufReader::new(file);
        let backup_file: BackupFile = serde_json::from_reader(reader)?;

        let file_size = backup_path.metadata()?.len();

        Ok(BackupInfo {
            path: backup_path.to_string_lossy().to_string(),
            metadata: backup_file.metadata,
            file_size_bytes: file_size,
        })
    }

    /// Delete a backup file
    pub fn delete_backup(&self, backup_path: &str) -> Result<()> {
        let path = Path::new(backup_path);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Export secrets to various formats
    pub fn export_secrets(
        &self,
        store: &SecretStore,
        format: ExportFormat,
        output_path: &str,
        include_metadata: bool,
        encrypt: bool,
        crypto: Option<&CryptoManager>,
    ) -> Result<()> {
        let data = match format {
            ExportFormat::Json => self.export_to_json(store, include_metadata)?,
            ExportFormat::Csv => self.export_to_csv(store)?,
        };

        let final_data = if encrypt {
            if let Some(crypto_manager) = crypto {
                crypto_manager.encrypt(data.as_bytes())?
            } else {
                return Err(anyhow!("Crypto manager required for encryption"));
            }
        } else {
            data.into_bytes()
        };

        let path = Path::new(output_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, final_data)?;
        Ok(())
    }

    /// Import secrets from a file
    pub fn import_secrets(
        &self,
        input_path: &str,
        format: ExportFormat,
        merge: bool,
        encrypted: bool,
        crypto: Option<&CryptoManager>,
    ) -> Result<SecretStore> {
        let path = Path::new(input_path);
        if !path.exists() {
            return Err(anyhow!("Import file does not exist: {}", input_path));
        }

        let file_data = fs::read(path)?;

        let data_str = if encrypted {
            if let Some(crypto_manager) = crypto {
                let decrypted = crypto_manager.decrypt(&file_data)?;
                String::from_utf8(decrypted)?
            } else {
                return Err(anyhow!("Crypto manager required for decryption"));
            }
        } else {
            String::from_utf8(file_data)?
        };

        let imported_store = match format {
            ExportFormat::Json => self.import_from_json(&data_str)?,
            ExportFormat::Csv => self.import_from_csv(&data_str)?,
        };

        Ok(imported_store)
    }

    // Private helper methods

    fn get_backup_path(&self) -> Result<PathBuf> {
        let backup_dir = self.get_backup_dir()?;
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("secret_backup_{}.bak", timestamp);
        Ok(backup_dir.join(filename))
    }

    fn get_backup_dir(&self) -> Result<PathBuf> {
        let backup_path = self.config.backup_path.as_ref()
            .ok_or_else(|| anyhow!("Backup path not configured"))?;
        
        let expanded_path = shellexpand::tilde(backup_path);
        Ok(PathBuf::from(expanded_path.as_ref()))
    }

    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simple compression using flate2 (would need to add dependency)
        // For now, just return the data as-is
        Ok(data.to_vec())
    }

    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Decompression counterpart
        // For now, just return the data as-is
        Ok(data.to_vec())
    }

    fn cleanup_old_backups(&self) -> Result<()> {
        let backups = self.list_backups()?;
        let max_backups = self.config.max_backups;

        if backups.len() > max_backups {
            let to_delete = &backups[max_backups..];
            for backup in to_delete {
                if let Err(e) = self.delete_backup(&backup.path) {
                    eprintln!("Warning: Failed to delete old backup {}: {}", backup.path, e);
                }
            }
        }

        Ok(())
    }

    fn export_to_json(&self, store: &SecretStore, include_metadata: bool) -> Result<String> {
        if include_metadata {
            serde_json::to_string_pretty(store).map_err(|e| anyhow!("JSON export failed: {}", e))
        } else {
            // Export only the secrets without metadata
            let secrets: Vec<_> = store.secrets.values().collect();
            serde_json::to_string_pretty(&secrets).map_err(|e| anyhow!("JSON export failed: {}", e))
        }
    }

    fn export_to_csv(&self, store: &SecretStore) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("Name,Value,Category,Description,Tags,Created,Updated\n");

        for secret in store.secrets.values() {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                self.escape_csv(&secret.name),
                self.escape_csv(&secret.value),
                self.escape_csv(secret.category.as_deref().unwrap_or("")),
                self.escape_csv(secret.description.as_deref().unwrap_or("")),
                self.escape_csv(&secret.tags.join(";")),
                secret.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                secret.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            ));
        }

        Ok(csv)
    }

    fn import_from_json(&self, data: &str) -> Result<SecretStore> {
        serde_json::from_str(data).map_err(|e| anyhow!("JSON import failed: {}", e))
    }

    fn import_from_csv(&self, _data: &str) -> Result<SecretStore> {
        // CSV import would be more complex, requiring parsing
        // For now, return an error
        Err(anyhow!("CSV import not yet implemented"))
    }

    fn escape_csv(&self, value: &str) -> String {
        if value.contains(',') || value.contains('"') || value.contains('\n') {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub path: String,
    pub metadata: BackupMetadata,
    pub file_size_bytes: u64,
}

impl BackupInfo {
    pub fn file_size_human(&self) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
        let mut size = self.file_size_bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
}

impl std::str::FromStr for ExportFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ExportFormat::Json),
            "csv" => Ok(ExportFormat::Csv),
            _ => Err(anyhow!("Unsupported format: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;
    use tempfile::tempdir;

    #[test]
    fn test_backup_and_restore() {
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("backups");
        
        let mut config = Config::default();
        config.backup_path = Some(backup_path.to_string_lossy().to_string());

        let backup_manager = BackupManager::new(config);
        let mut store = SecretStore::new();
        
        // Add a test secret
        let secret = crate::types::Secret::new("test".to_string(), "value".to_string());
        store.add_secret(secret);

        // Create crypto manager
        let salt = MasterKey::generate_salt();
        let master_key = MasterKey::from_password("test_password", &salt, 10000);
        let crypto = CryptoManager::new(master_key);

        // Create backup
        let backup_path = backup_manager.create_backup(&store, &crypto, Some("test backup".to_string())).unwrap();

        // Restore backup
        let restored_store = backup_manager.restore_backup(&backup_path, &crypto).unwrap();

        assert_eq!(store.secrets.len(), restored_store.secrets.len());
    }
}