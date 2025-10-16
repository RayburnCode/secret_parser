use crate::types::{AuditEntry, AuditOperation, Config};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde_json;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use uuid::Uuid;

pub struct AuditLogger {
    log_path: Option<String>,
    enabled: bool,
}

impl AuditLogger {
    pub fn new(config: &Config) -> Self {
        Self {
            log_path: config.audit_log_path.clone(),
            enabled: config.audit_log_enabled,
        }
    }

    /// Log an audit entry
    pub fn log(&self, entry: AuditEntry) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let log_path = match &self.log_path {
            Some(path) => path,
            None => return Err(anyhow!("Audit log path not configured")),
        };

        // Expand tilde in path
        let expanded_path = shellexpand::tilde(log_path);
        let path = Path::new(expanded_path.as_ref());

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let mut writer = BufWriter::new(file);
        let json_line = serde_json::to_string(&entry)?;
        writeln!(writer, "{}", json_line)?;
        writer.flush()?;

        Ok(())
    }

    /// Log a successful operation
    pub fn log_success(&self, operation: AuditOperation) -> Result<()> {
        let entry = AuditEntry::new(operation);
        self.log(entry)
    }

    /// Log a successful operation with secret context
    pub fn log_secret_success(&self, operation: AuditOperation, secret_id: Uuid, secret_name: &str) -> Result<()> {
        let mut entry = AuditEntry::new(operation);
        entry.secret_id = Some(secret_id);
        entry.secret_name = Some(secret_name.to_string());
        self.log(entry)
    }

    /// Log a failed operation
    pub fn log_failure(&self, operation: AuditOperation, error: &str) -> Result<()> {
        let entry = AuditEntry::new(operation).with_error(error.to_string());
        self.log(entry)
    }

    /// Log a failed operation with secret context
    pub fn log_secret_failure(&self, operation: AuditOperation, secret_id: Uuid, secret_name: &str, error: &str) -> Result<()> {
        let mut entry = AuditEntry::new(operation).with_error(error.to_string());
        entry.secret_id = Some(secret_id);
        entry.secret_name = Some(secret_name.to_string());
        self.log(entry)
    }

    /// Read audit entries from the log file
    pub fn read_entries(&self, limit: Option<usize>) -> Result<Vec<AuditEntry>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let log_path = match &self.log_path {
            Some(path) => path,
            None => return Err(anyhow!("Audit log path not configured")),
        };

        let expanded_path = shellexpand::tilde(log_path);
        let path = Path::new(expanded_path.as_ref());

        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                entries.push(entry);
            }
        }

        // Sort by timestamp (newest first)
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            entries.truncate(limit);
        }

        Ok(entries)
    }

    /// Get audit entries filtered by operation type
    pub fn read_entries_by_operation(&self, operation: AuditOperation, limit: Option<usize>) -> Result<Vec<AuditEntry>> {
        let entries = self.read_entries(None)?;
        let filtered: Vec<AuditEntry> = entries
            .into_iter()
            .filter(|entry| std::mem::discriminant(&entry.operation) == std::mem::discriminant(&operation))
            .take(limit.unwrap_or(usize::MAX))
            .collect();

        Ok(filtered)
    }

    /// Get failed audit entries only
    pub fn read_failed_entries(&self, limit: Option<usize>) -> Result<Vec<AuditEntry>> {
        let entries = self.read_entries(None)?;
        let failed: Vec<AuditEntry> = entries
            .into_iter()
            .filter(|entry| !entry.success)
            .take(limit.unwrap_or(usize::MAX))
            .collect();

        Ok(failed)
    }

    /// Get audit entries for a specific secret
    pub fn read_entries_for_secret(&self, secret_id: Uuid, limit: Option<usize>) -> Result<Vec<AuditEntry>> {
        let entries = self.read_entries(None)?;
        let filtered: Vec<AuditEntry> = entries
            .into_iter()
            .filter(|entry| entry.secret_id == Some(secret_id))
            .take(limit.unwrap_or(usize::MAX))
            .collect();

        Ok(filtered)
    }

    /// Get audit entries within a date range
    pub fn read_entries_by_date_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<AuditEntry>> {
        let entries = self.read_entries(None)?;
        let filtered: Vec<AuditEntry> = entries
            .into_iter()
            .filter(|entry| entry.timestamp >= start && entry.timestamp <= end)
            .collect();

        Ok(filtered)
    }

    /// Clear the audit log
    pub fn clear_log(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let log_path = match &self.log_path {
            Some(path) => path,
            None => return Err(anyhow!("Audit log path not configured")),
        };

        let expanded_path = shellexpand::tilde(log_path);
        let path = Path::new(expanded_path.as_ref());

        if path.exists() {
            std::fs::remove_file(path)?;
        }

        Ok(())
    }

    /// Export audit log to a different format
    pub fn export_to_csv(&self, output_path: &str) -> Result<()> {
        let entries = self.read_entries(None)?;
        
        let expanded_path = shellexpand::tilde(output_path);
        let path = Path::new(expanded_path.as_ref());

        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write CSV header
        writeln!(writer, "Timestamp,Operation,SecretName,Success,ErrorMessage")?;

        for entry in entries {
            writeln!(
                writer,
                "{},{:?},{},{},{}",
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.operation,
                entry.secret_name.as_deref().unwrap_or("N/A"),
                entry.success,
                entry.error_message.as_deref().unwrap_or("")
            )?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Get audit statistics
    pub fn get_statistics(&self) -> Result<AuditStatistics> {
        let entries = self.read_entries(None)?;
        
        let total_entries = entries.len();
        let successful_operations = entries.iter().filter(|e| e.success).count();
        let failed_operations = entries.iter().filter(|e| !e.success).count();

        let mut operation_counts = std::collections::HashMap::new();
        for entry in &entries {
            *operation_counts.entry(format!("{:?}", entry.operation)).or_insert(0) += 1;
        }

        let most_recent = entries.first().map(|e| e.timestamp);
        let oldest = entries.last().map(|e| e.timestamp);

        Ok(AuditStatistics {
            total_entries,
            successful_operations,
            failed_operations,
            operation_counts,
            most_recent_entry: most_recent,
            oldest_entry: oldest,
        })
    }
}

#[derive(Debug)]
pub struct AuditStatistics {
    pub total_entries: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub operation_counts: std::collections::HashMap<String, usize>,
    pub most_recent_entry: Option<DateTime<Utc>>,
    pub oldest_entry: Option<DateTime<Utc>>,
}

impl std::fmt::Display for AuditStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Audit Log Statistics:")?;
        writeln!(f, "  Total Entries: {}", self.total_entries)?;
        writeln!(f, "  Successful Operations: {}", self.successful_operations)?;
        writeln!(f, "  Failed Operations: {}", self.failed_operations)?;
        
        if let Some(recent) = self.most_recent_entry {
            writeln!(f, "  Most Recent: {}", recent.format("%Y-%m-%d %H:%M UTC"))?;
        }
        
        if let Some(oldest) = self.oldest_entry {
            writeln!(f, "  Oldest Entry: {}", oldest.format("%Y-%m-%d %H:%M UTC"))?;
        }

        writeln!(f, "  Operation Counts:")?;
        for (operation, count) in &self.operation_counts {
            writeln!(f, "    {}: {}", operation, count)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_audit_logger() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("audit.log").to_string_lossy().to_string();
        
        let mut config = Config::default();
        config.audit_log_path = Some(log_path);
        config.audit_log_enabled = true;

        let logger = AuditLogger::new(&config);

        // Test logging success
        logger.log_success(AuditOperation::Create).unwrap();

        // Test logging failure
        logger.log_failure(AuditOperation::Read, "Test error").unwrap();

        // Read entries
        let entries = logger.read_entries(None).unwrap();
        assert_eq!(entries.len(), 2);

        // Test statistics
        let stats = logger.get_statistics().unwrap();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.failed_operations, 1);
    }
}