use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub name: String,
    pub value: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl Secret {
    pub fn new(name: String, value: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            value,
            category: None,
            description: None,
            created_at: now,
            updated_at: now,
            last_accessed: None,
            expires_at: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_category(mut self, category: String) -> Self {
        self.category = Some(category);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn mark_accessed(&mut self) {
        self.last_accessed = Some(Utc::now());
    }

    pub fn update_value(&mut self, new_value: String) {
        self.value = new_value;
        self.updated_at = Utc::now();
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretStore {
    pub secrets: HashMap<Uuid, Secret>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: String,
}

impl SecretStore {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            secrets: HashMap::new(),
            created_at: now,
            updated_at: now,
            version: "1.0".to_string(),
        }
    }

    pub fn add_secret(&mut self, secret: Secret) {
        self.secrets.insert(secret.id, secret);
        self.updated_at = Utc::now();
    }

    pub fn get_secret(&mut self, id: &Uuid) -> Option<&mut Secret> {
        if let Some(secret) = self.secrets.get_mut(id) {
            secret.mark_accessed();
            Some(secret)
        } else {
            None
        }
    }

    pub fn get_secret_by_name(&mut self, name: &str) -> Option<&mut Secret> {
        let id = self.secrets
            .values()
            .find(|s| s.name == name)
            .map(|s| s.id)?;
        self.get_secret(&id)
    }

    pub fn remove_secret(&mut self, id: &Uuid) -> Option<Secret> {
        self.updated_at = Utc::now();
        self.secrets.remove(id)
    }

    pub fn list_secrets(&self) -> Vec<&Secret> {
        self.secrets.values().collect()
    }

    pub fn search_secrets(&self, query: &str) -> Vec<&Secret> {
        let query_lower = query.to_lowercase();
        self.secrets
            .values()
            .filter(|secret| {
                secret.name.to_lowercase().contains(&query_lower)
                    || secret.description.as_ref().map_or(false, |d| d.to_lowercase().contains(&query_lower))
                    || secret.category.as_ref().map_or(false, |c| c.to_lowercase().contains(&query_lower))
                    || secret.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    #[allow(dead_code)]
    pub fn get_expired_secrets(&self) -> Vec<&Secret> {
        self.secrets
            .values()
            .filter(|secret| secret.is_expired())
            .collect()
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub store_path: String,
    pub backup_path: Option<String>,
    pub auto_backup: bool,
    pub backup_interval_hours: u64,
    pub max_backups: usize,
    pub audit_log_enabled: bool,
    pub audit_log_path: Option<String>,
    pub master_password_hint: Option<String>,
    pub encryption_iterations: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            store_path: "~/.secret/store.enc".to_string(),
            backup_path: Some("~/.secret/backups/".to_string()),
            auto_backup: true,
            backup_interval_hours: 6,
            max_backups: 10,
            audit_log_enabled: true,
            audit_log_path: Some("~/.secret/audit.log".to_string()),
            master_password_hint: None,
            encryption_iterations: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub operation: AuditOperation,
    pub secret_id: Option<Uuid>,
    pub secret_name: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub client_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperation {
    Create,
    Read,
    Update,
    Delete,
    List,
    Search,
    Backup,
    Restore,
    Export,
    Import,
    Login,
    Logout,
}

impl AuditEntry {
    pub fn new(operation: AuditOperation) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            operation,
            secret_id: None,
            secret_name: None,
            success: true,
            error_message: None,
            client_info: None,
        }
    }

    pub fn with_secret(mut self, secret: &Secret) -> Self {
        self.secret_id = Some(secret.id);
        self.secret_name = Some(secret.name.clone());
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.success = false;
        self.error_message = Some(error);
        self
    }
}

/// Secure wrapper for sensitive data that gets zeroized on drop
#[allow(dead_code)]
#[derive(Clone)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn into_string(self) -> String {
        self.inner.clone()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureString")
            .field("inner", &"[REDACTED]")
            .finish()
    }
}