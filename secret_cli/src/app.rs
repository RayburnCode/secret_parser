use crate::audit_log::AuditLogger;
use crate::backups::{BackupManager, ExportFormat};
use crate::cli::{Cli, Commands, BackupCommands, HealthCommands, RotationCommands, AuditCommands, ConfigCommands};
use crate::crypto::{CryptoManager, MasterKey, password};
use crate::health_check::HealthChecker;
use crate::rotation::RotationManager;
use crate::terminal_ui::run_tui;
use crate::types::{Config, Secret, SecretStore, AuditOperation};
use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::Parser;
use colored::*;
use dirs;
use rpassword;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;

pub struct SecretApp {
    config: Config,
    crypto: Option<CryptoManager>,
    store: Option<SecretStore>,
    salt: Option<[u8; 16]>, // Store the salt for subsequent save operations
    audit_logger: AuditLogger,
    backup_manager: BackupManager,
    health_checker: HealthChecker,
    rotation_manager: RotationManager,
}

impl SecretApp {
    pub fn new() -> Result<Self> {
        let config = Self::load_or_create_config()?;
        let audit_logger = AuditLogger::new(&config);
        let backup_manager = BackupManager::new(config.clone());
        let health_checker = HealthChecker::new();
        let rotation_manager = RotationManager::new();

        Ok(Self {
            config,
            crypto: None,
            store: None,
            salt: None,
            audit_logger,
            backup_manager,
            health_checker,
            rotation_manager,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let cli = Cli::parse();

        match &cli.command {
            Commands::Init { path, force } => {
                self.init_store(path.as_deref(), *force)?;
            }
            Commands::Ui => {
                self.ensure_authenticated()?;
                if let Some(store) = self.store.take() {
                    let updated_store = run_tui(store)?;
                    self.store = Some(updated_store);
                    self.save_store()?;
                }
            }
            _ => {
                self.ensure_authenticated()?;
                self.handle_command(&cli.command).await?;
            }
        }

        Ok(())
    }

    async fn handle_command(&mut self, command: &Commands) -> Result<()> {
        match command {
            Commands::Add { name, value, category, description, tags, expires, generate, length } => {
                let secret_value = if *generate {
                    self.generate_password(*length)
                } else if let Some(v) = value {
                    v.clone()
                } else {
                    self.prompt_for_secret("Enter secret value")?
                };

                let mut secret = Secret::new(name.clone(), secret_value);

                if let Some(cat) = category {
                    secret = secret.with_category(cat.clone());
                }

                if let Some(desc) = description {
                    secret = secret.with_description(desc.clone());
                }

                if let Some(tag_str) = tags {
                    let tag_vec: Vec<String> = tag_str.split(',').map(|s| s.trim().to_string()).collect();
                    secret = secret.with_tags(tag_vec);
                }

                if let Some(expires_str) = expires {
                    let expires_date = chrono::DateTime::parse_from_rfc3339(expires_str)?;
                    secret = secret.with_expiration(expires_date.with_timezone(&Utc));
                }

                if let Some(store) = &mut self.store {
                    store.add_secret(secret.clone());
                    self.save_store()?;
                    self.audit_logger.log_secret_success(AuditOperation::Create, secret.id, &secret.name)?;
                    println!("{}", "Secret added successfully!".green());
                }
            }

            Commands::Get { identifier, copy, full } => {
                if let Some(store) = &mut self.store {
                    let secret_info = if let Ok(uuid) = uuid::Uuid::parse_str(identifier) {
                        store.get_secret(&uuid).map(|s| (s.id, s.name.clone(), s.value.clone()))
                    } else {
                        store.get_secret_by_name(identifier).map(|s| (s.id, s.name.clone(), s.value.clone()))
                    };

                    if let Some((secret_id, secret_name, secret_value)) = secret_info {
                        if *copy {
                            // Copy to clipboard (would need clipboard dependency)
                            println!("{}", "Secret copied to clipboard!".green());
                        } else if *full {
                            // Display full secret info without borrowing self
                            if let Some(secret) = store.secrets.get(&secret_id) {
                                println!("{}: {}", "ID".yellow().bold(), secret.id);
                                println!("{}: {}", "Name".yellow().bold(), secret.name);
                                println!("{}: {}", "Value".yellow().bold(), secret.value);
                                if let Some(category) = &secret.category {
                                    println!("{}: {}", "Category".yellow().bold(), category);
                                }
                                if let Some(description) = &secret.description {
                                    println!("{}: {}", "Description".yellow().bold(), description);
                                }
                                if !secret.tags.is_empty() {
                                    println!("{}: {}", "Tags".yellow().bold(), secret.tags.join(", "));
                                }
                                println!("{}: {}", "Created".yellow().bold(), secret.created_at.format("%Y-%m-%d %H:%M UTC"));
                                println!("{}: {}", "Updated".yellow().bold(), secret.updated_at.format("%Y-%m-%d %H:%M UTC"));
                                if let Some(accessed) = secret.last_accessed {
                                    println!("{}: {}", "Last Accessed".yellow().bold(), accessed.format("%Y-%m-%d %H:%M UTC"));
                                }
                                if let Some(expires) = secret.expires_at {
                                    println!("{}: {}", "Expires".yellow().bold(), expires.format("%Y-%m-%d %H:%M UTC"));
                                }
                            }
                        } else {
                            println!("{}: {}", "Name".yellow().bold(), secret_name);
                            println!("{}: {}", "Value".yellow().bold(), "*".repeat(secret_value.len().min(8)));
                        }
                        self.audit_logger.log_secret_success(AuditOperation::Read, secret_id, &secret_name)?;
                    } else {
                        return Err(anyhow!("Secret not found: {}", identifier));
                    }
                }
            }

            Commands::List { category, tag, expired, format, show_values } => {
                if let Some(store) = &self.store {
                    let mut secrets: Vec<&Secret> = store.list_secrets();

                    // Apply filters
                    if let Some(cat) = category {
                        secrets.retain(|s| s.category.as_deref() == Some(cat));
                    }

                    if let Some(tag_filter) = tag {
                        secrets.retain(|s| s.tags.contains(tag_filter));
                    }

                    if *expired {
                        secrets.retain(|s| s.is_expired());
                    }

                    match format.as_str() {
                        "json" => {
                            let json = serde_json::to_string_pretty(&secrets)?;
                            println!("{}", json);
                        }
                        "csv" => {
                            self.print_secrets_csv(&secrets, *show_values);
                        }
                        _ => {
                            self.print_secrets_table(&secrets, *show_values);
                        }
                    }

                    self.audit_logger.log_success(AuditOperation::List)?;
                }
            }

            Commands::Search { query, case_sensitive: _ } => {
                if let Some(store) = &self.store {
                    let results = store.search_secrets(query);
                    self.print_secrets_table(&results, false);
                    self.audit_logger.log_success(AuditOperation::Search)?;
                }
            }

            Commands::Delete { identifier, force } => {
                if let Some(store) = &mut self.store {
                    let secret_info = if let Ok(uuid) = uuid::Uuid::parse_str(identifier) {
                        store.secrets.get(&uuid).map(|s| (s.id, s.name.clone()))
                    } else {
                        store.secrets.values().find(|s| s.name.as_str() == identifier).map(|s| (s.id, s.name.clone()))
                    };

                    if let Some((secret_id, secret_name)) = secret_info {
                        if !force {
                            print!("Are you sure you want to delete '{}'? (y/N): ", secret_name);
                            io::stdout().flush()?;
                            let mut input = String::new();
                            io::stdin().read_line(&mut input)?;
                            if !input.trim().to_lowercase().starts_with('y') {
                                println!("Deletion cancelled.");
                                return Ok(());
                            }
                        }

                        store.remove_secret(&secret_id);
                        self.save_store()?;
                        self.audit_logger.log_secret_success(AuditOperation::Delete, secret_id, &secret_name)?;
                        println!("{}", format!("Secret '{}' deleted!", secret_name).yellow());
                    } else {
                        return Err(anyhow!("Secret not found: {}", identifier));
                    }
                }
            }

            Commands::Update { identifier, value, category, description, tags, expires } => {
                if let Some(store) = &mut self.store {
                    let secret_id = if let Ok(uuid) = uuid::Uuid::parse_str(identifier) {
                        if store.secrets.contains_key(&uuid) { Some(uuid) } else { None }
                    } else {
                        store.secrets.values().find(|s| s.name.as_str() == identifier).map(|s| s.id)
                    };

                    if let Some(id) = secret_id {
                        let secret_name = store.secrets.get(&id).unwrap().name.clone();

                        if let Some(secret) = store.secrets.get_mut(&id) {
                            if let Some(new_value) = value {
                                secret.update_value(new_value.clone());
                            }

                            if let Some(cat) = category {
                                secret.category = Some(cat.clone());
                            }

                            if let Some(desc) = description {
                                secret.description = Some(desc.clone());
                            }

                            if let Some(tag_str) = tags {
                                let tag_vec: Vec<String> = tag_str.split(',').map(|s| s.trim().to_string()).collect();
                                secret.tags = tag_vec;
                            }

                            if let Some(expires_str) = expires {
                                let expires_date = chrono::DateTime::parse_from_rfc3339(expires_str)?;
                                secret.expires_at = Some(expires_date.with_timezone(&Utc));
                            }
                        }

                        self.save_store()?;
                        self.audit_logger.log_secret_success(AuditOperation::Update, id, &secret_name)?;
                        println!("{}", "Secret updated successfully!".green());
                    } else {
                        return Err(anyhow!("Secret not found: {}", identifier));
                    }
                }
            }

            Commands::Backup { action } => {
                self.handle_backup_command(action).await?;
            }

            Commands::Health { action } => {
                self.handle_health_command(action).await?;
            }

            Commands::Rotate { action } => {
                self.handle_rotation_command(action).await?;
            }

            Commands::Audit { action } => {
                self.handle_audit_command(action).await?;
            }

            Commands::Config { action } => {
                self.handle_config_command(action).await?;
            }

            Commands::Export { file, format, metadata, encrypt } => {
                if let Some(store) = &self.store {
                    let export_format = ExportFormat::from_str(format)?;
                    let crypto = if *encrypt { self.crypto.as_ref() } else { None };
                    
                    self.backup_manager.export_secrets(
                        store,
                        export_format,
                        file,
                        *metadata,
                        *encrypt,
                        crypto,
                    )?;
                    
                    self.audit_logger.log_success(AuditOperation::Export)?;
                    println!("{}", format!("Secrets exported to {}", file).green());
                }
            }

            Commands::Import { file, format, merge } => {
                let export_format = ExportFormat::from_str(format)?;
                let imported_store = self.backup_manager.import_secrets(
                    file,
                    export_format,
                    *merge,
                    false, // assume not encrypted for now
                    None,
                )?;

                if *merge {
                    if let Some(current_store) = &mut self.store {
                        for (_, secret) in imported_store.secrets {
                            current_store.add_secret(secret);
                        }
                    }
                } else {
                    self.store = Some(imported_store);
                }

                self.save_store()?;
                self.audit_logger.log_success(AuditOperation::Import)?;
                println!("{}", "Secrets imported successfully!".green());
            }

            Commands::Generate { length, symbols, numbers, uppercase, lowercase, copy } => {
                let password = self.generate_custom_password(*length, *symbols, *numbers, *uppercase, *lowercase);
                
                if *copy {
                    println!("{}", "Password copied to clipboard!".green());
                } else {
                    println!("Generated password: {}", password.bright_green());
                }
            }

            Commands::ChangePassword => {
                self.change_master_password()?;
            }

            _ => {
                return Err(anyhow!("Command not implemented yet"));
            }
        }

        Ok(())
    }

    // Helper methods (private)
    
    fn ensure_authenticated(&mut self) -> Result<()> {
        if self.crypto.is_none() || self.store.is_none() {
            self.authenticate()?;
        }
        Ok(())
    }

    fn authenticate(&mut self) -> Result<()> {
        let store_path = shellexpand::tilde(&self.config.store_path);
        let store_path = Path::new(store_path.as_ref());

        if !store_path.exists() {
            return Err(anyhow!("Store not initialized. Run 'secret init' first."));
        }

        let password = self.prompt_for_password("Enter master password")?;
        let encrypted_store_data = fs::read(store_path)?;

        // Extract salt from stored data
        let (salt, encrypted_data) = CryptoManager::extract_salt_from_store(&encrypted_store_data)?;
        
        // Derive key using extracted salt
        let master_key = MasterKey::from_password(&password, &salt, self.config.encryption_iterations);
        let crypto = CryptoManager::new(master_key);

        match crypto.decrypt(&encrypted_data) {
            Ok(decrypted_data) => {
                let json_str = String::from_utf8(decrypted_data)?;
                let store: SecretStore = serde_json::from_str(&json_str)?;
                self.crypto = Some(crypto);
                self.store = Some(store);
                self.salt = Some(salt); // Store the salt for future saves
                self.audit_logger.log_success(AuditOperation::Login)?;
                Ok(())
            }
            Err(_) => {
                self.audit_logger.log_failure(AuditOperation::Login, "Invalid password")?;
                Err(anyhow!("Invalid master password"))
            }
        }
    }

    fn save_store(&self) -> Result<()> {
        if let (Some(crypto), Some(store), Some(salt)) = (&self.crypto, &self.store, &self.salt) {
            let json_data = serde_json::to_string_pretty(store)?;
            let encrypted_data = crypto.encrypt_with_salt(json_data.as_bytes(), salt)?;
            
            let store_path = shellexpand::tilde(&self.config.store_path);
            let store_path = Path::new(store_path.as_ref());
            
            if let Some(parent) = store_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            fs::write(store_path, encrypted_data)?;
        }
        Ok(())
    }

    // Implementation continues with helper methods...
    
    fn prompt_for_password(&self, prompt: &str) -> Result<String> {
        print!("{}: ", prompt);
        io::stdout().flush()?;
        rpassword::read_password().map_err(|e| anyhow!("Failed to read password: {}", e))
    }

    fn prompt_for_secret(&self, prompt: &str) -> Result<String> {
        print!("{}: ", prompt);
        io::stdout().flush()?;
        rpassword::read_password().map_err(|e| anyhow!("Failed to read secret: {}", e))
    }

    fn generate_password(&self, length: usize) -> String {
        use crate::rotation::RotationManager;
        RotationManager::generate_complex_password(length)
    }

    fn generate_custom_password(&self, length: usize, symbols: bool, numbers: bool, uppercase: bool, lowercase: bool) -> String {
        let mut charset = String::new();
        
        if lowercase {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
        if uppercase {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if numbers {
            charset.push_str("0123456789");
        }
        if symbols {
            charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
        }

        if charset.is_empty() {
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string();
        }

        use rand::{thread_rng, Rng};
        (0..length)
            .map(|_| {
                let idx = thread_rng().gen_range(0..charset.len());
                charset.chars().nth(idx).unwrap()
            })
            .collect()
    }



    fn display_secret_brief(&self, secret: &Secret) {
        println!("{}: {}", "Name".yellow().bold(), secret.name);
        println!("{}: {}", "Value".yellow().bold(), "*".repeat(secret.value.len().min(8)));
        if let Some(category) = &secret.category {
            println!("{}: {}", "Category".yellow().bold(), category);
        }
    }

    fn display_secret_full(&self, secret: &Secret) {
        println!("{}: {}", "ID".yellow().bold(), secret.id);
        println!("{}: {}", "Name".yellow().bold(), secret.name);
        println!("{}: {}", "Value".yellow().bold(), secret.value);
        if let Some(category) = &secret.category {
            println!("{}: {}", "Category".yellow().bold(), category);
        }
        if let Some(description) = &secret.description {
            println!("{}: {}", "Description".yellow().bold(), description);
        }
        if !secret.tags.is_empty() {
            println!("{}: {}", "Tags".yellow().bold(), secret.tags.join(", "));
        }
        println!("{}: {}", "Created".yellow().bold(), secret.created_at.format("%Y-%m-%d %H:%M UTC"));
        println!("{}: {}", "Updated".yellow().bold(), secret.updated_at.format("%Y-%m-%d %H:%M UTC"));
        if let Some(accessed) = secret.last_accessed {
            println!("{}: {}", "Last Accessed".yellow().bold(), accessed.format("%Y-%m-%d %H:%M UTC"));
        }
        if let Some(expires) = secret.expires_at {
            println!("{}: {}", "Expires".yellow().bold(), expires.format("%Y-%m-%d %H:%M UTC"));
        }
    }

    fn print_secrets_table(&self, secrets: &[&Secret], show_values: bool) {
        if secrets.is_empty() {
            println!("No secrets found.");
            return;
        }

        println!("{:<30} {:<20} {:<15} {:<10}", "Name".yellow().bold(), "Category".yellow().bold(), "Age".yellow().bold(), "Status".yellow().bold());
        println!("{}", "-".repeat(80));

        for secret in secrets {
            let category = secret.category.as_deref().unwrap_or("-");
            let age = {
                let duration = Utc::now() - secret.created_at;
                if duration.num_days() > 0 {
                    format!("{}d", duration.num_days())
                } else if duration.num_hours() > 0 {
                    format!("{}h", duration.num_hours())
                } else {
                    format!("{}m", duration.num_minutes())
                }
            };

            let status = if secret.is_expired() {
                "EXPIRED".red()
            } else if secret.expires_at.is_some() {
                "TEMP".yellow()
            } else {
                "OK".green()
            };

            println!("{:<30} {:<20} {:<15} {:<10}", 
                secret.name.bright_white(), 
                category, 
                age, 
                status
            );

            if show_values {
                println!("  {}: {}", "Value".bright_black(), secret.value.bright_black());
            }
        }
    }

    fn print_secrets_csv(&self, secrets: &[&Secret], show_values: bool) {
        if show_values {
            println!("Name,Value,Category,Created,Updated");
            for secret in secrets {
                println!("{},{},{},{},{}", 
                    secret.name,
                    secret.value,
                    secret.category.as_deref().unwrap_or(""),
                    secret.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    secret.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        } else {
            println!("Name,Category,Created,Updated");
            for secret in secrets {
                println!("{},{},{},{}", 
                    secret.name,
                    secret.category.as_deref().unwrap_or(""),
                    secret.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                    secret.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }
    }

    fn init_store(&mut self, path: Option<&str>, force: bool) -> Result<()> {
        let store_path = if let Some(p) = path {
            p.to_string()
        } else {
            self.config.store_path.clone()
        };

        let expanded_path = shellexpand::tilde(&store_path);
        let path = Path::new(expanded_path.as_ref());

        if path.exists() && !force {
            return Err(anyhow!("Store already exists. Use --force to overwrite."));
        }

        println!("Initializing new secret store...");
        
        let password = self.prompt_for_password("Enter master password")?;
        
        // Validate password strength
        if let Err(e) = password::validate_strength(&password) {
            return Err(anyhow!("Password validation failed: {}", e));
        }

        let password_confirm = self.prompt_for_password("Confirm master password")?;
        
        if password != password_confirm {
            return Err(anyhow!("Passwords do not match"));
        }

        // Create directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Initialize crypto
        let salt = MasterKey::generate_salt();
        let master_key = MasterKey::from_password(&password, &salt, self.config.encryption_iterations);
        let crypto = CryptoManager::new(master_key);

        // Create empty store
        let store = SecretStore::new();
        let json_data = serde_json::to_string_pretty(&store)?;
        let encrypted_data = crypto.encrypt_with_salt(json_data.as_bytes(), &salt)?;

        // Save encrypted store (includes salt)
        fs::write(path, encrypted_data)?;

        // Update app state
        self.crypto = Some(crypto);
        self.store = Some(store);
        self.salt = Some(salt); // Store the salt for future saves

        println!("{}", "Secret store initialized successfully!".green());
        Ok(())
    }

    fn change_master_password(&mut self) -> Result<()> {
        println!("Changing master password...");
        
        let old_password = self.prompt_for_password("Enter current master password")?;
        let new_password = self.prompt_for_password("Enter new master password")?;
        
        // Validate new password strength
        if let Err(e) = password::validate_strength(&new_password) {
            return Err(anyhow!("New password validation failed: {}", e));
        }

        let confirm_password = self.prompt_for_password("Confirm new master password")?;
        
        if new_password != confirm_password {
            return Err(anyhow!("New passwords do not match"));
        }

        // Verify old password by trying to decrypt
        let store_path = shellexpand::tilde(&self.config.store_path);
        let encrypted_data = fs::read(Path::new(store_path.as_ref()))?;
        
        let salt = MasterKey::generate_salt(); // Should load the actual salt
        let old_master_key = MasterKey::from_password(&old_password, &salt, self.config.encryption_iterations);
        let old_crypto = CryptoManager::new(old_master_key);

        match old_crypto.decrypt(&encrypted_data) {
            Ok(decrypted_data) => {
                // Create new crypto with new password
                let new_salt = MasterKey::generate_salt();
                let new_master_key = MasterKey::from_password(&new_password, &new_salt, self.config.encryption_iterations);
                let new_crypto = CryptoManager::new(new_master_key);

                // Re-encrypt with new password
                let new_encrypted_data = new_crypto.encrypt(&decrypted_data)?;
                fs::write(Path::new(store_path.as_ref()), new_encrypted_data)?;

                // Update app state
                self.crypto = Some(new_crypto);
                
                println!("{}", "Master password changed successfully!".green());
                Ok(())
            }
            Err(_) => {
                Err(anyhow!("Invalid current master password"))
            }
        }
    }

    async fn handle_backup_command(&mut self, _action: &BackupCommands) -> Result<()> {
        // Implement backup commands
        println!("Backup command not yet fully implemented");
        Ok(())
    }

    async fn handle_health_command(&mut self, action: &HealthCommands) -> Result<()> {
        if let Some(store) = &self.store {
            match action {
                HealthCommands::Check => {
                    let report = self.health_checker.check_health(store)?;
                    println!("{}", report);
                }
                _ => {
                    println!("Health command not yet fully implemented");
                }
            }
        }
        Ok(())
    }

    async fn handle_rotation_command(&mut self, _action: &RotationCommands) -> Result<()> {
        // Implement rotation commands
        println!("Rotation command not yet fully implemented");
        Ok(())
    }

    async fn handle_audit_command(&mut self, _action: &AuditCommands) -> Result<()> {
        // Implement audit commands
        println!("Audit command not yet fully implemented");
        Ok(())
    }

    async fn handle_config_command(&mut self, _action: &ConfigCommands) -> Result<()> {
        // Implement config commands
        println!("Config command not yet fully implemented");
        Ok(())
    }

    fn load_or_create_config() -> Result<Config> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("secret");

        let config_path = config_dir.join("config.json");

        if config_path.exists() {
            let config_data = fs::read_to_string(&config_path)?;
            let config: Config = serde_json::from_str(&config_data)?;
            Ok(config)
        } else {
            // Create default config
            let config = Config::default();
            
            // Create config directory
            fs::create_dir_all(&config_dir)?;
            
            // Save default config
            let config_json = serde_json::to_string_pretty(&config)?;
            fs::write(&config_path, config_json)?;
            
            Ok(config)
        }
    }
}