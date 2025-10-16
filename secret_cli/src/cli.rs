use clap::{Parser, Subcommand};
use chrono::{DateTime, Utc};

#[derive(Parser)]
#[command(name = "secret")]
#[command(about = "A secure CLI secret manager with Terminal UI")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<String>,

    /// Store file path (overrides config)
    #[arg(short, long, global = true)]
    pub store: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Add a new secret
    Add {
        /// Name of the secret
        name: String,

        /// Value of the secret (if not provided, will prompt securely)
        #[arg(short, long)]
        value: Option<String>,

        /// Category for the secret
        #[arg(short, long)]
        category: Option<String>,

        /// Description of the secret
        #[arg(short, long)]
        description: Option<String>,

        /// Tags (comma-separated)
        #[arg(short, long)]
        tags: Option<String>,

        /// Expiration date (ISO 8601 format)
        #[arg(short, long)]
        expires: Option<String>,

        /// Generate a random password
        #[arg(short = 'g', long)]
        generate: bool,

        /// Length for generated password (default: 32)
        #[arg(long, default_value = "32")]
        length: usize,
    },

    /// Get a secret by name or ID
    Get {
        /// Name or ID of the secret
        identifier: String,

        /// Copy to clipboard instead of displaying
        #[arg(short, long)]
        copy: bool,

        /// Show full details
        #[arg(short, long)]
        full: bool,
    },

    /// Update an existing secret
    Update {
        /// Name or ID of the secret to update
        identifier: String,

        /// New value for the secret
        #[arg(short, long)]
        value: Option<String>,

        /// New category
        #[arg(short, long)]
        category: Option<String>,

        /// New description
        #[arg(short, long)]
        description: Option<String>,

        /// New tags (comma-separated)
        #[arg(short, long)]
        tags: Option<String>,

        /// New expiration date
        #[arg(short, long)]
        expires: Option<String>,
    },

    /// Delete a secret
    Delete {
        /// Name or ID of the secret to delete
        identifier: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// List all secrets
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Filter by tag
        #[arg(short, long)]
        tag: Option<String>,

        /// Show expired secrets only
        #[arg(short, long)]
        expired: bool,

        /// Output format (table, json, csv)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Include values in output (insecure)
        #[arg(long)]
        show_values: bool,
    },

    /// Search secrets
    Search {
        /// Search query
        query: String,

        /// Case sensitive search
        #[arg(short, long)]
        case_sensitive: bool,
    },

    /// Launch interactive Terminal UI
    Ui,

    /// Backup operations
    Backup {
        #[command(subcommand)]
        action: BackupCommands,
    },

    /// Import secrets from a file
    Import {
        /// File to import from
        file: String,

        /// File format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Merge with existing secrets
        #[arg(short, long)]
        merge: bool,
    },

    /// Export secrets to a file
    Export {
        /// Output file
        file: String,

        /// Export format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Include metadata in export
        #[arg(short, long)]
        metadata: bool,

        /// Encrypt exported file
        #[arg(short, long)]
        encrypt: bool,
    },

    /// Health check operations
    Health {
        #[command(subcommand)]
        action: HealthCommands,
    },

    /// Secret rotation operations
    Rotate {
        #[command(subcommand)]
        action: RotationCommands,
    },

    /// Audit log operations
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Initialize a new secret store
    Init {
        /// Store file path
        #[arg(short, long)]
        path: Option<String>,

        /// Force initialization (overwrite existing)
        #[arg(short, long)]
        force: bool,
    },

    /// Change master password
    ChangePassword,

    /// Generate a secure password
    Generate {
        /// Password length
        #[arg(short, long, default_value = "32")]
        length: usize,

        /// Include symbols
        #[arg(long, default_value = "true")]
        symbols: bool,

        /// Include numbers
        #[arg(long, default_value = "true")]
        numbers: bool,

        /// Include uppercase letters
        #[arg(long, default_value = "true")]
        uppercase: bool,

        /// Include lowercase letters  
        #[arg(long, default_value = "true")]
        lowercase: bool,

        /// Copy to clipboard
        #[arg(short, long)]
        copy: bool,
    },
}

#[derive(Subcommand)]
pub enum BackupCommands {
    /// Create a manual backup
    Create {
        /// Backup file path
        path: Option<String>,
    },

    /// Restore from backup
    Restore {
        /// Backup file path
        path: String,

        /// Force restore (overwrite existing)
        #[arg(short, long)]
        force: bool,
    },

    /// List available backups
    List,

    /// Schedule automatic backups
    Schedule {
        /// Interval in hours
        #[arg(short, long)]
        interval: Option<u64>,

        /// Enable/disable scheduling
        #[arg(short, long)]
        enable: Option<bool>,
    },

    /// Clean old backups
    Clean {
        /// Keep this many recent backups
        #[arg(short, long)]
        keep: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum HealthCommands {
    /// Check overall system health
    Check,

    /// Check for expired secrets
    Expired,

    /// Check for weak passwords
    Weak,

    /// Check for duplicate secrets
    Duplicates,

    /// Generate health report
    Report {
        /// Output file
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum RotationCommands {
    /// List secrets due for rotation
    List,

    /// Rotate a specific secret
    Secret {
        /// Secret identifier
        identifier: String,

        /// New value (if not provided, will generate)
        #[arg(short, long)]
        value: Option<String>,
    },

    /// Set rotation policy for a secret
    Policy {
        /// Secret identifier
        identifier: String,

        /// Rotation interval in days
        #[arg(short, long)]
        days: Option<u32>,

        /// Auto-rotate (if supported)
        #[arg(short, long)]
        auto: Option<bool>,
    },
}

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Show audit log
    Show {
        /// Number of entries to show
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Filter by operation
        #[arg(short, long)]
        operation: Option<String>,

        /// Show only failed operations
        #[arg(short, long)]
        failed: bool,
    },

    /// Export audit log
    Export {
        /// Output file
        file: String,

        /// Export format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Clear audit log
    Clear {
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set configuration value
    Set {
        /// Configuration key
        key: String,

        /// Configuration value
        value: String,
    },

    /// Get configuration value
    Get {
        /// Configuration key
        key: String,
    },

    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
}