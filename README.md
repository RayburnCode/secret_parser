<!-- @format -->

# secret CLI - A Secure Terminal-based Secret Manager

A lightweight, secure CLI secret manager built in Rust with an interactive Terminal UI (TUI) for Ubuntu Server VPS environments and beyond.

## Features

### 🔐 Security

- **AES-256-GCM encryption** for all stored secrets
- **PBKDF2 key derivation** from master password with configurable iterations
- **Secure password validation** with strength checking
- **Zeroized memory** for sensitive data handling
- **Audit logging** for all secret operations

### 🖥️ User Interface

- **Beautiful Terminal UI** built with ratatui
- **Colored CLI output** for better navigation
- **Interactive secret management** with keyboard shortcuts
- **Search functionality** with real-time filtering
- **Context-aware help** system

### 🔄 Secret Management

- **CRUD operations** (Create, Read, Update, Delete)
- **Categorization and tagging** for organization
- **Secret expiration** with automatic detection
- **Bulk operations** and batch processing
- **Metadata tracking** (creation, access, update times)

### 🔄 Advanced Features

- **Automatic secret rotation** with configurable policies
- **Health monitoring** for expired/weak secrets
- **Automated backups** with encryption
- **Import/Export** in multiple formats (JSON, CSV)
- **High availability** through backup replication

## Installation

### Prerequisites

- Rust 1.70+ (for building from source)
- A terminal that supports colors and unicode

### From Source

```bash
git clone https://github.com/RayburnCode/secret_parser.git
cd secret_parser/secret_cli
cargo build --release
sudo cp target/release/secret_cli /usr/local/bin/secret
```

## Quick Start

### Initialize a New Secret Store

```bash
secret init
# Follow the prompts to set your master password
```

### Add Your First Secret

```bash
secret add database-password --category "Database" --description "Production DB password"
# Enter the secret value when prompted
```

### List All Secrets

```bash
secret list
```

### Launch Interactive TUI

```bash
secret ui
```

## Usage Examples

### Basic Secret Operations

#### Add a secret with metadata

```bash
secret add api-key \
  --category "API" \
  --description "Stripe API key for payments" \
  --tags "stripe,payment,production" \
  --expires "2024-12-31T23:59:59Z"
```

#### Generate a strong password

```bash
secret add user-password --generate --length 32
```

#### Retrieve a secret

```bash
secret get api-key --full  # Show all metadata
secret get api-key --copy  # Copy to clipboard (requires clipboard support)
```

#### Update a secret

```bash
secret update api-key --value "new-api-key-value" --category "Payment"
```

#### Search secrets

```bash
secret search "stripe"        # Search by name, category, description, or tags
secret list --category "API"  # Filter by category
secret list --expired         # Show only expired secrets
```

### Advanced Operations

#### Health Monitoring

```bash
secret health check                    # Comprehensive health report
secret health expired                  # List expired secrets
secret health weak                     # Find weak passwords
secret health duplicates               # Find duplicate secret values
```

#### Secret Rotation

```bash
secret rotate list                     # Show rotation status
secret rotate secret api-key           # Rotate a specific secret
secret rotate policy api-key --days 90 --auto  # Set rotation policy
```

#### Backup & Recovery

```bash
secret backup create                   # Manual backup
secret backup schedule --interval 6    # Auto-backup every 6 hours
secret backup restore backup-file.bak  # Restore from backup
```

#### Import/Export

```bash
secret export secrets.json --format json --encrypt
secret import secrets.json --format json --merge
secret export secrets.csv --format csv --metadata
```

#### Audit Logging

```bash
secret audit show --limit 100         # Show recent audit entries
secret audit show --failed            # Show only failed operations
secret audit export audit.json        # Export audit log
```

## Terminal UI (TUI)

Launch the interactive Terminal UI with:

```bash
secret ui
```

### TUI Navigation

- `↑/k` - Move up
- `↓/j` - Move down
- `Enter` - View secret details
- `a` - Add new secret
- `d` - Delete selected secret
- `/` - Search secrets
- `h/F1` - Toggle help
- `Esc` - Go back
- `q` - Quit

### TUI Features

- Real-time search filtering
- Colored status indicators (OK, EXPIRED, TEMP)
- Interactive forms for adding secrets
- Sortable columns
- Help overlay

## Configuration

### Default Configuration

secret creates a configuration file at `~/.config/secret/config.json`:

```json
{
  "store_path": "~/.secret/store.enc",
  "backup_path": "~/.secret/backups/",
  "auto_backup": true,
  "backup_interval_hours": 6,
  "max_backups": 10,
  "audit_log_enabled": true,
  "audit_log_path": "~/.secret/audit.log",
  "encryption_iterations": 100000
}
```

## Security Considerations

### Best Practices

1. **Strong Master Password** - Use a unique, strong password for your secret store
2. **Regular Backups** - Enable automatic backups to prevent data loss
3. **Audit Reviews** - Regularly review audit logs for suspicious activity
4. **Access Control** - Secure the host system where secrets are stored
5. **Rotation Policy** - Implement regular secret rotation for sensitive credentials

### Threat Model

- **Encrypted at Rest** - All secrets encrypted with AES-256-GCM
- **Memory Protection** - Sensitive data zeroized after use
- **Audit Trail** - Complete logging of all secret operations
- **Master Password** - Single point of authentication
- **File Permissions** - Relies on OS file permission security

## Architecture

### Security Model

```
┌─────────────────┐    PBKDF2     ┌──────────────────┐
│ Master Password │─────────────→│ Encryption Key   │
└─────────────────┘               └──────────────────┘
                                            │
                                            │ AES-256-GCM
                                            ▼
┌─────────────────┐               ┌──────────────────┐
│ Secret Store    │◄──────────────│ Encrypted Store  │
│ (JSON in memory)│               │ (File on disk)   │
└─────────────────┘               └──────────────────┘
```

## Docker Integration

### Using with Docker Containers

```bash
# Mount secrets into containers
docker run -v ~/.secret:/secrets myapp

# Use init containers to fetch secrets
docker run --rm -v secrets:/shared secret get api-key > /shared/api-key
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⚡ Fast • 🔒 Secure • 🖥️ Terminal-Native • 🦀 Rust-Powered**
