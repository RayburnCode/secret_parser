<!-- @format -->

# Secred CLI - A Secure Terminal-based Secret Manager

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
cd secret_parser/secred_cli
cargo build --release
sudo cp target/release/secred_cli /usr/local/bin/secred
```

## Quick Start

### Initialize a New Secret Store

```bash
secred init
# Follow the prompts to set your master password
```

### Add Your First Secret

```bash
secred add database-password --category "Database" --description "Production DB password"
# Enter the secret value when prompted
```

### List All Secrets

```bash
secred list
```

### Launch Interactive TUI

```bash
secred ui
```

## Usage Examples

### Basic Secret Operations

#### Add a secret with metadata

```bash
secred add api-key \
  --category "API" \
  --description "Stripe API key for payments" \
  --tags "stripe,payment,production" \
  --expires "2024-12-31T23:59:59Z"
```

#### Generate a strong password

```bash
secred add user-password --generate --length 32
```

#### Retrieve a secret

```bash
secred get api-key --full  # Show all metadata
secred get api-key --copy  # Copy to clipboard (requires clipboard support)
```

#### Update a secret

```bash
secred update api-key --value "new-api-key-value" --category "Payment"
```

#### Search secrets

```bash
secred search "stripe"        # Search by name, category, description, or tags
secred list --category "API"  # Filter by category
secred list --expired         # Show only expired secrets
```

### Advanced Operations

#### Health Monitoring

```bash
secred health check                    # Comprehensive health report
secred health expired                  # List expired secrets
secred health weak                     # Find weak passwords
secred health duplicates               # Find duplicate secret values
```

#### Secret Rotation

```bash
secred rotate list                     # Show rotation status
secred rotate secret api-key           # Rotate a specific secret
secred rotate policy api-key --days 90 --auto  # Set rotation policy
```

#### Backup & Recovery

```bash
secred backup create                   # Manual backup
secred backup schedule --interval 6    # Auto-backup every 6 hours
secred backup restore backup-file.bak  # Restore from backup
```

#### Import/Export

```bash
secred export secrets.json --format json --encrypt
secred import secrets.json --format json --merge
secred export secrets.csv --format csv --metadata
```

#### Audit Logging

```bash
secred audit show --limit 100         # Show recent audit entries
secred audit show --failed            # Show only failed operations
secred audit export audit.json        # Export audit log
```

## Terminal UI (TUI)

Launch the interactive Terminal UI with:

```bash
secred ui
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

Secred creates a configuration file at `~/.config/secred/config.json`:

```json
{
  "store_path": "~/.secred/store.enc",
  "backup_path": "~/.secred/backups/",
  "auto_backup": true,
  "backup_interval_hours": 6,
  "max_backups": 10,
  "audit_log_enabled": true,
  "audit_log_path": "~/.secred/audit.log",
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
docker run -v ~/.secred:/secrets myapp

# Use init containers to fetch secrets
docker run --rm -v secrets:/shared secred get api-key > /shared/api-key
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
