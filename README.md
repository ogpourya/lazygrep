# lazygrep

Fast pattern extraction tool for finding secrets, credentials, tokens, and infrastructure patterns. Built for bug bounty hunters and security researchers. 🔒

## Installation

```bash
go install github.com/ogpourya/lazygrep@latest
```

## Usage

**Single Mode** - Extract one pattern type:
```bash
lazygrep emails
cat file.txt | lazygrep aws-keys
```

**Multi-Mode** - Extract multiple patterns in one pass:
```bash
lazygrep domains urls emails ips
echo "https://api.example.com" | lazygrep domains urls
cat app.js | lazygrep bearer-tokens jwt aws-keys
```

**Recursive Scan** - Scans current directory recursively (skips `.git`, `node_modules`, etc.):
```bash
lazygrep aws-keys github-pat slack-webhook
```

**Pipe Mode** - Process any text stream:
```bash
curl -s https://example.com | lazygrep urls domains
cat logs.txt | lazygrep ips emails
```

## Available Modes

### 🌐 Network & Infrastructure
- `domains` - Domain names with valid TLDs
- `urls` - HTTP/HTTPS URLs
- `emails` - Email addresses
- `ipv4` - IPv4 addresses
- `ipv6` - IPv6 addresses
- `ips` - IPv4 or IPv6 addresses
- `private-ips` - RFC1918 private IPs
- `public-ips` - Public routable IPv4
- `ipv4-with-port` - IPv4:port pairs
- `ipv4-cidrs` - IPv4 CIDR notation

### 🔐 Hashes & Cryptography
- `md5` - MD5 hashes
- `sha1` - SHA-1 hashes
- `sha256` - SHA-256 hashes
- `bcrypt` - bcrypt hashes
- `jwt` - JWT tokens
- `base64` - Base64 strings (20+ chars)
- `uuids` - UUIDs
- `bearer-tokens` - Bearer token headers

### 🔑 Credentials & Secrets
- `connection-strings` - Database connection strings (MongoDB, MySQL, PostgreSQL, JDBC)
- `embedded-passwords` - URLs with embedded passwords
- `cloud-metadata-urls` - Cloud metadata service URLs (169.254.169.254)

### ☁️ Cloud Provider Secrets

**AWS:**
- `aws-keys` - AWS access keys (AKIA/ASIA)
- `aws-secret-keys` - AWS secret access keys

**GCP:**
- `gcp-api-keys` - GCP API keys

**Azure:**
- `azure-storage-keys` - Azure storage account keys

### 🐙 GitHub & Git
- `github-pat` - GitHub personal tokens
- `github-oauth` - GitHub OAuth tokens
- `github-repos` - GitHub repo references
- `gitlab-pat` - GitLab PATs

### 💬 Communication & Messaging
- `slack-webhook` - Slack webhook URLs
- `slack-bot-token` - Slack bot tokens
- `slack-user-token` - Slack user tokens
- `telegram-bot` - Telegram bot tokens
- `discord-bot` - Discord bot tokens
- `discord-webhook` - Discord webhook URLs
- `twilio-sid` - Twilio account SIDs
- `sendgrid-keys` - SendGrid API keys
- `mailgun-keys` - Mailgun API keys

### 💳 Payment
- `credit-cards` - Credit card numbers (Luhn validated)

### 🗄️ Databases
- `postgres-urls` - PostgreSQL URLs
- `mysql-urls` - MySQL URLs
- `mongodb-urls` - MongoDB URLs
- `redis-urls` - Redis URLs

### 🔧 SSH & Keys
- `ssh-private-keys` - SSH private key headers
- `pgp-private-keys` - PGP private key blocks

### 🐛 Security & Vulnerabilities
- `cve-ids` - CVE identifiers

## Examples

```bash
# Find all cloud provider secrets
lazygrep aws-keys aws-secret-keys gcp-api-keys azure-storage-keys

# Extract network infrastructure
lazygrep domains ips emails urls

# Scan for messaging/chat tokens
lazygrep slack-webhook discord-bot telegram-bot

# Find database connections
lazygrep postgres-urls mysql-urls mongodb-urls redis-urls

# Hunt for embedded credentials
lazygrep embedded-passwords connection-strings cloud-metadata-urls

# Extract crypto material
lazygrep jwt bcrypt sha256 bearer-tokens

# Find private keys
lazygrep ssh-private-keys pgp-private-keys
```

## Features

✅ **~70 essential extraction modes** - Focused on practical bug bounty patterns  
✅ **Strict validation** - TLD checks, Luhn algorithm, format verification  
✅ **Concurrent workers** - Fast multi-threaded scanning (30 workers)  
✅ **Multi-mode support** - Extract multiple patterns in one pass  
✅ **Stdin/pipe support** - Chain with other tools  
✅ **Smart deduplication** - Results printed once  
✅ **Binary file skipping** - No garbage output  
✅ **Zero config** - Works out of the box (downloads TLD list automatically)  

## License

MIT
