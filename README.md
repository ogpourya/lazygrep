# lazygrep

A static binary to extract patterns from files or streams. Fast, concurrent, and validation-focused. 🔍

## Installation

```
GOPROXY=direct go install github.com/ogpourya/lazygrep@latest
```

## Usage

**Recursive Scan** Scans current directory recursively, ignoring junk like `.git` and `node_modules`.

```
lazygrep <mode>
```

**Pipe Mode (Stdin)** Pipe any text into `lazygrep` to scan that stream.

```
cat large.txt | lazygrep emails
curl -s https://example.com | lazygrep urls
```

## Available Modes

| Mode | Description |
| --- | --- |
| `amqp-urls` | AMQP URLs |
| `amqps-urls` | AMQPS URLs |
| `argon2i` | Argon2i password hashes |
| `argon2id` | Argon2id password hashes |
| `auth0-domains` | Auth0 tenant domains |
| `aws-arns` | AWS ARNs |
| `aws-keys` | AWS access key IDs (AKIA/ASIA) |
| `azure-blob-urls` | Azure Blob Storage URLs |
| `azure-devops-urls` | Azure DevOps organization/project URLs |
| `base64` | Base64 strings (min 20 chars, decodes cleanly) |
| `bcrypt` | bcrypt password hashes |
| `cassandra-urls` | Cassandra URLs |
| `clickhouse-urls` | ClickHouse URLs |
| `cloudfront-domains` | CloudFront distribution domains |
| `credit-cards` | Credit card numbers (Luhn validated) |
| `cve-ids` | CVE identifiers |
| `digitalocean-spaces` | DigitalOcean Spaces endpoints |
| `discord-bot-tokens` | Discord bot tokens |
| `discord-mfa-tokens` | Discord MFA tokens |
| `docker-images` | Docker image references |
| `domain-ports` | Domain names with ports |
| `domains` | Extract and validate DNS domains |
| `dropbox-short-tokens` | Dropbox short-lived tokens (sl.) |
| `emails` | Email addresses with valid TLDs |
| `etcd-urls` | etcd URLs |
| `firebase-urls` | Firebase database URLs |
| `ftp-urls` | FTP URLs |
| `ftps-urls` | FTPS URLs |
| `gcp-oauth-tokens` | Google OAuth tokens (ya29...) |
| `gcp-service-accounts` | GCP service account emails |
| `gho-tokens` | GitHub OAuth tokens (gho\_) |
| `ghp-tokens` | GitHub PATs (ghp\_) |
| `ghr-tokens` | GitHub refresh tokens (ghr\_) |
| `ghs-tokens` | GitHub Server-to-Server tokens (ghs\_) |
| `ghu-tokens` | GitHub User-to-Server tokens (ghu\_) |
| `git+https-urls` | git+https URLs |
| `git+ssh-urls` | git+ssh URLs |
| `git-shas` | Git commit hashes (7-40 chars) |
| `git-urls` | Git SSH/HTTPS repository URLs |
| `gitlab-pats` | GitLab personal access tokens |
| `gitlab-runners` | GitLab runner registration tokens |
| `google-api-keys` | Google API keys (AIza...) |
| `google-client-ids` | Google OAuth client IDs |
| `gs-urls` | Google Cloud Storage URLs (gs://) |
| `hex-colors` | Hex color codes (#abc, #aabbcc) |
| `hg-urls` | Mercurial URLs |
| `imap-urls` | IMAP URLs |
| `imaps-urls` | IMAPS URLs |
| `ips` | IPv4 or IPv6 addresses |
| `ipv4` | IPv4 addresses |
| `ipv4-cidrs` | IPv4 CIDR blocks |
| `ipv4-with-port` | IPv4 addresses with ports |
| `ipv6` | IPv6 addresses |
| `ipv6-cidrs` | IPv6 CIDR blocks |
| `iso-dates` | ISO-8601 dates (YYYY-MM-DD) |
| `iso-datetimes` | ISO datetimes without timezone (YYYY-MM-DDTHH:MM:SS) |
| `jdbc-urls` | JDBC URLs |
| `jira-cloud` | Jira Cloud site domains |
| `jwts` | JWT tokens (base64url segments) |
| `kafka-urls` | Kafka URLs |
| `ldap-urls` | LDAP URLs |
| `ldaps-urls` | LDAPS URLs |
| `linklocal-ipv4` | Link-local IPv4 addresses |
| `linklocal-ipv6` | Link-local IPv6 addresses |
| `loopback-ipv4` | Loopback IPv4 addresses |
| `macs` | MAC addresses |
| `mariadb-urls` | MariaDB URLs |
| `md5` | MD5 hashes |
| `mongodb-urls` | MongoDB URLs |
| `mongodbsrv-urls` | MongoDB SRV URLs |
| `mqtt-urls` | MQTT URLs |
| `mssql-urls` | SQL Server URLs |
| `mysql-urls` | MySQL URLs |
| `nats-urls` | NATS URLs |
| `npm-tokens` | npm tokens (npm\_...) |
| `okta-domains` | Okta tenant domains |
| `oracle-urls` | Oracle DB URLs |
| `pem-keys` | PEM block headers |
| `pop3-urls` | POP3 URLs |
| `pop3s-urls` | POP3S URLs |
| `postgres-urls` | Postgres URLs |
| `private-ipv4` | Private IPv4 addresses |
| `private-ipv6` | Unique-local IPv6 addresses (fc00::/7) |
| `public-ipv4` | Public IPv4 addresses |
| `public-ipv6` | Public-scoped IPv6 addresses |
| `pypi-tokens` | PyPI upload tokens (pypi-AgEI...) |
| `rds-endpoints` | AWS RDS endpoints |
| `redis-urls` | Redis URLs |
| `rediss-urls` | Redis TLS URLs |
| `rfc3339-timestamps` | RFC3339 timestamps |
| `s3-urls` | Amazon S3 URLs (s3://bucket/key) |
| `scrypt-hashes` | scrypt password hashes |
| `semver` | Semantic versions |
| `sendgrid-api-keys` | SendGrid API keys (SG.x.x) |
| `sftp-urls` | SFTP URLs |
| `sha1` | SHA-1 hashes |
| `sha256` | SHA-256 hashes |
| `sha384` | SHA-384 hashes |
| `sha512` | SHA-512 hashes |
| `shopify-domains` | Shopify store domains |
| `slack-app-tokens` | Slack app-level tokens (xapp-1-) |
| `slack-bot-tokens` | Slack bot tokens (xoxb-) |
| `slack-hooks` | Slack incoming webhook URLs |
| `slack-legacy-tokens` | Slack legacy workspace tokens (xoxa-) |
| `slack-user-tokens` | Slack user tokens (xoxp-) |
| `smtp-urls` | SMTP URLs |
| `smtps-urls` | SMTPS URLs |
| `snowflake-accounts` | Snowflake account endpoints |
| `sqlite-urls` | SQLite URLs (file-based) |
| `ssh-urls` | SSH URLs (ssh://user@host) |
| `stripe-publishable-live` | Stripe live publishable keys (pk\_live\_) |
| `stripe-publishable-test` | Stripe test publishable keys (pk\_test\_) |
| `stripe-restricted-live` | Stripe live restricted keys (rk\_live\_) |
| `stripe-restricted-test` | Stripe test restricted keys (rk\_test\_) |
| `stripe-secret-live` | Stripe live secret keys (sk\_live\_) |
| `stripe-secret-test` | Stripe test secret keys (sk\_test\_) |
| `svn-urls` | Subversion URLs |
| `telegram-bot-tokens` | Telegram bot tokens |
| `twilio-account-sids` | Twilio account SIDs (AC...32 hex) |
| `twilio-api-keys` | Twilio API keys (SK...32 hex) |
| `urls` | Extract and validate HTTP/HTTPS URLs |
| `uuids` | RFC4122 UUIDs |
| `ws-urls` | WebSocket ws:// URLs |
| `wss-urls` | WebSocket wss:// URLs |
