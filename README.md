# lazygrep

**500 cybersecurity-focused extraction modes** for finding secrets, credentials, tokens, vulnerabilities, and infrastructure patterns. Fast, concurrent, validation-heavy. Built for bug bounty hunters, pentesters, and security researchers. 🔒

## Installation

```bash
GOPROXY=direct go install github.com/ogpourya/lazygrep@latest
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
echo "https://api.example.com" | lazygrep domains urls api-endpoints
cat app.js | lazygrep api-key-patterns bearer-tokens jwt
```

**Recursive Scan** - Scans current directory recursively, ignoring junk like `.git` and `node_modules`:

```bash
lazygrep aws-keys github-pat stripe-live-secret
```

**Pipe Mode (Stdin)** - Pipe any text stream:

```bash
curl -s https://example.com | lazygrep urls domains
cat large.txt | lazygrep emails domains
nuclei -u https://target.com -silent | lazygrep xss-payloads sqli-patterns
```

## Mode Categories

### 🌐 Network & Infrastructure (15 modes)
Essential patterns for network recon and infrastructure mapping.
- `domains`, `urls`, `emails`, `ipv4`, `ipv6`, `ips`
- `private-ips`, `public-ips`, `ipv4-with-port`, `domain-ports`
- `ipv4-cidrs`, `ipv6-cidrs`, `macs`, `asn-numbers`
- `internal-domains`, `localhost-refs`

### 🔐 Hashes & Cryptography (20+ modes)
Password hashes, checksums, and cryptographic patterns.
- `md5`, `sha1`, `sha256`, `sha384`, `sha512`
- `bcrypt`, `argon2id`, `ntlm-hashes`, `unix-crypt`
- `django-pbkdf2`, `jwt`, `base64`, `hex-strings`, `uuids`

### 🔑 Generic Secrets (15+ modes)
Catch-all patterns for API keys and credentials.
- `api-key-patterns`, `secret-patterns`, `bearer-tokens`
- `basic-auth`, `auth-headers`, `session-cookies`
- `api-endpoints`, `rest-paths`, `graphql-endpoints`
- `admin-paths`, `login-paths`, `upload-paths`, `debug-paths`

### ☁️ AWS (25+ modes)
Complete AWS infrastructure and secret extraction.
- `aws-keys`, `aws-secret-keys`, `aws-session-tokens`, `aws-account-ids`, `aws-arns`
- `s3-buckets`, `s3-urls`, `s3-presigned`, `cloudfront-domains`
- `ec2-metadata`, `lambda-urls`, `apigateway-urls`, `rds-endpoints`
- `dynamodb-endpoints`, `sqs-urls`, `sns-topics`, `elastic-ips`
- `ecs-endpoints`, `eks-endpoints`, `elasticache-endpoints`

### ☁️ GCP (15+ modes)
Google Cloud Platform secrets and infrastructure.
- `gcp-api-keys`, `gcp-oauth`, `gcp-service-accounts`, `gcp-project-ids`
- `gcs-buckets`, `gcs-urls`, `firebase-urls`, `firebase-ids`
- `firestore-refs`, `gcp-function-urls`, `gcp-run-urls`
- `bigquery-tables`, `gke-clusters`

### ☁️ Azure (15+ modes)
Microsoft Azure secrets and services.
- `azure-storage-keys`, `azure-connection`, `azure-blob-urls`, `azure-sas-tokens`
- `azure-tenant-ids`, `azure-client-secret`, `azure-app-insights`
- `azure-keyvault-urls`, `azure-cosmosdb`, `azure-sql`, `azure-functions`
- `azure-devops`, `azure-metadata`

### 🐙 GitHub & Git (12+ modes)
GitHub tokens, repos, and version control patterns.
- `github-pat`, `github-oauth`, `github-app`, `github-refresh`, `github-fine-grained`
- `github-actions`, `github-webhook`, `github-raw-urls`, `github-gists`, `github-repos`
- `gitlab-pat`, `gitlab-runner`, `gitlab-trigger`, `gitlab-oauth`

### 💬 Communication (15+ modes)
Slack, Discord, Telegram, Twilio and more.
- `slack-webhook`, `slack-bot-token`, `slack-user-token`, `slack-workspace`
- `discord-bot`, `discord-webhook`, `discord-mfa`
- `telegram-bot`, `twilio-sid`, `twilio-auth-token`, `twilio-api-key`
- `sendgrid-keys`, `mailgun-keys`, `mailchimp-keys`

### 💳 Payment & Crypto (25+ modes)
Financial API tokens and cryptocurrency addresses.
- `stripe-live-secret`, `stripe-test-secret`, `paypal-client-id`
- `credit-cards`, `iban-numbers`
- `bitcoin-addresses`, `ethereum-addresses`, `solana-addresses`
- `monero-addresses`, `litecoin-addresses`, `dogecoin-addresses`
- `ripple-addresses`, `cardano-addresses`, `wallet-seeds`

### 🗄️ Databases (20+ modes)
Connection strings for all major databases.
- `postgres-urls`, `mysql-urls`, `mongodb-urls`, `redis-urls`
- `elasticsearch-urls`, `cassandra-urls`, `clickhouse-urls`
- `neo4j-urls`, `couchdb-urls`, `arangodb-urls`, `influxdb-tokens`
- `planetscale-password`, `supabase-anon-key`, `mongodb-atlas-key`

### 🔧 CI/CD & DevOps (25+ modes)
Pipeline tokens, deployment keys, container registries.
- `jenkins-api-token`, `circleci-token`, `travis-token`
- `docker-hub-token`, `kubernetes-token`, `terraform-cloud`
- `gitlab-ci-vars`, `github-workflows`, `azure-pipelines-yaml`
- `heroku-api-key`, `netlify-token`, `vercel-token`

### 📦 Package Managers (10+ modes)
Registry tokens for npm, PyPI, RubyGems, etc.
- `npm-token`, `pypi-token`, `rubygems-key`, `nuget-key`
- `cargo-token`, `maven-password`, `gradle-keys`, `composer-auth`

### 🛡️ Security & Monitoring (30+ modes)
SaaS security tools, SIEM, APM, and monitoring platforms.
- `datadog-key`, `newrelic-key`, `sentry-dsn`, `bugsnag-key`
- `pagerduty-key`, `cloudflare-token`, `auth0-secret`, `okta-token`
- `shodan-key`, `virustotal-key`, `securitytrails-key`
- `grafana-api-key`, `splunk-token`, `elastic-cloud-id`

### 🌍 SaaS & Third-Party APIs (50+ modes)
Productivity, analytics, CMS, CDN, maps, and more.
- `google-maps-key`, `mapbox-token`, `algolia-key`, `segment-write-key`
- `mixpanel-token`, `amplitude-key`, `google-analytics-id`
- `airtable-key`, `notion-token`, `contentful-token`, `sanity-token`
- `cloudinary-key`, `imgix-token`, `uploadcare-secret`

### 🐛 Bug Bounty & Pentesting (40+ modes)
Vulnerability patterns, exploitation indicators, security misconfigs.
- `cve-ids`, `cwe-ids`, `capec-ids`, `mitre-attack-ids`, `owasp-references`
- `xss-payloads`, `sqli-patterns`, `path-traversal`, `xxe-payloads`
- `ssrf-localhost`, `rce-commands`, `jwt-none-alg`, `open-redirect-params`
- `idor-params`, `debug-enabled`, `weak-passwords`, `cors-any-origin`
- `burp-collab-interactions`, `interactsh-urls`, `ngrok-urls`

### 📄 Files & Config (40+ modes)
Config files, backups, logs, keys, and sensitive artifacts.
- `backup-files`, `config-files`, `db-files`, `sql-dumps`, `log-files`
- `key-files`, `ssh-private-keys`, `pgp-private-keys`, `ssl-certificate-keys`
- `.env` patterns, `php-info-paths`, `git-config-exposed`, `robots-disallow`
- CI/CD configs (`.gitlab-ci.yml`, `.github/workflows`, `Jenkinsfile`)
- IaC files (`terraform`, `cloudformation`, `kubernetes-manifests`)

### 🌐 Social Media (20+ modes)
Access tokens for Twitter, Facebook, Instagram, TikTok, etc.
- `twitter-bearer`, `twitter-api-key`, `facebook-token`
- `instagram-token`, `linkedin-token`, `tiktok-token`, `snapchat-token`
- `pinterest-token`, `reddit-client-secret`, `youtube-api-key`

### 📊 Analytics & Product (20+ modes)
Feature flags, A/B testing, session replay, heatmaps.
- `google-analytics-id`, `google-analytics-4`, `google-tag-manager`
- `facebook-pixel-id`, `hotjar-id`, `fullstory-org-id`, `logrocket-app-id`
- `launchdarkly-sdk-key`, `optimizely-key`, `posthog-key`

## Why 500 modes?

Every mode was chosen with the **40% rule**: *"Will at least 40% of security researchers need this at times?"*

**Removed useless patterns** like obscure database protocols, legacy systems nobody uses, and niche file formats.  

**Added practical modes** like:
- `burp-collab-interactions` - Find Burp Collaborator callbacks in responses
- `github-actions` - Extract GitHub Actions secret references
- `weak-passwords` - Catch hardcoded `password=admin123` patterns
- `suspicious-base64` - Base64 strings that decode to "password", "secret", "key"
- `test-credentials` - Common test creds like `admin:admin`
- `cloud-metadata-urls` - AWS/GCP/Azure metadata endpoints (169.254.169.254)
- `internal-domains` - `.local`, `.internal`, `.corp` TLDs
- All modern crypto wallet addresses (Bitcoin, Ethereum, Solana, Cardano, etc.)
- Every major SaaS API token format (500+ services)

## Examples

```bash
# Multi-mode extraction - scan for multiple patterns at once
echo "https://api.github.com admin@site.com 192.168.1.1" | lazygrep domains urls emails ips
# Output: api.github.com, github.com, https://api.github.com, admin@site.com, 192.168.1.1

# Find all AWS secrets in a repo
lazygrep aws-keys aws-secret-keys aws-session-tokens

# Extract hardcoded credentials
lazygrep weak-passwords embedded-passwords api-key-patterns secret-patterns

# Find API endpoints across all formats
lazygrep api-endpoints rest-paths graphql-endpoints

# Scan for crypto wallets (all chains at once)
lazygrep bitcoin-addresses ethereum-addresses solana-addresses cardano-addresses

# Find CVEs and security references
lazygrep cve-ids mitre-attack-ids owasp-references cwe-ids

# Check for SSRF vectors
lazygrep cloud-metadata-urls
lazygrep internal-ips
lazygrep ssrf-localhost

# Extract all tokens from HTTP traffic
cat burp-history.txt | lazygrep bearer-tokens
cat burp-history.txt | lazygrep session-cookies

# Find debug/test artifacts
lazygrep debug-enabled
lazygrep test-credentials
lazygrep todo-fixme-comments

# Scan for exposed configs
lazygrep git-config-exposed
lazygrep dotenv-vars
lazygrep env-secrets
```

## Features

✅ **500 cybersecurity-focused modes** - Every pattern matters  
✅ **Strict validation** - TLD checks, Luhn algorithm, format verification  
✅ **Concurrent workers** - Fast multi-threaded file scanning  
✅ **Stdin piping** - Chain with curl, cat, grep, nuclei, httpx  
✅ **Smart deduplication** - Results printed once  
✅ **Binary file skipping** - No garbage from images/executables  
✅ **Zero dependencies** - Static Go binary, works everywhere  

## License

MIT
