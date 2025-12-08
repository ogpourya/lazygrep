# lazygrep

Extract patterns from files in any directory 🔍

## Installation

```bash
GOPROXY=direct go install github.com/ogpourya/lazygrep@latest
````

## Usage

Simply run the tool in any directory. It recursively scans files, ignoring junk like `.git` and `node_modules`.

```bash
# Extract and validate domains, URLs, emails, IPs, hashes, secrets, cloud endpoints, and more
lazygrep <mode>

# Pipe into other tools
lazygrep urls | sort -u
lazygrep aws-keys | xargs -I{} printf "Found key: %s\n" {}
```

`lazygrep` now ships with 100 battle-tested modes. Run `lazygrep` with no args to see the full list. Highlights:

- **Net/Infra:** `domains`, `urls`, `emails`, `ipv4|ipv6|ips`, `ipv4-cidrs`, `ipv6-cidrs`, `private-ipv4`, `public-ipv4`, `host:port` combos, protocol URLs (`ftp|ssh|redis|postgres|mysql|mongo|kafka|jdbc|ws|wss|s3|gs|azure-blob|azure-devops`, etc.).
- **Cloud/App:** `aws-keys`, `aws-arns`, `s3-urls`, `cloudfront-domains`, `rds-endpoints`, `gcp-service-accounts`, `firebase-urls`, `auth0-domains`, `okta-domains`, `snowflake-accounts`, `shopify-domains`, `jira-cloud`, `digitalocean-spaces`.
- **Secrets/Tokens:** GitHub (`ghp|gho|ghu|ghs|ghr`), GitLab (`glpat|glrt`), Slack tokens/hooks, Stripe keys, SendGrid keys, Twilio SIDs/keys, Telegram/Discord/Dropbox/Google tokens, npm/PyPI tokens, JWTs, credit-cards (Luhn), base64, bcrypt/argon2/scrypt hashes, PEM headers.
- **Hashes/IDs:** `sha256|sha1|md5|sha384|sha512`, `git-shas`, `uuids`, `jwts`, `semver`, `git-urls`, `docker-images`.
- **Dates/Colors:** `iso-dates`, `iso-datetimes`, `rfc3339-timestamps`, `hex-colors`.
- **Validation-first:** Domain/TLD checks, URL parsing, Luhn, Base64 decode, RFC3339/ISO parsing, IP scope filters, scheme filters.

## Features

  * **Ultra Fast**: Concurrent worker pool pattern for high-speed processing.
  * **Strict Validation**: Validates domains against the official [IANA TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) and RFC standards.
  * **One Command**: 100 purpose-built modes for common artifacts (domains, URLs, IPs, hashes, secrets, versions, tokens, etc.).
  * **Smart Filtering**: Automatically ignores binary files and heavy directories (`node_modules`, `vendor`, etc.).
  * **Clean Output**: Results are trimmed, deduplicated, and ready for piping.
