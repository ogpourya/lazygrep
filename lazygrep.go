package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config
const (
	ianaURL      = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	workerCount  = 30 // Increased for file I/O latency
	configFolder = ".config/ezgrep"
	tldFile      = "tlds-alpha-by-domain.txt"
)

// Directories to completely ignore (files inside won't be scanned)
var skipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	".idea":        {},
	".vscode":      {},
	"__pycache__":  {},
	"dist":         {},
	"build":        {},
}

// Regex patterns (pre-compiled)
var (
	domainRegex         = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	urlRegex            = regexp.MustCompile(`https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
	emailRegex          = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	ipv4Regex           = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex           = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|\b::1\b|\b::\b`)
	ipRegex             = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|\b::1\b|\b::\b`)
	macRegex            = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
	uuidRegex           = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b`)
	sha256Regex         = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	sha1Regex           = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	md5Regex            = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	gitSHARegex         = regexp.MustCompile(`\b[0-9a-fA-F]{7,40}\b`)
	jwtRegex            = regexp.MustCompile(`\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	cardRegex           = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	semverRegex         = regexp.MustCompile(`\bv?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\b`)
	isoDateRegex        = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	hexColorRegex       = regexp.MustCompile(`#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b`)
	cidrRegex           = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	awsKeyRegex         = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	slackHookRegex      = regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`)
	bcryptRegex         = regexp.MustCompile(`\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}`)
	dockerRegex         = regexp.MustCompile(`\b(?:[a-z0-9]+(?:(?:[._-][a-z0-9]+)+)?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9._-]{1,128})?(?:@sha256:[a-fA-F0-9]{64})?\b`)
	base64Regex         = regexp.MustCompile(`\b(?:[A-Za-z0-9+/]{20,}={0,2})\b`)
	pemRegex            = regexp.MustCompile(`-----BEGIN [A-Z ]+-----`)
	gitURLRegex         = regexp.MustCompile(`\b(?:git@[A-Za-z0-9._-]+:[A-Za-z0-9._/-]+\.git|https?://[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+(?:\.git)?)\b`)
	schemeURLRegex      = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)
	ipv4PortRegex       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	domainPortRegex     = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}:\d{1,5}\b`)
	cveRegex            = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	rfc3339Regex        = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b`)
	googleAPIKeyRegex   = regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)
	gcpOAuthRegex       = regexp.MustCompile(`\bya29\.[0-9A-Za-z\-_]+\b`)
	googleClientIDRegex = regexp.MustCompile(`\b\d{21,22}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b`)
	dropboxShortRegex   = regexp.MustCompile(`\bsl\.[A-Za-z0-9_-]{60}\b`)
	simpleHostRegex     = regexp.MustCompile(`^[a-zA-Z0-9-]{1,63}$`)
)

type extractor struct {
	regex       *regexp.Regexp
	requiresTLD bool
	normalize   func(string) string
	validate    func(string) bool
	description string
}

var modeExtractors = map[string]extractor{
	"domains": {
		regex:       domainRegex,
		requiresTLD: true,
		normalize:   lowerTrim,
		validate:    isValidDomain,
		description: "Extract and validate DNS domains",
	},
	"urls": {
		regex:       urlRegex,
		requiresTLD: true,
		normalize:   strings.TrimSpace,
		validate:    isValidURL,
		description: "Extract and validate HTTP/HTTPS URLs",
	},
	"emails": {
		regex:       emailRegex,
		requiresTLD: true,
		normalize:   lowerTrim,
		validate:    isValidEmail,
		description: "Email addresses with valid TLDs",
	},
	"ipv4": {
		regex:       ipv4Regex,
		validate:    isIPv4,
		description: "IPv4 addresses",
	},
	"ipv6": {
		regex:       ipv6Regex,
		validate:    isIPv6,
		description: "IPv6 addresses",
	},
	"ips": {
		regex:       ipRegex,
		validate:    isIP,
		description: "IPv4 or IPv6 addresses",
	},
	"macs": {
		regex:       macRegex,
		description: "MAC addresses",
	},
	"uuids": {
		regex:       uuidRegex,
		description: "RFC4122 UUIDs",
	},
	"sha256": {
		regex:       sha256Regex,
		description: "SHA-256 hashes",
	},
	"sha1": {
		regex:       sha1Regex,
		description: "SHA-1 hashes",
	},
	"md5": {
		regex:       md5Regex,
		description: "MD5 hashes",
	},
	"git-shas": {
		regex:       gitSHARegex,
		description: "Git commit hashes (7-40 chars)",
	},
	"jwts": {
		regex:       jwtRegex,
		validate:    isJWT,
		description: "JWT tokens (base64url segments)",
	},
	"credit-cards": {
		regex:       cardRegex,
		normalize:   stripSpacesAndHyphens,
		validate:    isValidCard,
		description: "Credit card numbers (Luhn validated)",
	},
	"semver": {
		regex:       semverRegex,
		description: "Semantic versions",
	},
	"iso-dates": {
		regex:       isoDateRegex,
		validate:    isValidISODate,
		description: "ISO-8601 dates (YYYY-MM-DD)",
	},
	"hex-colors": {
		regex:       hexColorRegex,
		description: "Hex color codes (#abc, #aabbcc)",
	},
	"ipv4-cidrs": {
		regex:       cidrRegex,
		validate:    isValidCIDR,
		description: "IPv4 CIDR blocks",
	},
	"aws-keys": {
		regex:       awsKeyRegex,
		description: "AWS access key IDs (AKIA/ASIA)",
	},
	"slack-hooks": {
		regex:       slackHookRegex,
		description: "Slack incoming webhook URLs",
	},
	"bcrypt": {
		regex:       bcryptRegex,
		description: "bcrypt password hashes",
	},
	"docker-images": {
		regex:       dockerRegex,
		description: "Docker image references",
	},
	"base64": {
		regex:       base64Regex,
		validate:    isValidBase64,
		description: "Base64 strings (min 20 chars, decodes cleanly)",
	},
	"pem-keys": {
		regex:       pemRegex,
		description: "PEM block headers",
	},
	"git-urls": {
		regex:       gitURLRegex,
		description: "Git SSH/HTTPS repository URLs",
	},
	"sha512": {
		regex:       regexp.MustCompile(`\b[a-fA-F0-9]{128}\b`),
		description: "SHA-512 hashes",
	},
	"sha384": {
		regex:       regexp.MustCompile(`\b[a-fA-F0-9]{96}\b`),
		description: "SHA-384 hashes",
	},
	"argon2id": {
		regex:       regexp.MustCompile(`\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+`),
		description: "Argon2id password hashes",
	},
	"argon2i": {
		regex:       regexp.MustCompile(`\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+`),
		description: "Argon2i password hashes",
	},
	"scrypt-hashes": {
		regex:       regexp.MustCompile(`\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+`),
		description: "scrypt password hashes",
	},
	"ftp-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, false, false, "ftp"),
		description: "FTP URLs",
	},
	"ftps-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, false, false, "ftps"),
		description: "FTPS URLs",
	},
	"ssh-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "ssh"),
		description: "SSH URLs (ssh://user@host)",
	},
	"sftp-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "sftp"),
		description: "SFTP URLs",
	},
	"smtp-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "smtp"),
		description: "SMTP URLs",
	},
	"smtps-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "smtps"),
		description: "SMTPS URLs",
	},
	"imap-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "imap"),
		description: "IMAP URLs",
	},
	"imaps-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "imaps"),
		description: "IMAPS URLs",
	},
	"pop3-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "pop3"),
		description: "POP3 URLs",
	},
	"pop3s-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "pop3s"),
		description: "POP3S URLs",
	},
	"ldap-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "ldap"),
		description: "LDAP URLs",
	},
	"ldaps-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "ldaps"),
		description: "LDAPS URLs",
	},
	"mqtt-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "mqtt"),
		description: "MQTT URLs",
	},
	"amqp-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "amqp"),
		description: "AMQP URLs",
	},
	"amqps-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "amqps"),
		description: "AMQPS URLs",
	},
	"ws-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "ws"),
		description: "WebSocket ws:// URLs",
	},
	"wss-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "wss"),
		description: "WebSocket wss:// URLs",
	},
	"redis-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "redis"),
		description: "Redis URLs",
	},
	"rediss-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "rediss"),
		description: "Redis TLS URLs",
	},
	"postgres-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "postgres", "postgresql"),
		description: "Postgres URLs",
	},
	"mysql-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "mysql"),
		description: "MySQL URLs",
	},
	"mariadb-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "mariadb"),
		description: "MariaDB URLs",
	},
	"mssql-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "mssql", "sqlserver"),
		description: "SQL Server URLs",
	},
	"oracle-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "oracle"),
		description: "Oracle DB URLs",
	},
	"sqlite-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(false, true, false, "sqlite"),
		description: "SQLite URLs (file-based)",
	},
	"mongodb-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "mongodb"),
		description: "MongoDB URLs",
	},
	"mongodbsrv-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "mongodb+srv"),
		description: "MongoDB SRV URLs",
	},
	"cassandra-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "cassandra"),
		description: "Cassandra URLs",
	},
	"clickhouse-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "clickhouse"),
		description: "ClickHouse URLs",
	},
	"jdbc-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "jdbc"),
		description: "JDBC URLs",
	},
	"svn-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "svn"),
		description: "Subversion URLs",
	},
	"hg-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "hg"),
		description: "Mercurial URLs",
	},
	"nats-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "nats"),
		description: "NATS URLs",
	},
	"kafka-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "kafka"),
		description: "Kafka URLs",
	},
	"etcd-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "etcd"),
		description: "etcd URLs",
	},
	"git+ssh-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "git+ssh"),
		description: "git+ssh URLs",
	},
	"git+https-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "git+https"),
		description: "git+https URLs",
	},
	"s3-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "s3"),
		description: "Amazon S3 URLs (s3://bucket/key)",
	},
	"gs-urls": {
		regex:       schemeURLRegex,
		validate:    schemeValidator(true, true, false, "gs"),
		description: "Google Cloud Storage URLs (gs://)",
	},
	"azure-blob-urls": {
		regex:       regexp.MustCompile(`https://[\w-]+\.blob\.core\.windows\.net/[^\s"'<>]+`),
		description: "Azure Blob Storage URLs",
	},
	"azure-devops-urls": {
		regex:       regexp.MustCompile(`https://dev\.azure\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`),
		description: "Azure DevOps organization/project URLs",
	},
	"gcp-service-accounts": {
		regex:       regexp.MustCompile(`\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b`),
		description: "GCP service account emails",
	},
	"firebase-urls": {
		regex:       regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com[^\s"'<>]*`),
		description: "Firebase database URLs",
	},
	"auth0-domains": {
		regex:       regexp.MustCompile(`\b[a-zA-Z0-9-]+\.auth0\.com\b`),
		description: "Auth0 tenant domains",
	},
	"okta-domains": {
		regex:       regexp.MustCompile(`\b[a-z0-9.-]+\.okta\.com\b`),
		description: "Okta tenant domains",
	},
	"snowflake-accounts": {
		regex:       regexp.MustCompile(`\b[a-zA-Z0-9_-]+\.snowflakecomputing\.com\b`),
		description: "Snowflake account endpoints",
	},
	"shopify-domains": {
		regex:       regexp.MustCompile(`\b[a-z0-9-]+\.myshopify\.com\b`),
		description: "Shopify store domains",
	},
	"jira-cloud": {
		regex:       regexp.MustCompile(`\b[a-zA-Z0-9-]+\.atlassian\.net\b`),
		description: "Jira Cloud site domains",
	},
	"cloudfront-domains": {
		regex:       regexp.MustCompile(`\b[a-z0-9]{16}\.cloudfront\.net\b`),
		description: "CloudFront distribution domains",
	},
	"digitalocean-spaces": {
		regex:       regexp.MustCompile(`\b[a-z0-9.-]+\.digitaloceanspaces\.com\b`),
		description: "DigitalOcean Spaces endpoints",
	},
	"rds-endpoints": {
		regex:       regexp.MustCompile(`\b[a-z0-9.-]+\.rds\.amazonaws\.com\b`),
		description: "AWS RDS endpoints",
	},
	"aws-arns": {
		regex:       regexp.MustCompile(`\barn:[A-Za-z0-9_-]+:[^ \n\t]+`),
		validate:    isValidARN,
		description: "AWS ARNs",
	},
	"cve-ids": {
		regex:       cveRegex,
		validate:    isValidCVE,
		description: "CVE identifiers",
	},
	"rfc3339-timestamps": {
		regex:       rfc3339Regex,
		validate:    isValidRFC3339,
		description: "RFC3339 timestamps",
	},
	"iso-datetimes": {
		regex:       regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b`),
		validate:    isValidISODatetime,
		description: "ISO datetimes without timezone (YYYY-MM-DDTHH:MM:SS)",
	},
	"ipv4-with-port": {
		regex:       ipv4PortRegex,
		validate:    isValidIPv4Port,
		description: "IPv4 addresses with ports",
	},
	"domain-ports": {
		regex:       domainPortRegex,
		requiresTLD: true,
		validate:    isValidDomainPort,
		description: "Domain names with ports",
	},
	"private-ipv4": {
		regex:       ipv4Regex,
		validate:    isIPv4Private,
		description: "Private IPv4 addresses",
	},
	"public-ipv4": {
		regex:       ipv4Regex,
		validate:    isIPv4Public,
		description: "Public IPv4 addresses",
	},
	"loopback-ipv4": {
		regex:       ipv4Regex,
		validate:    isIPv4Loopback,
		description: "Loopback IPv4 addresses",
	},
	"linklocal-ipv4": {
		regex:       ipv4Regex,
		validate:    isIPv4LinkLocal,
		description: "Link-local IPv4 addresses",
	},
	"private-ipv6": {
		regex:       ipv6Regex,
		validate:    isIPv6Private,
		description: "Unique-local IPv6 addresses (fc00::/7)",
	},
	"public-ipv6": {
		regex:       ipv6Regex,
		validate:    isIPv6Public,
		description: "Public-scoped IPv6 addresses",
	},
	"linklocal-ipv6": {
		regex:       ipv6Regex,
		validate:    isIPv6LinkLocal,
		description: "Link-local IPv6 addresses",
	},
	"ipv6-cidrs": {
		regex:       regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}/\d{1,3}\b`),
		validate:    isValidIPv6CIDR,
		description: "IPv6 CIDR blocks",
	},
	"ghp-tokens": {
		regex:       regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
		description: "GitHub PATs (ghp_)",
	},
	"gho-tokens": {
		regex:       regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`),
		description: "GitHub OAuth tokens (gho_)",
	},
	"ghu-tokens": {
		regex:       regexp.MustCompile(`\bghu_[A-Za-z0-9]{36}\b`),
		description: "GitHub User-to-Server tokens (ghu_)",
	},
	"ghs-tokens": {
		regex:       regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`),
		description: "GitHub Server-to-Server tokens (ghs_)",
	},
	"ghr-tokens": {
		regex:       regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`),
		description: "GitHub refresh tokens (ghr_)",
	},
	"gitlab-pats": {
		regex:       regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
		description: "GitLab personal access tokens",
	},
	"gitlab-runners": {
		regex:       regexp.MustCompile(`\bglrt-[A-Za-z0-9_-]{20}\b`),
		description: "GitLab runner registration tokens",
	},
	"slack-bot-tokens": {
		regex:       regexp.MustCompile(`\bxoxb-\d{10,12}-\d{10,12}-[A-Za-z0-9]{24}\b`),
		description: "Slack bot tokens (xoxb-)",
	},
	"slack-user-tokens": {
		regex:       regexp.MustCompile(`\bxoxp-\d{10,12}-\d{10,12}-[A-Za-z0-9]{24}\b`),
		description: "Slack user tokens (xoxp-)",
	},
	"slack-app-tokens": {
		regex:       regexp.MustCompile(`\bxapp-1-[A-Za-z0-9-]{147}\b`),
		description: "Slack app-level tokens (xapp-1-)",
	},
	"slack-legacy-tokens": {
		regex:       regexp.MustCompile(`\bxoxa-\d{10,12}-\d{10,12}-[A-Za-z0-9]{24}\b`),
		description: "Slack legacy workspace tokens (xoxa-)",
	},
	"stripe-secret-live": {
		regex:       regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24}\b`),
		description: "Stripe live secret keys (sk_live_)",
	},
	"stripe-secret-test": {
		regex:       regexp.MustCompile(`\bsk_test_[0-9a-zA-Z]{24}\b`),
		description: "Stripe test secret keys (sk_test_)",
	},
	"stripe-publishable-live": {
		regex:       regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24}\b`),
		description: "Stripe live publishable keys (pk_live_)",
	},
	"stripe-publishable-test": {
		regex:       regexp.MustCompile(`\bpk_test_[0-9a-zA-Z]{24}\b`),
		description: "Stripe test publishable keys (pk_test_)",
	},
	"stripe-restricted-live": {
		regex:       regexp.MustCompile(`\brk_live_[0-9a-zA-Z]{24}\b`),
		description: "Stripe live restricted keys (rk_live_)",
	},
	"stripe-restricted-test": {
		regex:       regexp.MustCompile(`\brk_test_[0-9a-zA-Z]{24}\b`),
		description: "Stripe test restricted keys (rk_test_)",
	},
	"sendgrid-api-keys": {
		regex:       regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
		description: "SendGrid API keys (SG.x.x)",
	},
	"twilio-account-sids": {
		regex:       regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`),
		description: "Twilio account SIDs (AC...32 hex)",
	},
	"twilio-api-keys": {
		regex:       regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
		description: "Twilio API keys (SK...32 hex)",
	},
	"telegram-bot-tokens": {
		regex:       regexp.MustCompile(`\b\d{9,10}:AA[A-Za-z0-9_-]{33}\b`),
		description: "Telegram bot tokens",
	},
	"discord-bot-tokens": {
		regex:       regexp.MustCompile(`\b[NM][A-Za-z0-9]{23}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27}\b`),
		description: "Discord bot tokens",
	},
	"discord-mfa-tokens": {
		regex:       regexp.MustCompile(`\bmfa\.[A-Za-z0-9_-]{84}\b`),
		description: "Discord MFA tokens",
	},
	"pypi-tokens": {
		regex:       regexp.MustCompile(`\bpypi-AgEI[0-9A-Za-z_-]{40,}\b`),
		description: "PyPI upload tokens (pypi-AgEI...)",
	},
	"npm-tokens": {
		regex:       regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		description: "npm tokens (npm_...)",
	},
	"google-api-keys": {
		regex:       googleAPIKeyRegex,
		description: "Google API keys (AIza...)",
	},
	"gcp-oauth-tokens": {
		regex:       gcpOAuthRegex,
		description: "Google OAuth tokens (ya29...)",
	},
	"google-client-ids": {
		regex:       googleClientIDRegex,
		description: "Google OAuth client IDs",
	},
	"dropbox-short-tokens": {
		regex:       dropboxShortRegex,
		description: "Dropbox short-lived tokens (sl.)",
	},
}

// Global TLD map
var validTLDs = make(map[string]struct{})
var (
	privateIPv4Nets  = mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
	loopbackIPv4Net  = mustCIDR("127.0.0.0/8")
	linkLocalIPv4Net = mustCIDR("169.254.0.0/16")
	multicastIPv4Net = mustCIDR("224.0.0.0/4")

	privateIPv6Nets  = mustCIDRs("fc00::/7")
	linkLocalIPv6Net = mustCIDR("fe80::/10")
	loopbackIPv6Net  = mustCIDR("::1/128")
)

func mustCIDR(c string) *net.IPNet {
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		panic(err)
	}
	return n
}

func mustCIDRs(list ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		out = append(out, mustCIDR(c))
	}
	return out
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	extractor, ok := modeExtractors[mode]
	if !ok {
		printUsage()
		os.Exit(1)
	}

	// 1. Setup Environment
	if extractor.requiresTLD {
		if err := setupTLDs(); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up TLDs: %v\n", err)
			os.Exit(1)
		}
	}

	// 2. Channels
	fileJobs := make(chan string, 2000) // Buffer file paths
	results := make(chan string, 2000)
	var wg sync.WaitGroup

	// 3. Start Workers (File Processors)
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go worker(extractor, fileJobs, results, &wg)
	}

	// 4. Start Collector (Deduplicator)
	done := make(chan bool)
	go collector(results, done)

	// 5. Walk the Filesystem (Producer)
	go func() {
		err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // access denied, etc. just skip
			}

			// Skip specific directories
			if d.IsDir() {
				if _, shouldSkip := skipDirs[d.Name()]; shouldSkip {
					return filepath.SkipDir
				}
				return nil
			}

			// It's a file, push to workers
			// Only process regular files
			if d.Type().IsRegular() {
				fileJobs <- path
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error walking path: %v\n", err)
		}
		close(fileJobs) // Done finding files
	}()

	// 6. Wait
	wg.Wait()      // Wait for all files to be processed
	close(results) // Tell collector we are done
	<-done         // Wait for printing to finish
}

// worker takes a file path, opens it, scans it, and extracts data
func worker(ext extractor, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Reuse buffer for scanner to reduce GC pressure
	// But since we open many files, we allocate inside loop or use a sync.Pool if strictly necessary.
	// For simplicity and safety, we allocate per file here.

	for path := range jobs {
		processFile(path, ext, results)
	}
}

func processFile(path string, ext extractor, results chan<- string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	// Quick Binary Check: Read first 512 bytes
	// If we find a NUL byte, it's likely a binary file (image, exe, etc) -> Skip
	bufHead := make([]byte, 512)
	n, _ := file.Read(bufHead)
	for i := 0; i < n; i++ {
		if bufHead[i] == 0 {
			return // Skip binary file
		}
	}

	// Rewind file for scanner
	file.Seek(0, 0)

	scanner := bufio.NewScanner(file)
	// Allow scanning very long lines (up to 1MB)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		matches := ext.regex.FindAllString(line, -1)
		for _, m := range matches {
			if ext.normalize != nil {
				m = ext.normalize(m)
			}
			if ext.validate != nil && !ext.validate(m) {
				continue
			}
			results <- m
		}
	}
}

// collector handles deduplication and printing
func collector(results <-chan string, done chan<- bool) {
	seen := make(map[string]struct{})
	for item := range results {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			fmt.Println(item)
		}
	}
	done <- true
}

func isValidDomain(d string) bool {
	d = strings.TrimSuffix(d, ".")
	if len(d) < 4 || len(d) > 253 {
		return false
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}

	// TLD Check
	tld := strings.ToUpper(parts[len(parts)-1])
	if _, ok := validTLDs[tld]; !ok {
		return false
	}

	// Label Checks
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	return true
}

func isValidURL(rawUrl string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return isValidDomain(u.Hostname())
}

func isValidHost(host string, allowBareHost bool, requireTLD bool) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if requireTLD {
		return isValidDomain(host)
	}
	if len(validTLDs) > 0 && isValidDomain(host) {
		return true
	}
	if domainRegex.MatchString(host) {
		return true
	}
	return allowBareHost && simpleHostRegex.MatchString(host)
}

func schemeValidator(requireHost bool, allowBareHost bool, requireTLD bool, schemes ...string) func(string) bool {
	allowed := make(map[string]struct{}, len(schemes))
	for _, s := range schemes {
		allowed[s] = struct{}{}
	}
	return func(raw string) bool {
		u, err := url.Parse(raw)
		if err != nil {
			return false
		}
		if _, ok := allowed[u.Scheme]; !ok {
			return false
		}
		host := u.Hostname()
		if host == "" {
			return !requireHost
		}
		return isValidHost(host, allowBareHost, requireTLD)
	}
}

func setupTLDs() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, configFolder)
	filePath := filepath.Join(configPath, tldFile)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		os.MkdirAll(configPath, 0755)
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if err := downloadFile(filePath, ianaURL); err != nil {
			return err
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		validTLDs[line] = struct{}{}
	}
	return scanner.Err()
}

func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: lazygrep <mode>\n")
	fmt.Fprintf(os.Stderr, "Modes:\n")
	names := make([]string, 0, len(modeExtractors))
	for name := range modeExtractors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ext := modeExtractors[name]
		fmt.Fprintf(os.Stderr, "  - %-13s %s\n", name, ext.description)
	}
}

func lowerTrim(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func stripSpacesAndHyphens(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	return strings.ReplaceAll(s, "-", "")
}

func isValidEmail(e string) bool {
	parts := strings.Split(e, "@")
	if len(parts) != 2 {
		return false
	}
	local, domain := parts[0], parts[1]
	if local == "" || len(local) > 64 {
		return false
	}
	return isValidDomain(domain)
}

func isIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && strings.Count(ip, ":") == 0
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && strings.Contains(ip, ":")
}

func isIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] { // header and payload must decode
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			return false
		}
	}
	return true
}

func isValidCard(num string) bool {
	if len(num) < 13 || len(num) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func isValidISODate(value string) bool {
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}

func isValidCIDR(c string) bool {
	ip, ipnet, err := net.ParseCIDR(c)
	if err != nil || ip == nil || ipnet == nil {
		return false
	}
	ones, bits := ipnet.Mask.Size()
	return bits == 32 && ones >= 0 && ones <= 32
}

func isValidBase64(s string) bool {
	if len(s) < 20 {
		return false
	}
	// normalize padding
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func isValidIPv4Port(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	ip := net.ParseIP(parts[0])
	if ip == nil || ip.To4() == nil {
		return false
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return true
}

func isValidDomainPort(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return false
	}
	return isValidDomain(host)
}

func containsNet(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isIPv4Private(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return containsNet(ip, privateIPv4Nets)
}

func isIPv4Loopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return loopbackIPv4Net.Contains(ip)
}

func isIPv4LinkLocal(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return linkLocalIPv4Net.Contains(ip)
}

func isIPv4Public(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if containsNet(ip, privateIPv4Nets) || loopbackIPv4Net.Contains(ip) || linkLocalIPv4Net.Contains(ip) || multicastIPv4Net.Contains(ip) {
		return false
	}
	return true
}

func isIPv6Private(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return false
	}
	return containsNet(ip, privateIPv6Nets)
}

func isIPv6LinkLocal(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return false
	}
	return linkLocalIPv6Net.Contains(ip)
}

func isIPv6Public(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() || loopbackIPv6Net.Contains(ip) || linkLocalIPv6Net.Contains(ip) || containsNet(ip, privateIPv6Nets) {
		return false
	}
	return true
}

func isValidIPv6CIDR(value string) bool {
	_, netw, err := net.ParseCIDR(value)
	if err != nil || netw == nil {
		return false
	}
	ones, bits := netw.Mask.Size()
	return bits == 128 && ones >= 0 && ones <= 128
}

func isValidRFC3339(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func isValidISODatetime(value string) bool {
	_, err := time.Parse("2006-01-02T15:04:05", value)
	return err == nil
}

func isValidCVE(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 3 {
		return false
	}
	year, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	idNum, err := strconv.Atoi(parts[2])
	if err != nil || idNum <= 0 {
		return false
	}
	current := time.Now().Year() + 1
	return year >= 1999 && year <= current
}

func isValidARN(value string) bool {
	if !strings.HasPrefix(value, "arn:") {
		return false
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) < 6 {
		return false
	}
	if parts[2] == "" || parts[5] == "" {
		return false
	}
	return true
}
