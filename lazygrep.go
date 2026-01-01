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
	workerCount  = 30
	configFolder = ".config/ezgrep"
	tldFile      = "tlds-alpha-by-domain.txt"
)

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

// Regex patterns (pre-compiled for common patterns)
var (
	domainRegex     = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	urlRegex        = regexp.MustCompile(`https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
	emailRegex      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	ipv4Regex       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex       = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|\b::1\b|\b::\b`)
	ipRegex         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|\b::1\b|\b::\b`)
	macRegex        = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
	uuidRegex       = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b`)
	sha256Regex     = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	sha1Regex       = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	md5Regex        = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	jwtRegex        = regexp.MustCompile(`\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	cardRegex       = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	awsKeyRegex     = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	slackHookRegex  = regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`)
	bcryptRegex     = regexp.MustCompile(`\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}`)
	base64Regex     = regexp.MustCompile(`\b(?:[A-Za-z0-9+/]{20,}={0,2})\b`)
	schemeURLRegex  = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)
	ipv4PortRegex   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	domainPortRegex = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}:\d{1,5}\b`)
	cveRegex        = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	simpleHostRegex = regexp.MustCompile(`^[a-zA-Z0-9-]{1,63}$`)
)

type extractor struct {
	regex       *regexp.Regexp
	requiresTLD bool
	normalize   func(string) string
	validate    func(string) bool
	description string
}

var modeExtractors = map[string]extractor{
	// Core network patterns (essential for everyone)
	"domains":          {regex: domainRegex, requiresTLD: true, normalize: lowerTrim, validate: isValidDomain, description: "Domain names with valid TLDs"},
	"urls":             {regex: urlRegex, requiresTLD: true, normalize: strings.TrimSpace, validate: isValidURL, description: "HTTP/HTTPS URLs"},
	"emails":           {regex: emailRegex, requiresTLD: true, normalize: lowerTrim, validate: isValidEmail, description: "Email addresses"},
	"ipv4":             {regex: ipv4Regex, validate: isIPv4, description: "IPv4 addresses"},
	"ipv6":             {regex: ipv6Regex, validate: isIPv6, description: "IPv6 addresses"},
	"ips":              {regex: ipRegex, validate: isIP, description: "IPv4 or IPv6 addresses"},
	"private-ips":      {regex: ipv4Regex, validate: isIPv4Private, description: "RFC1918 private IPs"},
	"public-ips":       {regex: ipv4Regex, validate: isIPv4Public, description: "Public routable IPv4"},
	"ipv4-with-port":   {regex: ipv4PortRegex, validate: isValidIPv4Port, description: "IPv4:port pairs"},
	"domain-ports":     {regex: domainPortRegex, requiresTLD: true, validate: isValidDomainPort, description: "domain:port pairs"},
	"ipv4-cidrs":       {regex: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`), validate: isValidCIDR, description: "IPv4 CIDR notation"},
	"ipv6-cidrs":       {regex: regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}/\d{1,3}\b`), validate: isValidIPv6CIDR, description: "IPv6 CIDR notation"},
	"macs":             {regex: macRegex, description: "MAC addresses"},
	"asn-numbers":      {regex: regexp.MustCompile(`\bAS\d{1,10}\b`), description: "Autonomous System Numbers"},
	"internal-domains": {regex: regexp.MustCompile(`\b[a-z0-9-]+\.(?:local|internal|corp|lan|private)\b`), description: "Internal domain TLDs"},
	"localhost-refs":   {regex: regexp.MustCompile(`\blocalhost(?::\d{1,5})?\b`), description: "localhost references"},

	// Hashes & crypto (forensics, password audits, API keys)
	"md5":                 {regex: md5Regex, description: "MD5 hashes"},
	"sha1":                {regex: sha1Regex, description: "SHA-1 hashes"},
	"sha256":              {regex: sha256Regex, description: "SHA-256 hashes"},
	"sha384":              {regex: regexp.MustCompile(`\b[a-fA-F0-9]{96}\b`), description: "SHA-384 hashes"},
	"sha512":              {regex: regexp.MustCompile(`\b[a-fA-F0-9]{128}\b`), description: "SHA-512 hashes"},
	"bcrypt":              {regex: bcryptRegex, description: "bcrypt hashes"},
	"argon2id":            {regex: regexp.MustCompile(`\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+`), description: "Argon2id hashes"},
	"ntlm-hashes":         {regex: regexp.MustCompile(`\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b`), description: "NTLM hash pairs"},
	"unix-crypt":          {regex: regexp.MustCompile(`\$[156y]\$[^\s:]{1,}$`), description: "Unix crypt hashes"},
	"django-pbkdf2":       {regex: regexp.MustCompile(`pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+`), description: "Django PBKDF2 hashes"},
	"jwt":                 {regex: jwtRegex, validate: isJWT, description: "JWT tokens"},
	"base64":              {regex: base64Regex, validate: isValidBase64, description: "Base64 strings (20+ chars)"},
	"hex-strings":         {regex: regexp.MustCompile(`\b0x[a-fA-F0-9]{8,}\b`), description: "Hex encoded data (0x prefix)"},
	"uuids":               {regex: uuidRegex, description: "UUIDs"},
	"api-key-patterns":    {regex: regexp.MustCompile(`(?i)\bapi[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})`), description: "Generic API key patterns"},
	"secret-patterns":     {regex: regexp.MustCompile(`(?i)\b(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'"]{6,})`), description: "Password/secret assignment"},
	"bearer-tokens":       {regex: regexp.MustCompile(`\bBearer\s+[A-Za-z0-9_\-\.]{20,}`), description: "Bearer token headers"},
	"basic-auth":          {regex: regexp.MustCompile(`\bBasic\s+[A-Za-z0-9+/=]{16,}`), description: "Basic auth headers"},
	"auth-headers":        {regex: regexp.MustCompile(`Authorization:\s*[^\r\n]+`), description: "Authorization header values"},
	"session-cookies":     {regex: regexp.MustCompile(`(?:PHPSESSID|JSESSIONID|connect\.sid|session)=[A-Za-z0-9\-_]{16,}`), description: "Session cookie values"},
	"api-endpoints":       {regex: regexp.MustCompile(`(?:https?://[^\s"']+)?/api/v?\d+/[^\s"'<>]*`), description: "API endpoint paths"},
	"rest-paths":          {regex: regexp.MustCompile(`(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s"']*)`), description: "REST endpoint paths"},
	"graphql-endpoints":   {regex: regexp.MustCompile(`https?://[^\s"']+/graphql`), description: "GraphQL endpoints"},
	"admin-paths":         {regex: regexp.MustCompile(`(?i)/(admin|administrator|manager|dashboard|panel|control)/[^\s"']*`), description: "Admin panel paths"},
	"login-paths":         {regex: regexp.MustCompile(`(?i)/(login|signin|auth|authenticate)[^\s"']*`), description: "Login endpoint paths"},
	"upload-paths":        {regex: regexp.MustCompile(`(?i)/(upload|uploader|file-upload)[^\s"']*`), description: "File upload paths"},
	"debug-paths":         {regex: regexp.MustCompile(`(?i)/(debug|trace|console|phpinfo)[^\s"']*`), description: "Debug/info paths"},
	"backup-files":        {regex: regexp.MustCompile(`\b[\w.-]+\.(?:bak|backup|old|orig|save|swp|tmp|~)\b`), description: "Backup file extensions"},
	"config-files":        {regex: regexp.MustCompile(`\b[\w.-]*(?:config|conf|settings|env|properties)[\w.-]*\b`), description: "Config file names"},
	"db-files":            {regex: regexp.MustCompile(`\b[\w.-]+\.(?:sql|db|sqlite|sqlite3|mdb|accdb)\b`), description: "Database files"},
	"sql-dumps":           {regex: regexp.MustCompile(`\b[\w.-]*dump[\w.-]*\.(?:sql|gz|zip)\b`), description: "SQL dump files"},
	"log-files":           {regex: regexp.MustCompile(`\b[\w.-]+\.(?:log|logs)\b`), description: "Log file names"},
	"key-files":           {regex: regexp.MustCompile(`\b[\w.-]*(?:key|pem|crt|cer|p12|pfx|jks|keystore)[\w.-]*\b`), description: "Cryptographic key files"},
	"dotenv-vars":         {regex: regexp.MustCompile(`^[A-Z_][A-Z0-9_]*=.+`), description: ".env variable assignments"},
	"env-secrets":         {regex: regexp.MustCompile(`(?i)(?:PASSWORD|SECRET|KEY|TOKEN)=[^\s]+`), description: "Environment secrets"},
	"connection-strings":  {regex: regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|jdbc|sqlserver)://[^\s"'<>]+`), description: "Database connection strings"},
	"jdbc-connections":    {regex: regexp.MustCompile(`jdbc:[a-z]+://[^\s"'<>]+`), description: "JDBC connection strings"},
	"ftp-credentials":     {regex: regexp.MustCompile(`ftp://[^:]+:[^@]+@[^\s"'<>]+`), description: "FTP URLs with credentials"},
	"embedded-passwords":  {regex: regexp.MustCompile(`(?i)://[^:]+:[^@]{4,}@[^\s"'<>]+`), description: "URLs with embedded passwords"},
	"credentials-in-url":  {regex: regexp.MustCompile(`(?i)[a-z]+://[a-z0-9]+:[a-z0-9]+@`), description: "Protocol URLs with creds"},
	"internal-ips":        {regex: regexp.MustCompile(`\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b`), description: "Internal IP ranges"},
	"cloud-metadata-urls": {regex: regexp.MustCompile(`http://169\.254\.169\.254/[^\s"']*`), description: "Cloud metadata service URLs"},
	"aws-metadata":        {regex: regexp.MustCompile(`169\.254\.169\.254/latest/meta-data`), description: "AWS metadata endpoints"},
	"gcp-metadata":        {regex: regexp.MustCompile(`metadata\.google\.internal`), description: "GCP metadata endpoints"},
	"azure-metadata":      {regex: regexp.MustCompile(`169\.254\.169\.254/metadata`), description: "Azure metadata endpoints"},

	// AWS secrets & infrastructure
	"aws-keys":              {regex: awsKeyRegex, description: "AWS access keys (AKIA/ASIA)"},
	"aws-secret-keys":       {regex: regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`), validate: isLikelyAWSSecret, description: "AWS secret access keys"},
	"aws-session-tokens":    {regex: regexp.MustCompile(`\b[A-Za-z0-9/+=]{100,}\b`), description: "AWS session tokens"},
	"aws-account-ids":       {regex: regexp.MustCompile(`\b\d{12}\b`), validate: isLikelyAWSAccount, description: "AWS account IDs (12 digits)"},
	"aws-arns":              {regex: regexp.MustCompile(`\barn:[A-Za-z0-9_-]+:[^\s\n\t]+`), validate: isValidARN, description: "AWS ARNs"},
	"s3-buckets":            {regex: regexp.MustCompile(`\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b`), description: "S3 bucket domains"},
	"s3-urls":               {regex: regexp.MustCompile(`s3://[a-z0-9.-]+(?:/[^\s"'<>]*)?`), description: "S3 protocol URLs"},
	"s3-presigned":          {regex: regexp.MustCompile(`https://[^/]+\.amazonaws\.com/[^?\s"']*\?[^"\s]*X-Amz-Signature=[a-fA-F0-9]{64}`), description: "S3 presigned URLs"},
	"cloudfront-domains":    {regex: regexp.MustCompile(`\b[a-z0-9]{13,16}\.cloudfront\.net\b`), description: "CloudFront distributions"},
	"ec2-metadata":          {regex: regexp.MustCompile(`http://169\.254\.169\.254/latest/`), description: "EC2 metadata URLs"},
	"lambda-urls":           {regex: regexp.MustCompile(`https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws`), description: "AWS Lambda function URLs"},
	"apigateway-urls":       {regex: regexp.MustCompile(`https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com`), description: "API Gateway URLs"},
	"rds-endpoints":         {regex: regexp.MustCompile(`\b[a-z0-9.-]+\.rds\.amazonaws\.com\b`), description: "RDS database endpoints"},
	"dynamodb-endpoints":    {regex: regexp.MustCompile(`dynamodb\.[a-z0-9-]+\.amazonaws\.com`), description: "DynamoDB endpoints"},
	"sqs-urls":              {regex: regexp.MustCompile(`https://sqs\.[a-z0-9-]+\.amazonaws\.com/\d+/[a-zA-Z0-9_-]+`), description: "SQS queue URLs"},
	"sns-topics":            {regex: regexp.MustCompile(`arn:aws:sns:[a-z0-9-]+:\d{12}:[a-zA-Z0-9_-]+`), description: "SNS topic ARNs"},
	"elastic-ips":           {regex: regexp.MustCompile(`\b(?:3|13|15|18|34|35|52|54|99|100|107)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`), description: "Elastic IP ranges"},
	"ecs-endpoints":         {regex: regexp.MustCompile(`[a-z0-9-]+\.ecs\.[a-z0-9-]+\.amazonaws\.com`), description: "ECS service endpoints"},
	"eks-endpoints":         {regex: regexp.MustCompile(`[A-Z0-9]+\.eks\.[a-z0-9-]+\.amazonaws\.com`), description: "EKS cluster endpoints"},
	"elasticache-endpoints": {regex: regexp.MustCompile(`[a-z0-9.-]+\.cache\.amazonaws\.com`), description: "ElastiCache endpoints"},

	// GCP secrets & infrastructure
	"gcp-api-keys":          {regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), description: "GCP API keys"},
	"gcp-oauth":             {regex: regexp.MustCompile(`\bya29\.[0-9A-Za-z\-_]+\b`), description: "GCP OAuth tokens"},
	"gcp-service-accounts":  {regex: regexp.MustCompile(`\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b`), description: "GCP service accounts"},
	"gcp-project-ids":       {regex: regexp.MustCompile(`\b[a-z][a-z0-9-]{4,28}[a-z0-9]\b`), validate: isLikelyGCPProject, description: "GCP project IDs"},
	"gcs-buckets":           {regex: regexp.MustCompile(`gs://[a-z0-9._-]+`), description: "Google Cloud Storage buckets"},
	"gcs-urls":              {regex: regexp.MustCompile(`https://storage\.googleapis\.com/[a-z0-9._-]+`), description: "GCS HTTP URLs"},
	"firebase-urls":         {regex: regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), description: "Firebase Realtime DB URLs"},
	"firebase-ids":          {regex: regexp.MustCompile(`\b[a-z0-9-]+\.firebaseapp\.com\b`), description: "Firebase app domains"},
	"firestore-refs":        {regex: regexp.MustCompile(`projects/[^/]+/databases/[^/]+/documents/[^\s"']+`), description: "Firestore document paths"},
	"gcp-function-urls":     {regex: regexp.MustCompile(`https://[a-z0-9-]+-[a-z0-9]+-[a-z]{2}\.cloudfunctions\.net`), description: "Cloud Functions URLs"},
	"gcp-run-urls":          {regex: regexp.MustCompile(`https://[a-z0-9-]+-[a-z0-9]+-[a-z]{2}\.a\.run\.app`), description: "Cloud Run URLs"},
	"bigquery-tables":       {regex: regexp.MustCompile(`[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_]+`), validate: isLikelyBQTable, description: "BigQuery table refs"},
	"gke-clusters":          {regex: regexp.MustCompile(`container\.googleapis\.com/v1/projects/[^/]+/zones/[^/]+/clusters/[^\s"']+`), description: "GKE cluster endpoints"},

	// Azure secrets & infrastructure
	"azure-storage-keys":  {regex: regexp.MustCompile(`\b[A-Za-z0-9+/]{88}==\b`), description: "Azure storage account keys"},
	"azure-connection":    {regex: regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`), description: "Azure storage connections"},
	"azure-blob-urls":     {regex: regexp.MustCompile(`https://[\w-]+\.blob\.core\.windows\.net`), description: "Azure Blob Storage URLs"},
	"azure-sas-tokens":    {regex: regexp.MustCompile(`\?sv=\d{4}-\d{2}-\d{2}&[^\s"']*sig=[A-Za-z0-9%]+`), description: "Azure SAS tokens"},
	"azure-tenant-ids":    {regex: uuidRegex, validate: isUUID, description: "Azure tenant/app IDs"},
	"azure-client-secret": {regex: regexp.MustCompile(`\b[A-Za-z0-9_\-\.~]{34,}\b`), description: "Azure client secrets"},
	"azure-app-insights":  {regex: regexp.MustCompile(`InstrumentationKey=[a-fA-F0-9-]{36}`), description: "App Insights keys"},
	"azure-keyvault-urls": {regex: regexp.MustCompile(`https://[a-z0-9-]+\.vault\.azure\.net`), description: "Key Vault URLs"},
	"azure-cosmosdb":      {regex: regexp.MustCompile(`https://[a-z0-9-]+\.documents\.azure\.com`), description: "CosmosDB endpoints"},
	"azure-sql":           {regex: regexp.MustCompile(`[a-z0-9-]+\.database\.windows\.net`), description: "Azure SQL endpoints"},
	"azure-functions":     {regex: regexp.MustCompile(`https://[a-z0-9-]+\.azurewebsites\.net`), description: "Azure Functions URLs"},
	"azure-devops":        {regex: regexp.MustCompile(`https://dev\.azure\.com/[A-Za-z0-9_.-]+`), description: "Azure DevOps URLs"},

	// GitHub secrets & patterns
	"github-pat":          {regex: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,255}\b`), description: "GitHub personal tokens"},
	"github-oauth":        {regex: regexp.MustCompile(`\bgho_[A-Za-z0-9]{36,255}\b`), description: "GitHub OAuth tokens"},
	"github-app":          {regex: regexp.MustCompile(`\b(?:ghu|ghs)_[A-Za-z0-9]{36,255}\b`), description: "GitHub App tokens"},
	"github-refresh":      {regex: regexp.MustCompile(`\bghr_[A-Za-z0-9]{36,255}\b`), description: "GitHub refresh tokens"},
	"github-fine-grained": {regex: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`), description: "GitHub fine-grained PATs"},
	"github-actions":      {regex: regexp.MustCompile(`\bGITHUB_TOKEN|secrets\.[A-Z_]+`), description: "GitHub Actions secrets refs"},
	"github-webhook":      {regex: regexp.MustCompile(`https://[^/]+/webhooks/[A-Za-z0-9]+`), description: "GitHub webhook URLs"},
	"github-raw-urls":     {regex: regexp.MustCompile(`https://raw\.githubusercontent\.com/[^\s"']+`), description: "GitHub raw content URLs"},
	"github-gists":        {regex: regexp.MustCompile(`https://gist\.github(?:usercontent)?\.com/[^\s"']+`), description: "GitHub Gist URLs"},
	"github-repos":        {regex: regexp.MustCompile(`github\.com[/:]([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)`), description: "GitHub repo references"},

	// GitLab secrets
	"gitlab-pat":     {regex: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`), description: "GitLab PATs"},
	"gitlab-runner":  {regex: regexp.MustCompile(`\bglrt-[A-Za-z0-9_-]{20}\b`), description: "GitLab runner tokens"},
	"gitlab-trigger": {regex: regexp.MustCompile(`\bglptt-[A-Za-z0-9_-]{40}\b`), description: "GitLab pipeline triggers"},
	"gitlab-oauth":   {regex: regexp.MustCompile(`\bgloa-[A-Za-z0-9_-]{64}\b`), description: "GitLab OAuth tokens"},

	// Slack secrets
	"slack-webhook":     {regex: slackHookRegex, description: "Slack webhook URLs"},
	"slack-bot-token":   {regex: regexp.MustCompile(`\bxoxb-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,32}\b`), description: "Slack bot tokens"},
	"slack-user-token":  {regex: regexp.MustCompile(`\bxoxp-\d{10,13}-\d{10,13}-\d{10,13}-[A-Za-z0-9]{32}\b`), description: "Slack user tokens"},
	"slack-app-token":   {regex: regexp.MustCompile(`\bxapp-\d-[A-Za-z0-9]+-\d+-[a-f0-9]{64}\b`), description: "Slack app tokens"},
	"slack-workspace":   {regex: regexp.MustCompile(`\b[a-z0-9-]+\.slack\.com\b`), description: "Slack workspace domains"},
	"slack-oauth":       {regex: regexp.MustCompile(`\bxox[aprb]-[A-Za-z0-9-]+`), description: "Generic Slack tokens"},
	"slack-signing":     {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelySlackSigning, description: "Slack signing secrets"},
	"slack-channel-ids": {regex: regexp.MustCompile(`\bC[A-Z0-9]{8,12}\b`), description: "Slack channel IDs"},

	// Payment & financial APIs
	"stripe-live-secret":   {regex: regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,99}\b`), description: "Stripe live secret keys"},
	"stripe-test-secret":   {regex: regexp.MustCompile(`\bsk_test_[0-9a-zA-Z]{24,99}\b`), description: "Stripe test secret keys"},
	"stripe-live-pub":      {regex: regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,99}\b`), description: "Stripe live publishable"},
	"stripe-test-pub":      {regex: regexp.MustCompile(`\bpk_test_[0-9a-zA-Z]{24,99}\b`), description: "Stripe test publishable"},
	"stripe-restricted":    {regex: regexp.MustCompile(`\brk_(?:live|test)_[0-9a-zA-Z]{24,99}\b`), description: "Stripe restricted keys"},
	"stripe-webhook":       {regex: regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{32,}\b`), description: "Stripe webhook secrets"},
	"paypal-client-id":     {regex: regexp.MustCompile(`\bA[A-Za-z0-9_-]{60,80}\b`), validate: isLikelyPayPal, description: "PayPal client IDs"},
	"square-tokens":        {regex: regexp.MustCompile(`\bsq0[a-z]{3}-[A-Za-z0-9\-_]{22,43}\b`), description: "Square access tokens"},
	"braintree-tokens":     {regex: regexp.MustCompile(`\baccess_token\$[a-z]{10}\$[a-z0-9]{16}\$[a-f0-9]{32}`), description: "Braintree tokens"},
	"credit-cards":         {regex: cardRegex, normalize: stripSpacesAndHyphens, validate: isValidCard, description: "Credit card numbers (Luhn)"},
	"iban-numbers":         {regex: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`), description: "IBAN bank accounts"},
	"bitcoin-addresses":    {regex: regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`), description: "Bitcoin addresses"},
	"ethereum-addresses":   {regex: regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`), description: "Ethereum addresses"},
	"crypto-private-keys":  {regex: regexp.MustCompile(`\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b`), description: "Bitcoin private keys (WIF)"},
	"solana-addresses":     {regex: regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`), validate: isLikelySolana, description: "Solana wallet addresses"},
	"monero-addresses":     {regex: regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`), description: "Monero addresses"},
	"litecoin-addresses":   {regex: regexp.MustCompile(`\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b`), description: "Litecoin addresses"},
	"dogecoin-addresses":   {regex: regexp.MustCompile(`\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b`), description: "Dogecoin addresses"},
	"ripple-addresses":     {regex: regexp.MustCompile(`\br[a-zA-Z0-9]{24,34}\b`), description: "Ripple (XRP) addresses"},
	"cardano-addresses":    {regex: regexp.MustCompile(`\baddr1[a-z0-9]{58,}\b`), description: "Cardano addresses"},
	"wallet-seeds":         {regex: regexp.MustCompile(`\b(?:[a-z]+\s+){11,23}[a-z]+\b`), validate: isLikelySeedPhrase, description: "Crypto wallet seed phrases"},
	"metamask-phrases":     {regex: regexp.MustCompile(`(?i)metamask.{0,50}(?:seed|phrase|recovery)`), description: "MetaMask seed references"},
	"wallet-json":          {regex: regexp.MustCompile(`\{[^}]*"version":\s*3[^}]*"crypto":[^}]*\}`), description: "Ethereum keystore JSON"},

	// Communication & messaging APIs
	"twilio-sid":             {regex: regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`), description: "Twilio account SIDs"},
	"twilio-auth-token":      {regex: regexp.MustCompile(`\b[0-9a-f]{32}\b`), validate: isLikelyTwilioAuth, description: "Twilio auth tokens"},
	"twilio-api-key":         {regex: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), description: "Twilio API keys"},
	"sendgrid-keys":          {regex: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), description: "SendGrid API keys"},
	"mailgun-keys":           {regex: regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`), description: "Mailgun API keys"},
	"mailchimp-keys":         {regex: regexp.MustCompile(`\b[0-9a-f]{32}-us\d{1,2}\b`), description: "Mailchimp API keys"},
	"telegram-bot":           {regex: regexp.MustCompile(`\b\d{9,10}:AA[A-Za-z0-9_-]{33}\b`), description: "Telegram bot tokens"},
	"discord-bot":            {regex: regexp.MustCompile(`\b[NM][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b`), description: "Discord bot tokens"},
	"discord-webhook":        {regex: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`), description: "Discord webhook URLs"},
	"discord-mfa":            {regex: regexp.MustCompile(`\bmfa\.[A-Za-z0-9_-]{84}\b`), description: "Discord MFA tokens"},
	"zoom-jwt":               {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{200,}\b`), validate: isLikelyZoomJWT, description: "Zoom JWT tokens"},
	"zoom-webhook-token":     {regex: regexp.MustCompile(`\b[A-Za-z0-9]{64}\b`), validate: isLikelyZoomWebhook, description: "Zoom webhook tokens"},
	"whatsapp-business-keys": {regex: regexp.MustCompile(`\bEAA[A-Za-z0-9]{100,}\b`), description: "WhatsApp Business API tokens"},

	// CI/CD & deployment
	"jenkins-api-token":    {regex: regexp.MustCompile(`\b[a-f0-9]{32,34}\b`), validate: isLikelyJenkinsToken, description: "Jenkins API tokens"},
	"circleci-token":       {regex: regexp.MustCompile(`\b[a-f0-9]{40}\b`), validate: isLikelyCircleCI, description: "CircleCI tokens"},
	"travis-token":         {regex: regexp.MustCompile(`\b[a-zA-Z0-9_-]{22}\b`), validate: isLikelyTravisCI, description: "Travis CI tokens"},
	"docker-hub-token":     {regex: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{32,}\b`), description: "Docker Hub access tokens"},
	"heroku-api-key":       {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Heroku API keys"},
	"netlify-token":        {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`), validate: isLikelyNetlify, description: "Netlify access tokens"},
	"vercel-token":         {regex: regexp.MustCompile(`\b[A-Za-z0-9]{24}\b`), validate: isLikelyVercel, description: "Vercel tokens"},
	"digitalocean-token":   {regex: regexp.MustCompile(`\b[a-f0-9]{64}\b`), validate: isLikelyDOToken, description: "DigitalOcean tokens"},
	"kubernetes-token":     {regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{100,}\b`), description: "Kubernetes service tokens"},
	"rancher-keys":         {regex: regexp.MustCompile(`\btoken-[a-z0-9]{5}:[a-z0-9]{54}\b`), description: "Rancher API tokens"},
	"ansible-vault":        {regex: regexp.MustCompile(`\$ANSIBLE_VAULT;[0-9.]+;[A-Z0-9]+`), description: "Ansible Vault headers"},
	"terraform-cloud":      {regex: regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b`), description: "Terraform Cloud tokens"},
	"cloud-init-secrets":   {regex: regexp.MustCompile(`#cloud-config[\s\S]{0,200}(?:password|token|key):`), description: "cloud-init with secrets"},
	"docker-compose-envs":  {regex: regexp.MustCompile(`(?:POSTGRES|MYSQL|MONGO)_PASSWORD=.+`), description: "Docker Compose secrets"},
	"drone-ci-token":       {regex: regexp.MustCompile(`\b[a-zA-Z0-9]{32}\b`), validate: isLikelyDroneCI, description: "Drone CI tokens"},
	"buildkite-token":      {regex: regexp.MustCompile(`\b[a-f0-9]{40}\b`), validate: isLikelyBuildkite, description: "Buildkite tokens"},
	"gitlab-ci-vars":       {regex: regexp.MustCompile(`\$CI_[A-Z_]+`), description: "GitLab CI variable refs"},
	"bitbucket-app-secret": {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelyBitbucket, description: "Bitbucket app secrets"},

	// Package managers & registries
	"npm-token":     {regex: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), description: "npm access tokens"},
	"pypi-token":    {regex: regexp.MustCompile(`\bpypi-AgEI[0-9A-Za-z_-]{50,}\b`), description: "PyPI upload tokens"},
	"rubygems-key":  {regex: regexp.MustCompile(`\brubygems_[a-f0-9]{48}\b`), description: "RubyGems API keys"},
	"nuget-key":     {regex: regexp.MustCompile(`\bNU-[A-Za-z0-9]{48}\b`), description: "NuGet API keys"},
	"cargo-token":   {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{22}\b`), validate: isLikelyCargoToken, description: "Cargo registry tokens"},
	"maven-password": {regex: regexp.MustCompile(`<password>[^<]{6,}</password>`), description: "Maven settings passwords"},
	"gradle-keys":   {regex: regexp.MustCompile(`(?:sonatypeUsername|signing\.key)=.+`), description: "Gradle publish credentials"},
	"composer-auth": {regex: regexp.MustCompile(`"github-oauth":\s*\{\s*"github\.com":\s*"[a-f0-9]{40}"`), description: "Composer GitHub tokens"},

	// Database & caching
	"postgres-urls":        {regex: regexp.MustCompile(`postgres(?:ql)?://[^\s"'<>]+`), description: "PostgreSQL URLs"},
	"mysql-urls":           {regex: regexp.MustCompile(`mysql://[^\s"'<>]+`), description: "MySQL URLs"},
	"mongodb-urls":         {regex: regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"'<>]+`), description: "MongoDB URLs"},
	"redis-urls":           {regex: regexp.MustCompile(`redis(?:s)?://[^\s"'<>]+`), description: "Redis URLs"},
	"cassandra-urls":       {regex: regexp.MustCompile(`cassandra://[^\s"'<>]+`), description: "Cassandra URLs"},
	"elasticsearch-urls":   {regex: regexp.MustCompile(`https?://[^\s"'<>]*:9200`), description: "Elasticsearch URLs"},
	"memcached-urls":       {regex: regexp.MustCompile(`memcache(?:d)?://[^\s"'<>]+`), description: "Memcached URLs"},
	"rabbitmq-urls":        {regex: regexp.MustCompile(`amqp(?:s)?://[^\s"'<>]+`), description: "RabbitMQ URLs"},
	"kafka-brokers":        {regex: regexp.MustCompile(`\b[a-z0-9.-]+:\d{4,5}(?:,[a-z0-9.-]+:\d{4,5})*\b`), validate: isLikelyKafka, description: "Kafka broker lists"},
	"influxdb-tokens":      {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{88}==\b`), description: "InfluxDB tokens"},
	"couchdb-urls":         {regex: regexp.MustCompile(`https?://[^@\s]+:[^@\s]+@[^\s"'<>]+:5984`), description: "CouchDB with auth"},
	"neo4j-urls":           {regex: regexp.MustCompile(`neo4j(?:\+s)?://[^\s"'<>]+`), description: "Neo4j URLs"},
	"clickhouse-urls":      {regex: regexp.MustCompile(`clickhouse://[^\s"'<>]+`), description: "ClickHouse URLs"},
	"cockroachdb-urls":     {regex: regexp.MustCompile(`postgres://.*:26257`), description: "CockroachDB URLs"},
	"timescaledb-urls":     {regex: regexp.MustCompile(`postgres://.*timescale`), description: "TimescaleDB URLs"},
	"arangodb-urls":        {regex: regexp.MustCompile(`https?://[^\s"'<>]+:8529`), description: "ArangoDB URLs"},
	"db-backup-strings":    {regex: regexp.MustCompile(`(?i)(?:mysqldump|pg_dump|mongodump).{0,100}--password[= ]['"]?[^\s'"]+`), description: "DB backup commands with passwords"},
	"sql-creds-in-queries": {regex: regexp.MustCompile(`(?i)(?:USER|PASSWORD)['\"]?\s*[:=]\s*['\"]([^'"\s]{4,})['\"]`), description: "SQL connection credentials"},

	// SaaS & third-party APIs
	"algolia-key":             {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyAlgolia, description: "Algolia API keys"},
	"segment-write-key":       {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelySegment, description: "Segment write keys"},
	"mixpanel-token":          {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyMixpanel, description: "Mixpanel tokens"},
	"amplitude-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyAmplitude, description: "Amplitude API keys"},
	"datadog-key":             {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyDatadog, description: "Datadog API keys"},
	"newrelic-key":            {regex: regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`), description: "New Relic keys"},
	"sentry-dsn":              {regex: regexp.MustCompile(`https://[a-f0-9]{32}@[^/]+\.ingest\.sentry\.io/\d+`), description: "Sentry DSN URLs"},
	"loggly-token":            {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Loggly tokens"},
	"bugsnag-key":             {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyBugsnag, description: "Bugsnag API keys"},
	"rollbar-token":           {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyRollbar, description: "Rollbar tokens"},
	"honeybadger-key":         {regex: regexp.MustCompile(`\b[a-f0-9]{6,8}\b`), validate: isLikelyHoneybadger, description: "Honeybadger API keys"},
	"pagerduty-key":           {regex: regexp.MustCompile(`\b[a-zA-Z0-9_-]{20}\b`), validate: isLikelyPagerDuty, description: "PagerDuty API keys"},
	"opsgenie-key":            {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Opsgenie API keys"},
	"cloudflare-key":          {regex: regexp.MustCompile(`\b[a-f0-9]{37}\b`), description: "Cloudflare API keys"},
	"cloudflare-token":        {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{40}\b`), validate: isLikelyCFToken, description: "Cloudflare API tokens"},
	"fastly-token":            {regex: regexp.MustCompile(`\b[a-zA-Z0-9_-]{32}\b`), validate: isLikelyFastly, description: "Fastly API tokens"},
	"akamai-creds":            {regex: regexp.MustCompile(`client_secret\s*=\s*[A-Za-z0-9+/=]{40,}`), description: "Akamai EdgeGrid credentials"},
	"auth0-secret":            {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{64}\b`), validate: isLikelyAuth0, description: "Auth0 client secrets"},
	"okta-token":              {regex: regexp.MustCompile(`\b00[A-Za-z0-9_-]{38,42}\b`), description: "Okta API tokens"},
	"auth0-domain":            {regex: regexp.MustCompile(`\b[a-zA-Z0-9-]+\.(?:auth0|eu\.auth0|au\.auth0)\.com\b`), description: "Auth0 tenant domains"},
	"okta-domain":             {regex: regexp.MustCompile(`\b[a-z0-9-]+\.okta\.com\b`), description: "Okta tenant domains"},
	"onelogin-secret":         {regex: regexp.MustCompile(`\b[a-f0-9]{64}\b`), validate: isLikelyOneLogin, description: "OneLogin client secrets"},
	"firebase-server-key":     {regex: regexp.MustCompile(`\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b`), description: "Firebase server keys"},
	"pusher-key":              {regex: regexp.MustCompile(`\b[a-f0-9]{20}\b`), validate: isLikelyPusher, description: "Pusher app keys"},
	"pusher-secret":           {regex: regexp.MustCompile(`\b[a-f0-9]{20}\b`), validate: isLikelyPusher, description: "Pusher secrets"},
	"intercom-token":          {regex: regexp.MustCompile(`\bdG9rOjc[A-Za-z0-9_-]{40,}\b`), description: "Intercom access tokens"},
	"zendesk-token":           {regex: regexp.MustCompile(`\b[a-zA-Z0-9]{40}\b`), validate: isLikelyZendesk, description: "Zendesk API tokens"},
	"freshdesk-key":           {regex: regexp.MustCompile(`\b[A-Za-z0-9]{20}\b`), validate: isLikelyFreshdesk, description: "Freshdesk API keys"},
	"hubspot-key":             {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "HubSpot API keys"},
	"salesforce-token":        {regex: regexp.MustCompile(`\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{100,}\b`), description: "Salesforce session tokens"},
	"mapbox-token":            {regex: regexp.MustCompile(`\bpk\.[a-zA-Z0-9]{60,}\b`), description: "Mapbox access tokens"},
	"google-maps-key":         {regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), description: "Google Maps API keys"},
	"here-api-key":            {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{20,60}\b`), validate: isLikelyHereAPI, description: "HERE Maps API keys"},
	"bing-maps-key":           {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{64}\b`), validate: isLikelyBingMaps, description: "Bing Maps keys"},
	"opencage-key":            {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyOpenCage, description: "OpenCage API keys"},
	"ipinfo-token":            {regex: regexp.MustCompile(`\b[a-f0-9]{14}\b`), description: "IPInfo tokens"},
	"ipstack-key":             {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyIPStack, description: "IPStack API keys"},
	"maxmind-key":             {regex: regexp.MustCompile(`\b[A-Za-z0-9]{16}\b`), validate: isLikelyMaxMind, description: "MaxMind license keys"},
	"shodan-key":              {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelyShodan, description: "Shodan API keys"},
	"censys-secret":           {regex: regexp.MustCompile(`\b[a-zA-Z0-9]{32}\b`), validate: isLikelyCensys, description: "Censys API secrets"},
	"virustotal-key":          {regex: regexp.MustCompile(`\b[a-f0-9]{64}\b`), validate: isLikelyVirusTotal, description: "VirusTotal API keys"},
	"abuseipdb-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{80}\b`), description: "AbuseIPDB API keys"},
	"securitytrails-key":      {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{32}\b`), validate: isLikelySecTrails, description: "SecurityTrails API keys"},
	"hunter-io-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{40}\b`), validate: isLikelyHunterIO, description: "Hunter.io API keys"},
	"clearbit-key":            {regex: regexp.MustCompile(`\bsk_[a-f0-9]{32}\b`), description: "Clearbit API keys"},
	"fullcontact-key":         {regex: regexp.MustCompile(`\b[a-f0-9]{20}\b`), validate: isLikelyFullContact, description: "FullContact API keys"},
	"dropbox-token":           {regex: regexp.MustCompile(`\bsl\.[A-Za-z0-9_-]{60,140}\b`), description: "Dropbox access tokens"},
	"box-token":               {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32,64}\b`), validate: isLikelyBox, description: "Box.com access tokens"},
	"onedrive-token":          {regex: regexp.MustCompile(`\bEw[A-Za-z0-9+/=]{100,}\b`), description: "OneDrive access tokens"},
	"asana-token":             {regex: regexp.MustCompile(`\b0/[a-f0-9]{32}\b`), description: "Asana personal tokens"},
	"trello-key":              {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyTrello, description: "Trello API keys"},
	"jira-token":              {regex: regexp.MustCompile(`\b[A-Za-z0-9]{24}\b`), validate: isLikelyJira, description: "Jira API tokens"},
	"confluence-token":        {regex: regexp.MustCompile(`\b[A-Za-z0-9]{24}\b`), validate: isLikelyConfluence, description: "Confluence tokens"},
	"notion-token":            {regex: regexp.MustCompile(`\bsecret_[A-Za-z0-9]{43}\b`), description: "Notion integration tokens"},
	"airtable-key":            {regex: regexp.MustCompile(`\bkey[A-Za-z0-9]{14}\b`), description: "Airtable API keys"},
	"monday-token":            {regex: regexp.MustCompile(`\b[a-f0-9]{64}\b`), validate: isLikelyMonday, description: "Monday.com tokens"},
	"linear-key":              {regex: regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`), description: "Linear API keys"},
	"clickup-token":           {regex: regexp.MustCompile(`\bpk_[0-9]+_[A-Z0-9]{32}\b`), description: "ClickUp API tokens"},
	"figma-token":             {regex: regexp.MustCompile(`\bfigd_[A-Za-z0-9_-]{43}\b`), description: "Figma personal tokens"},
	"adobe-client-secret":     {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Adobe API client secrets"},
	"canva-token":             {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`), validate: isLikelyCanva, description: "Canva access tokens"},
	"unsplash-key":            {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`), validate: isLikelyUnsplash, description: "Unsplash access keys"},
	"giphy-key":               {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelyGiphy, description: "Giphy API keys"},
	"youtube-api-key":         {regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), description: "YouTube Data API keys"},
	"vimeo-token":             {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyVimeo, description: "Vimeo access tokens"},
	"spotify-client-secret":   {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelySpotify, description: "Spotify client secrets"},
	"soundcloud-token":        {regex: regexp.MustCompile(`\b[A-Za-z0-9-_]{32}\b`), validate: isLikelySoundcloud, description: "SoundCloud tokens"},
	"twitter-bearer":          {regex: regexp.MustCompile(`\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,}\b`), description: "Twitter Bearer tokens"},
	"twitter-api-key":         {regex: regexp.MustCompile(`\b[A-Za-z0-9]{25}\b`), validate: isLikelyTwitterAPI, description: "Twitter API keys"},
	"twitter-api-secret":      {regex: regexp.MustCompile(`\b[A-Za-z0-9]{50}\b`), validate: isLikelyTwitterSecret, description: "Twitter API secrets"},
	"facebook-token":          {regex: regexp.MustCompile(`\bEA[A-Za-z0-9]{90,}\b`), description: "Facebook access tokens"},
	"facebook-app-secret":     {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyFBSecret, description: "Facebook app secrets"},
	"instagram-token":         {regex: regexp.MustCompile(`\bIGQV[A-Za-z0-9_-]{100,}\b`), description: "Instagram access tokens"},
	"linkedin-token":          {regex: regexp.MustCompile(`\bAQ[A-Za-z0-9_-]{60,}\b`), description: "LinkedIn access tokens"},
	"pinterest-token":         {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{64}\b`), validate: isLikelyPinterest, description: "Pinterest access tokens"},
	"reddit-client-secret":    {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{27}\b`), validate: isLikelyReddit, description: "Reddit client secrets"},
	"snapchat-token":          {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{100,}\b`), validate: isLikelySnapchat, description: "Snapchat tokens"},
	"tiktok-token":            {regex: regexp.MustCompile(`\bact\.[A-Za-z0-9_-]{100,}\b`), description: "TikTok access tokens"},
	"mastodon-token":          {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`), validate: isLikelyMastodon, description: "Mastodon access tokens"},
	"bluesky-token":           {regex: regexp.MustCompile(`\b[A-Za-z0-9._-]{43,}\b`), validate: isLikelyBluesky, description: "Bluesky app passwords"},
	"threads-token":           {regex: regexp.MustCompile(`\bIGQV[A-Za-z0-9_-]{100,}\b`), description: "Threads API tokens"},
	"npm-package-token":       {regex: regexp.MustCompile(`\b//registry\.npmjs\.org/:_authToken=[A-Za-z0-9-_]{36,}\b`), description: "npm auth in .npmrc"},
	"docker-config-auth":      {regex: regexp.MustCompile(`"auth":\s*"[A-Za-z0-9+/=]{20,}"`), description: "Docker config.json auth"},
	"kubernetes-secrets":      {regex: regexp.MustCompile(`kind:\s*Secret[\s\S]{0,500}data:`), description: "Kubernetes Secret manifests"},
	"helm-repo-password":      {regex: regexp.MustCompile(`password:\s*[^\s]{6,}`), validate: isLikelyHelmPassword, description: "Helm repository passwords"},
	"ansible-become-pass":     {regex: regexp.MustCompile(`ansible_become_pass(?:word)?:\s*[^\s]{6,}`), description: "Ansible become passwords"},
	"ssh-private-keys":        {regex: regexp.MustCompile(`-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----`), description: "SSH private key headers"},
	"pgp-private-keys":        {regex: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), description: "PGP private key blocks"},
	"x509-private-keys":       {regex: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), description: "PKCS#8 private keys"},
	"pkcs12-files":            {regex: regexp.MustCompile(`\b[\w.-]+\.p12\b`), description: "PKCS#12 certificate files"},
	"ssl-certificate-keys":    {regex: regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`), description: "SSL private keys"},
	"java-keystore":           {regex: regexp.MustCompile(`\b[\w.-]+\.jks\b`), description: "Java KeyStore files"},
	"android-keystore":        {regex: regexp.MustCompile(`\b[\w.-]+\.keystore\b`), description: "Android keystore files"},
	"aws-credentials-file":    {regex: regexp.MustCompile(`\[(?:default|[a-z0-9_-]+)\]\naws_access_key_id`), description: "AWS credentials file format"},
	"gcp-credentials-json":    {regex: regexp.MustCompile(`"type":\s*"service_account"[^}]{0,500}"private_key"`), description: "GCP service account JSON"},
	"azure-publish-profile":   {regex: regexp.MustCompile(`<publishData>[\s\S]{0,1000}userPWD="[^"]{10,}"`), description: "Azure publish profiles"},
	"ovh-credentials":         {regex: regexp.MustCompile(`\bovh-[a-z]+-[A-Za-z0-9]{32}\b`), description: "OVH API credentials"},
	"linode-token":            {regex: regexp.MustCompile(`\b[a-f0-9]{64}\b`), validate: isLikelyLinode, description: "Linode API tokens"},
	"vultr-api-key":           {regex: regexp.MustCompile(`\b[A-Z0-9]{36}\b`), validate: isLikelyVultr, description: "Vultr API keys"},
	"hetzner-token":           {regex: regexp.MustCompile(`\b[A-Za-z0-9]{64}\b`), validate: isLikelyHetzner, description: "Hetzner Cloud tokens"},
	"scaleway-secret":         {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Scaleway secret keys"},
	"cloudways-key":           {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelyCloudways, description: "Cloudways API keys"},
	"wpengine-creds":          {regex: regexp.MustCompile(`(?i)sftp://[^@]+@[^.]+\.wpengine\.com`), description: "WP Engine SFTP credentials"},
	"wordpress-salt-keys":     {regex: regexp.MustCompile(`define\(\s*'[A-Z_]+',\s*'[^']{64}'\s*\)`), description: "WordPress salt/key defines"},
	"drupal-hash-salt":        {regex: regexp.MustCompile(`\$settings\['hash_salt'\]\s*=\s*'[^']{43,}'`), description: "Drupal hash salt"},
	"laravel-app-key":         {regex: regexp.MustCompile(`APP_KEY=base64:[A-Za-z0-9+/=]{44}`), description: "Laravel app keys"},
	"django-secret-key":       {regex: regexp.MustCompile(`SECRET_KEY\s*=\s*['\"][^'\"]{40,}['\"]`), description: "Django secret keys"},
	"rails-secret-key-base":   {regex: regexp.MustCompile(`secret_key_base:\s*[a-f0-9]{128}`), description: "Rails secret_key_base"},
	"flask-secret-key":        {regex: regexp.MustCompile(`SECRET_KEY\s*=\s*['\"][^'\"]{16,}['\"]`), description: "Flask secret keys"},
	"express-session-secret":  {regex: regexp.MustCompile(`secret:\s*['\"][^'\"]{16,}['\"]`), description: "Express session secrets"},
	"jwt-secrets":             {regex: regexp.MustCompile(`(?i)jwt[_-]?secret['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]`), description: "JWT signing secrets"},
	"oauth-client-secrets":    {regex: regexp.MustCompile(`(?i)client[_-]?secret['\"]?\s*[:=]\s*['\"]([^'\"]{20,})['\"]`), description: "OAuth client secrets"},
	"recaptcha-secret":        {regex: regexp.MustCompile(`\b6L[a-zA-Z0-9_-]{38}\b`), description: "reCAPTCHA secret keys"},
	"hcaptcha-secret":         {regex: regexp.MustCompile(`\b0x[A-Fa-f0-9]{40}\b`), description: "hCaptcha secret keys"},
	"turnstile-secret":        {regex: regexp.MustCompile(`\b0x[A-Fa-f0-9]{40}\b`), description: "Cloudflare Turnstile secrets"},
	"grafana-api-key":         {regex: regexp.MustCompile(`\beyJrIjoi[A-Za-z0-9+/=]{40,}\b`), description: "Grafana API keys"},
	"prometheus-bearer":       {regex: regexp.MustCompile(`Bearer\s+[A-Za-z0-9_-]{20,}`), description: "Prometheus bearer tokens"},
	"elastic-cloud-id":        {regex: regexp.MustCompile(`\b[a-z0-9-]+:[A-Za-z0-9+/=]{100,}\b`), description: "Elastic Cloud IDs"},
	"kibana-encryption-key":   {regex: regexp.MustCompile(`xpack\.encryptedSavedObjects\.encryptionKey:\s*[a-zA-Z0-9]{32}`), description: "Kibana encryption keys"},
	"splunk-token":            {regex: regexp.MustCompile(`\bSplunk\s+[A-Za-z0-9\-]{36}\b`), description: "Splunk HEC tokens"},
	"sumologic-key":           {regex: regexp.MustCompile(`\bsu[A-Za-z0-9]{20}\b`), description: "Sumo Logic access keys"},
	"papertrail-token":        {regex: regexp.MustCompile(`\b[a-zA-Z0-9]{20}\b`), validate: isLikelyPapertrail, description: "Papertrail API tokens"},
	"logdna-key":              {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyLogDNA, description: "LogDNA ingestion keys"},
	"coralogix-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Coralogix private keys"},
	"browserstack-key":        {regex: regexp.MustCompile(`\b[a-zA-Z0-9]{20}\b`), validate: isLikelyBrowserStack, description: "BrowserStack access keys"},
	"saucelabs-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Sauce Labs access keys"},
	"lambdatest-key":          {regex: regexp.MustCompile(`\b[A-Za-z0-9]{20,60}\b`), validate: isLikelyLambdaTest, description: "LambdaTest access keys"},
	"postman-api-key":         {regex: regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`), description: "Postman API keys"},
	"insomnia-api-key":        {regex: regexp.MustCompile(`\bspc_[a-f0-9]{32}\b`), description: "Insomnia API keys"},
	"apiary-token":            {regex: regexp.MustCompile(`\b[a-f0-9]{40}\b`), validate: isLikelyApiary, description: "Apiary API tokens"},
	"swagger-api-key":         {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{32}\b`), validate: isLikelySwagger, description: "SwaggerHub API keys"},
	"readme-token":            {regex: regexp.MustCompile(`\brdme_[a-z0-9]{40}\b`), description: "ReadMe.io API tokens"},
	"gitbook-token":           {regex: regexp.MustCompile(`\bgbs_[A-Za-z0-9]{40}\b`), description: "GitBook API tokens"},
	"ghost-admin-key":         {regex: regexp.MustCompile(`\b[a-f0-9]{26}:[a-f0-9]{64}\b`), description: "Ghost Admin API keys"},
	"contentful-token":        {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`), validate: isLikelyContentful, description: "Contentful access tokens"},
	"sanity-token":            {regex: regexp.MustCompile(`\bsk[A-Za-z0-9]{40}\b`), description: "Sanity.io API tokens"},
	"strapi-token":            {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyStrapi, description: "Strapi API tokens"},
	"prismic-token":           {regex: regexp.MustCompile(`\bMC[A-Za-z0-9._-]{100,}\b`), description: "Prismic access tokens"},
	"graphcms-token":          {regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{100,}`), description: "Hygraph (GraphCMS) tokens"},
	"amplify-app-id":          {regex: regexp.MustCompile(`\bd[a-z0-9]{24}\b`), validate: isLikelyAmplifyApp, description: "AWS Amplify app IDs"},
	"vercel-env-vars":         {regex: regexp.MustCompile(`\bVERCEL_[A-Z_]+=.+`), description: "Vercel environment variables"},
	"netlify-env-vars":        {regex: regexp.MustCompile(`\bNETLIFY_[A-Z_]+=.+`), description: "Netlify environment variables"},
	"railway-token":           {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Railway API tokens"},
	"render-api-key":          {regex: regexp.MustCompile(`\brnd_[A-Za-z0-9]{40}\b`), description: "Render.com API keys"},
	"cyclic-token":            {regex: regexp.MustCompile(`\bcyc_[A-Za-z0-9]{32}\b`), description: "Cyclic.sh tokens"},
	"fly-io-token":            {regex: regexp.MustCompile(`\bfo1_[A-Za-z0-9]{43}\b`), description: "Fly.io access tokens"},
	"deta-project-key":        {regex: regexp.MustCompile(`\b[a-z0-9]{12}_[A-Za-z0-9]{32}\b`), description: "Deta project keys"},
	"supabase-anon-key":       {regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{43}`), description: "Supabase anon keys (JWT)"},
	"supabase-service-key":    {regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{200,}\.[A-Za-z0-9_-]{43}`), description: "Supabase service keys"},
	"planetscale-password":    {regex: regexp.MustCompile(`\bpscale_pw_[A-Za-z0-9]{40}\b`), description: "PlanetScale passwords"},
	"neon-api-key":            {regex: regexp.MustCompile(`\b[a-z0-9]{32}\b`), validate: isLikelyNeon, description: "Neon database API keys"},
	"cockroach-sql-user":      {regex: regexp.MustCompile(`postgres://[^:]+:[^@]{20,}@[^.]+\.cockroachlabs\.cloud`), description: "CockroachDB Cloud URLs"},
	"mongodb-atlas-key":       {regex: regexp.MustCompile(`\b[a-z]{8}-[a-z]{4}-[a-z]{4}-[a-z]{16}\b`), description: "MongoDB Atlas API keys"},
	"redis-cloud-key":         {regex: regexp.MustCompile(`\b[A-Za-z0-9]{40}\b`), validate: isLikelyRedisCloud, description: "Redis Cloud API keys"},
	"upstash-redis-url":       {regex: regexp.MustCompile(`https://[a-z0-9-]+\.upstash\.io`), description: "Upstash Redis URLs"},
	"fauna-secret":            {regex: regexp.MustCompile(`\bfn[AEO][A-Za-z0-9_-]{60,}\b`), description: "Fauna database secrets"},
	"hasura-admin-secret":     {regex: regexp.MustCompile(`\b[a-zA-Z0-9]{32,}\b`), validate: isLikelyHasura, description: "Hasura admin secrets"},
	"dgraph-token":            {regex: regexp.MustCompile(`\b[A-Za-z0-9]{20,}\b`), validate: isLikelyDgraph, description: "Dgraph Cloud tokens"},
	"convex-deploy-key":       {regex: regexp.MustCompile(`\bprod:[a-z0-9]{8}\|[a-z0-9]{64}`), description: "Convex deploy keys"},
	"xata-api-key":            {regex: regexp.MustCompile(`\bxau_[A-Za-z0-9]{32,}\b`), description: "Xata.io API keys"},
	"turso-token":             {regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{43}`), description: "Turso database tokens"},
	"cloudinary-key":          {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{15}:[A-Za-z0-9_-]{27}\b`), description: "Cloudinary API secrets"},
	"imgix-token":             {regex: regexp.MustCompile(`\b[a-f0-9]{40}\b`), validate: isLikelyImgix, description: "imgix API tokens"},
	"uploadcare-secret":       {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyUploadcare, description: "Uploadcare secrets"},
	"imagekit-private-key":    {regex: regexp.MustCompile(`\bprivate_[A-Za-z0-9+/=]{40,}\b`), description: "ImageKit private keys"},
	"resend-api-key":          {regex: regexp.MustCompile(`\bre_[A-Za-z0-9]{32}\b`), description: "Resend API keys"},
	"loops-api-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyLoops, description: "Loops.so API keys"},
	"customer-io-key":         {regex: regexp.MustCompile(`\b[a-f0-9]{24}\b`), validate: isLikelyCustomerIO, description: "Customer.io site IDs"},
	"vwo-account-id":          {regex: regexp.MustCompile(`\b\d{6}\b`), validate: isLikelyVWO, description: "VWO account IDs"},
	"optimizely-key":          {regex: regexp.MustCompile(`\b[A-Za-z0-9]{20,}\b`), validate: isLikelyOptimizely, description: "Optimizely SDK keys"},
	"launchdarkly-sdk-key":    {regex: regexp.MustCompile(`\bsdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), description: "LaunchDarkly SDK keys"},
	"split-io-key":            {regex: regexp.MustCompile(`\b[a-z0-9]{20,40}\b`), validate: isLikelySplitIO, description: "Split.io API keys"},
	"flagsmith-key":           {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelyFlagsmith, description: "Flagsmith environment keys"},
	"posthog-key":             {regex: regexp.MustCompile(`\bphc_[A-Za-z0-9]{43}\b`), description: "PostHog project API keys"},
	"june-write-key":          {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyJune, description: "June.so write keys"},
	"heap-app-id":             {regex: regexp.MustCompile(`\b\d{10,12}\b`), validate: isLikelyHeap, description: "Heap Analytics app IDs"},
	"hotjar-id":               {regex: regexp.MustCompile(`\bhjid:\s*\d{6,8}`), description: "Hotjar site IDs"},
	"fullstory-org-id":        {regex: regexp.MustCompile(`\b[A-Z0-9]{5,7}\b`), validate: isLikelyFullStory, description: "FullStory org IDs"},
	"logrocket-app-id":        {regex: regexp.MustCompile(`\b[a-z0-9-]+/[a-z0-9-]+\b`), validate: isLikelyLogRocket, description: "LogRocket app IDs"},
	"smartlook-key":           {regex: regexp.MustCompile(`\b[a-f0-9]{40}\b`), validate: isLikelySmartlook, description: "Smartlook project keys"},
	"mouseflow-id":            {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Mouseflow website IDs"},
	"crazy-egg-id":            {regex: regexp.MustCompile(`\b[0-9]{8}\b`), validate: isLikelyCrazyEgg, description: "Crazy Egg account numbers"},
	"google-analytics-id":     {regex: regexp.MustCompile(`\bUA-\d{6,10}-\d{1,4}\b`), description: "Google Analytics UA IDs"},
	"google-analytics-4":      {regex: regexp.MustCompile(`\bG-[A-Z0-9]{10}\b`), description: "Google Analytics 4 IDs"},
	"google-tag-manager":      {regex: regexp.MustCompile(`\bGTM-[A-Z0-9]{7,8}\b`), description: "Google Tag Manager IDs"},
	"facebook-pixel-id":       {regex: regexp.MustCompile(`\b\d{15,16}\b`), validate: isLikelyFBPixel, description: "Facebook Pixel IDs"},
	"linkedin-partner-id":     {regex: regexp.MustCompile(`\b\d{6,8}\b`), validate: isLikelyLinkedInPartner, description: "LinkedIn Partner IDs"},
	"twitter-pixel-id":        {regex: regexp.MustCompile(`\bo[a-z0-9]{4,6}\b`), description: "Twitter Pixel IDs"},
	"tiktok-pixel-id":         {regex: regexp.MustCompile(`\b[A-Z0-9]{20}\b`), validate: isLikelyTikTokPixel, description: "TikTok Pixel IDs"},
	"snapchat-pixel-id":       {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Snapchat Pixel IDs"},
	"pinterest-tag-id":        {regex: regexp.MustCompile(`\b\d{13}\b`), validate: isLikelyPinterestTag, description: "Pinterest Tag IDs"},
	"reddit-pixel-id":         {regex: regexp.MustCompile(`\bt2_[a-z0-9]{6,8}\b`), description: "Reddit Pixel IDs"},
	"quora-pixel-id":          {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyQuoraPixel, description: "Quora Pixel IDs"},
	"bing-ads-id":             {regex: regexp.MustCompile(`\b\d{7,9}\b`), validate: isLikelyBingAds, description: "Bing Ads IDs"},
	"google-ads-conversion":   {regex: regexp.MustCompile(`\bAW-\d{9,11}\b`), description: "Google Ads conversion IDs"},
	"cve-ids":                 {regex: cveRegex, validate: isValidCVE, description: "CVE identifiers"},
	"cwe-ids":                 {regex: regexp.MustCompile(`\bCWE-\d{1,5}\b`), description: "CWE (weakness) IDs"},
	"capec-ids":               {regex: regexp.MustCompile(`\bCAPEC-\d{1,5}\b`), description: "CAPEC attack pattern IDs"},
	"mitre-attack-ids":        {regex: regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`), description: "MITRE ATT&CK technique IDs"},
	"owasp-references":        {regex: regexp.MustCompile(`\bOWASP[- ](?:Top[- ]10[- ])?\d{4}[-:]A\d{1,2}\b`), description: "OWASP Top 10 references"},
	"nist-controls":           {regex: regexp.MustCompile(`\b[A-Z]{2}-\d{1,2}(?:\(\d+\))?(?:\s*\([a-z]\))?\b`), validate: isLikelyNIST, description: "NIST SP 800-53 controls"},
	"iso27001-controls":       {regex: regexp.MustCompile(`\bA\.\d{1,2}\.\d{1,2}\.\d{1,2}\b`), description: "ISO 27001 control refs"},
	"pci-dss-requirements":    {regex: regexp.MustCompile(`\b(?:PCI[- ]DSS[- ])?\d{1,2}\.\d{1,2}(?:\.\d{1,2})?\b`), validate: isLikelyPCIDSS, description: "PCI DSS requirement refs"},
	"xss-payloads":            {regex: regexp.MustCompile(`<script[^>]*>[^<]*(?:alert|prompt|confirm)\([^)]*\)`), description: "Potential XSS payloads"},
	"sqli-patterns":           {regex: regexp.MustCompile(`(?i)(?:'|\bOR\b|\bAND\b)\s*[1-9=]|UNION\s+SELECT|;--`), description: "SQL injection patterns"},
	"path-traversal":          {regex: regexp.MustCompile(`(?:\.\.\/|\.\.\\){2,}`), description: "Path traversal sequences"},
	"xxe-payloads":            {regex: regexp.MustCompile(`<!ENTITY[^>]+SYSTEM[^>]+>`), description: "XXE injection patterns"},
	"ssrf-localhost":          {regex: regexp.MustCompile(`(?i)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|0x7f000001)`), description: "SSRF localhost targets"},
	"rce-commands":            {regex: regexp.MustCompile(`(?i)(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(`), description: "Remote code execution functions"},
	"deserialization-gadgets": {regex: regexp.MustCompile(`(?i)(?:__wakeup|__destruct|readObject|ObjectInputStream)`), description: "Deserialization gadget indicators"},
	"jwt-none-alg":            {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+alg["\s:]*none`), description: "JWT with 'none' algorithm"},
	"open-redirect-params":    {regex: regexp.MustCompile(`(?i)[?&](?:url|redirect|next|return|callback|goto|dest|redir)=https?://`), description: "Open redirect parameters"},
	"idor-params":             {regex: regexp.MustCompile(`(?i)[?&](?:id|user|account|doc|file|key)=\d+`), description: "IDOR candidate parameters"},
	"debug-enabled":           {regex: regexp.MustCompile(`(?i)debug['\"]?\s*[:=]\s*(?:true|1|yes)`), description: "Debug mode enabled"},
	"test-credentials":        {regex: regexp.MustCompile(`(?i)(?:test|demo|admin):(?:test|demo|password|admin|123)`), description: "Common test credentials"},
	"weak-passwords":          {regex: regexp.MustCompile(`(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?(?:password|123456|admin|test|root)['\"]?`), description: "Hardcoded weak passwords"},
	"todo-fixme-comments":     {regex: regexp.MustCompile(`(?i)\b(?:TODO|FIXME|HACK|XXX|BUG|VULNERABLE|INSECURE):?[^\n]{0,100}`), description: "Security-relevant code comments"},
	"hardcoded-ips":           {regex: ipv4Regex, validate: isIPv4, description: "Hardcoded IP addresses"},
	"suspicious-base64":       {regex: base64Regex, validate: isSuspiciousBase64, description: "Base64 with suspicious decoded content"},
	"cors-any-origin":         {regex: regexp.MustCompile(`Access-Control-Allow-Origin:\s*\*`), description: "CORS wildcard origin"},
	"csrf-disabled":           {regex: regexp.MustCompile(`(?i)csrf['\"]?\s*[:=]\s*(?:false|0|disabled|off)`), description: "CSRF protection disabled"},
	"security-headers":        {regex: regexp.MustCompile(`(?i)(?:X-Frame-Options|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security):`), description: "Security header references"},
	"robots-disallow":         {regex: regexp.MustCompile(`Disallow:\s*/[^\n]*`), description: "robots.txt disallow directives"},
	"sitemap-urls":            {regex: regexp.MustCompile(`<loc>(https?://[^<]+)</loc>`), description: "URLs from sitemap.xml"},
	"wsdl-endpoints":              {regex: regexp.MustCompile(`https?://[^\s"']+\.wsdl`), description: "WSDL SOAP endpoints"},
	"wadl-endpoints":              {regex: regexp.MustCompile(`https?://[^\s"']+\.wadl`), description: "WADL REST endpoints"},
	"swagger-json":                {regex: regexp.MustCompile(`https?://[^\s"']+/(?:swagger|openapi)\.json`), description: "Swagger/OpenAPI specs"},
	"cloud-function-urls":         {regex: regexp.MustCompile(`https://[a-z0-9-]+\.(?:cloudfunctions\.net|azurewebsites\.net|lambda-url\..*\.on\.aws)`), description: "Serverless function URLs"},
	"php-info-paths":              {regex: regexp.MustCompile(`(?i)/phpinfo\.php`), description: "phpinfo.php paths"},
	"git-config-exposed":          {regex: regexp.MustCompile(`(?i)\.git/config`), description: ".git/config paths"},
	"svn-entries":                 {regex: regexp.MustCompile(`(?i)\.svn/entries`), description: ".svn/entries paths"},
	"ds-store-files":              {regex: regexp.MustCompile(`(?i)\.DS_Store`), description: ".DS_Store files"},
	"htaccess-files":              {regex: regexp.MustCompile(`(?i)\.htaccess`), description: ".htaccess files"},
	"htpasswd-files":              {regex: regexp.MustCompile(`(?i)\.htpasswd`), description: ".htpasswd files"},
	"web-config-xml":              {regex: regexp.MustCompile(`(?i)web\.config`), description: "web.config files"},
	"applicationhost-config":      {regex: regexp.MustCompile(`(?i)applicationhost\.config`), description: "IIS applicationhost.config"},
	"nginx-conf":                  {regex: regexp.MustCompile(`(?i)nginx\.conf`), description: "nginx.conf files"},
	"apache-conf":                 {regex: regexp.MustCompile(`(?i)(?:httpd|apache2?)\.conf`), description: "Apache config files"},
	"tomcat-users-xml":            {regex: regexp.MustCompile(`(?i)tomcat-users\.xml`), description: "Tomcat users XML"},
	"jboss-config":                {regex: regexp.MustCompile(`(?i)jboss-web\.xml`), description: "JBoss config files"},
	"weblogic-config":             {regex: regexp.MustCompile(`(?i)config\.xml`), description: "WebLogic config files"},
	"websphere-config":            {regex: regexp.MustCompile(`(?i)server\.xml`), description: "WebSphere config"},
	"iis-metabase":                {regex: regexp.MustCompile(`(?i)metabase\.xml`), description: "IIS metabase.xml"},
	"maven-settings":              {regex: regexp.MustCompile(`(?i)settings\.xml`), description: "Maven settings.xml"},
	"gradle-properties":           {regex: regexp.MustCompile(`(?i)gradle\.properties`), description: "Gradle properties"},
	"composer-json":               {regex: regexp.MustCompile(`(?i)composer\.json`), description: "composer.json files"},
	"package-json":                {regex: regexp.MustCompile(`(?i)package\.json`), description: "package.json files"},
	"yarn-lock":                   {regex: regexp.MustCompile(`(?i)yarn\.lock`), description: "yarn.lock files"},
	"gemfile":                     {regex: regexp.MustCompile(`(?i)Gemfile`), description: "Ruby Gemfile"},
	"pipfile":                     {regex: regexp.MustCompile(`(?i)Pipfile`), description: "Python Pipfile"},
	"requirements-txt":            {regex: regexp.MustCompile(`(?i)requirements\.txt`), description: "requirements.txt"},
	"cargo-toml":                  {regex: regexp.MustCompile(`(?i)Cargo\.toml`), description: "Cargo.toml files"},
	"go-mod":                      {regex: regexp.MustCompile(`(?i)go\.mod`), description: "go.mod files"},
	"dockerfile":                  {regex: regexp.MustCompile(`(?i)Dockerfile`), description: "Dockerfile names"},
	"docker-compose-yaml":         {regex: regexp.MustCompile(`(?i)docker-compose\.ya?ml`), description: "docker-compose files"},
	"kubernetes-manifests":        {regex: regexp.MustCompile(`(?i)\.ya?ml$`), validate: isLikelyK8sManifest, description: "Kubernetes YAML manifests"},
	"terraform-files":             {regex: regexp.MustCompile(`(?i)\.tf$`), description: "Terraform files"},
	"cloudformation-templates":    {regex: regexp.MustCompile(`(?i)cloudformation.*\.(?:json|ya?ml)`), description: "CloudFormation templates"},
	"arm-templates":               {regex: regexp.MustCompile(`(?i)azuredeploy\.json`), description: "Azure ARM templates"},
	"procfile":                    {regex: regexp.MustCompile(`(?i)^Procfile$`), description: "Heroku Procfile"},
	"makefile":                    {regex: regexp.MustCompile(`(?i)^Makefile$`), description: "Makefile"},
	"jenkinsfile":                 {regex: regexp.MustCompile(`(?i)^Jenkinsfile$`), description: "Jenkinsfile"},
	"gitlab-ci-yaml":              {regex: regexp.MustCompile(`(?i)\.gitlab-ci\.ya?ml`), description: ".gitlab-ci.yml"},
	"circleci-config":             {regex: regexp.MustCompile(`(?i)\.circleci/config\.ya?ml`), description: "CircleCI config"},
	"travis-ci-yaml":              {regex: regexp.MustCompile(`(?i)\.travis\.ya?ml`), description: ".travis.yml"},
	"appveyor-yaml":               {regex: regexp.MustCompile(`(?i)appveyor\.ya?ml`), description: "appveyor.yml"},
	"azure-pipelines-yaml":        {regex: regexp.MustCompile(`(?i)azure-pipelines\.ya?ml`), description: "azure-pipelines.yml"},
	"github-workflows":            {regex: regexp.MustCompile(`(?i)\.github/workflows/.*\.ya?ml`), description: "GitHub Actions workflows"},
	"bitbucket-pipelines":         {regex: regexp.MustCompile(`(?i)bitbucket-pipelines\.ya?ml`), description: "bitbucket-pipelines.yml"},
	"sonar-properties":            {regex: regexp.MustCompile(`(?i)sonar-project\.properties`), description: "SonarQube properties"},
	"eslintrc":                    {regex: regexp.MustCompile(`(?i)\.eslintrc(?:\.(?:js|json|ya?ml))?`), description: "ESLint config"},
	"prettierrc":                  {regex: regexp.MustCompile(`(?i)\.prettierrc(?:\.(?:js|json|ya?ml))?`), description: "Prettier config"},
	"editorconfig":                {regex: regexp.MustCompile(`(?i)\.editorconfig`), description: ".editorconfig files"},
	"gitignore":                   {regex: regexp.MustCompile(`(?i)\.gitignore`), description: ".gitignore files"},
	"dockerignore":                {regex: regexp.MustCompile(`(?i)\.dockerignore`), description: ".dockerignore files"},
	"npmignore":                   {regex: regexp.MustCompile(`(?i)\.npmignore`), description: ".npmignore files"},
	"python-bytecode":             {regex: regexp.MustCompile(`(?i)\.pyc$`), description: "Python bytecode files"},
	"java-class-files":            {regex: regexp.MustCompile(`(?i)\.class$`), description: "Java .class files"},
	"war-files":                   {regex: regexp.MustCompile(`(?i)\.war$`), description: "WAR archive files"},
	"jar-files":                   {regex: regexp.MustCompile(`(?i)\.jar$`), description: "JAR archive files"},
	"ear-files":                   {regex: regexp.MustCompile(`(?i)\.ear$`), description: "EAR archive files"},
	"zip-archives":                {regex: regexp.MustCompile(`(?i)\.zip$`), description: "ZIP archives"},
	"tar-archives":                {regex: regexp.MustCompile(`(?i)\.tar(?:\.(?:gz|bz2|xz))?$`), description: "TAR archives"},
	"rar-archives":                {regex: regexp.MustCompile(`(?i)\.rar$`), description: "RAR archives"},
	"seven-zip-archives":          {regex: regexp.MustCompile(`(?i)\.7z$`), description: "7-Zip archives"},
	"iso-images":                  {regex: regexp.MustCompile(`(?i)\.iso$`), description: "ISO disk images"},
	"burp-collab-interactions":    {regex: regexp.MustCompile(`https?://[a-z0-9]+\.(?:oastify|burpcollaborator)\.(?:com|net)`), description: "Burp Collaborator URLs"},
	"interactsh-urls":             {regex: regexp.MustCompile(`https?://[a-z0-9]+\.interact\.sh`), description: "Interactsh callback URLs"},
	"ngrok-urls":                  {regex: regexp.MustCompile(`https?://[a-z0-9-]+\.ngrok\.io`), description: "ngrok tunnel URLs"},
	"localtunnel-urls":            {regex: regexp.MustCompile(`https?://[a-z0-9-]+\.loca\.lt`), description: "localtunnel URLs"},
	"serveo-urls":                 {regex: regexp.MustCompile(`https?://[a-z0-9-]+\.serveo\.net`), description: "Serveo tunnel URLs"},
	"requestbin-urls":             {regex: regexp.MustCompile(`https?://[a-z0-9]+\.x\.pipedream\.net`), description: "RequestBin/Pipedream URLs"},
}

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

	// Support multiple modes: lazygrep emails urls domains
	modes := os.Args[1:]
	var extractors []extractor
	needTLD := false

	for _, mode := range modes {
		ext, ok := modeExtractors[mode]
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
			printUsage()
			os.Exit(1)
		}
		extractors = append(extractors, ext)
		if ext.requiresTLD {
			needTLD = true
		}
	}

	if needTLD {
		if err := setupTLDs(); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting up TLDs: %v\n", err)
			os.Exit(1)
		}
	}

	results := make(chan string, 2000)
	done := make(chan bool)
	go collector(results, done)

	stat, _ := os.Stdin.Stat()
	isPiped := (stat.Mode() & os.ModeCharDevice) == 0

	if isPiped {
		scanStreamMulti(os.Stdin, extractors, results)
		close(results)
		<-done
		return
	}

	fileJobs := make(chan string, 2000)
	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go workerMulti(extractors, fileJobs, results, &wg)
	}

	go func() {
		err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if _, shouldSkip := skipDirs[d.Name()]; shouldSkip {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				fileJobs <- path
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error walking path: %v\n", err)
		}
		close(fileJobs)
	}()

	wg.Wait()
	close(results)
	<-done
}

func scanStream(r io.Reader, ext extractor, results chan<- string) {
	scanner := bufio.NewScanner(r)
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

func scanStreamMulti(r io.Reader, extractors []extractor, results chan<- string) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		for _, ext := range extractors {
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
}

func worker(ext extractor, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range jobs {
		processFile(path, ext, results)
	}
}

func workerMulti(extractors []extractor, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range jobs {
		processFileMulti(path, extractors, results)
	}
}

func processFile(path string, ext extractor, results chan<- string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	bufHead := make([]byte, 512)
	n, _ := file.Read(bufHead)
	for i := 0; i < n; i++ {
		if bufHead[i] == 0 {
			return
		}
	}

	file.Seek(0, 0)
	scanStream(file, ext, results)
}

func processFileMulti(path string, extractors []extractor, results chan<- string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	bufHead := make([]byte, 512)
	n, _ := file.Read(bufHead)
	for i := 0; i < n; i++ {
		if bufHead[i] == 0 {
			return
		}
	}

	file.Seek(0, 0)
	scanStreamMulti(file, extractors, results)
}

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
	tld := strings.ToUpper(parts[len(parts)-1])
	if _, ok := validTLDs[tld]; !ok {
		return false
	}
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
		fmt.Fprintf(os.Stderr, "  - %-30s %s\n", name, ext.description)
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
	for _, p := range parts[:2] {
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

func isUUID(s string) bool {
	_, err := strconv.ParseUint(strings.ReplaceAll(s, "-", ""), 16, 128)
	return err == nil && len(s) == 36
}

// Heuristic validators for context-specific patterns
func isLikelyAWSSecret(s string) bool       { return len(s) == 40 && isAlphaNumPlus(s) }
func isLikelyAWSAccount(s string) bool      { return len(s) == 12 }
func isLikelyGCPProject(s string) bool      { return len(s) >= 6 && len(s) <= 30 && strings.Contains(s, "-") }
func isLikelyBQTable(s string) bool         { return strings.Count(s, ".") == 2 }
func isLikelyPayPal(s string) bool          { return len(s) >= 60 && len(s) <= 80 && strings.HasPrefix(s, "A") }
func isLikelySolana(s string) bool          { return len(s) >= 32 && len(s) <= 44 }
func isLikelySeedPhrase(s string) bool      { return strings.Count(s, " ") >= 11 && strings.Count(s, " ") <= 23 }
func isLikelySlackSigning(s string) bool    { return len(s) == 32 }
func isLikelyTwilioAuth(s string) bool      { return len(s) == 32 }
func isLikelyZoomJWT(s string) bool         { return len(s) >= 200 }
func isLikelyZoomWebhook(s string) bool     { return len(s) == 64 }
func isLikelyJenkinsToken(s string) bool    { return len(s) >= 32 && len(s) <= 34 }
func isLikelyCircleCI(s string) bool        { return len(s) == 40 }
func isLikelyTravisCI(s string) bool        { return len(s) == 22 }
func isLikelyNetlify(s string) bool         { return len(s) == 43 }
func isLikelyVercel(s string) bool          { return len(s) == 24 }
func isLikelyDOToken(s string) bool         { return len(s) == 64 }
func isLikelyDroneCI(s string) bool         { return len(s) == 32 }
func isLikelyBuildkite(s string) bool       { return len(s) == 40 }
func isLikelyBitbucket(s string) bool       { return len(s) == 32 }
func isLikelyCargoToken(s string) bool      { return len(s) == 22 }
func isLikelyKafka(s string) bool           { return strings.Contains(s, ":") }
func isLikelyAlgolia(s string) bool         { return len(s) == 32 }
func isLikelySegment(s string) bool         { return len(s) == 32 }
func isLikelyMixpanel(s string) bool        { return len(s) == 32 }
func isLikelyAmplitude(s string) bool       { return len(s) == 32 }
func isLikelyDatadog(s string) bool         { return len(s) == 32 }
func isLikelyBugsnag(s string) bool         { return len(s) == 32 }
func isLikelyRollbar(s string) bool         { return len(s) == 32 }
func isLikelyHoneybadger(s string) bool     { return len(s) >= 6 && len(s) <= 8 }
func isLikelyPagerDuty(s string) bool       { return len(s) == 20 }
func isLikelyCFToken(s string) bool         { return len(s) == 40 }
func isLikelyFastly(s string) bool          { return len(s) == 32 }
func isLikelyAuth0(s string) bool           { return len(s) == 64 }
func isLikelyOneLogin(s string) bool        { return len(s) == 64 }
func isLikelyPusher(s string) bool          { return len(s) == 20 }
func isLikelyZendesk(s string) bool         { return len(s) == 40 }
func isLikelyFreshdesk(s string) bool       { return len(s) == 20 }
func isLikelyHereAPI(s string) bool         { return len(s) >= 20 && len(s) <= 60 }
func isLikelyBingMaps(s string) bool        { return len(s) == 64 }
func isLikelyOpenCage(s string) bool        { return len(s) == 32 }
func isLikelyIPStack(s string) bool         { return len(s) == 32 }
func isLikelyMaxMind(s string) bool         { return len(s) == 16 }
func isLikelyShodan(s string) bool          { return len(s) == 32 }
func isLikelyCensys(s string) bool          { return len(s) == 32 }
func isLikelyVirusTotal(s string) bool      { return len(s) == 64 }
func isLikelySecTrails(s string) bool       { return len(s) == 32 }
func isLikelyHunterIO(s string) bool        { return len(s) == 40 }
func isLikelyFullContact(s string) bool     { return len(s) == 20 }
func isLikelyBox(s string) bool             { return len(s) >= 32 && len(s) <= 64 }
func isLikelyTrello(s string) bool          { return len(s) == 32 }
func isLikelyJira(s string) bool            { return len(s) == 24 }
func isLikelyConfluence(s string) bool      { return len(s) == 24 }
func isLikelyMonday(s string) bool          { return len(s) == 64 }
func isLikelyCanva(s string) bool           { return len(s) == 43 }
func isLikelyUnsplash(s string) bool        { return len(s) == 43 }
func isLikelyGiphy(s string) bool           { return len(s) == 32 }
func isLikelyVimeo(s string) bool           { return len(s) == 32 }
func isLikelySpotify(s string) bool         { return len(s) == 32 }
func isLikelySoundcloud(s string) bool      { return len(s) == 32 }
func isLikelyTwitterAPI(s string) bool      { return len(s) == 25 }
func isLikelyTwitterSecret(s string) bool   { return len(s) == 50 }
func isLikelyFBSecret(s string) bool        { return len(s) == 32 }
func isLikelyPinterest(s string) bool       { return len(s) == 64 }
func isLikelyReddit(s string) bool          { return len(s) == 27 }
func isLikelySnapchat(s string) bool        { return len(s) >= 100 }
func isLikelyMastodon(s string) bool        { return len(s) == 43 }
func isLikelyBluesky(s string) bool         { return len(s) >= 43 }
func isLikelyHelmPassword(s string) bool    { return len(s) >= 6 }
func isLikelyNeon(s string) bool            { return len(s) == 32 }
func isLikelyRedisCloud(s string) bool      { return len(s) == 40 }
func isLikelyHasura(s string) bool          { return len(s) >= 32 }
func isLikelyDgraph(s string) bool          { return len(s) >= 20 }
func isLikelyImgix(s string) bool           { return len(s) == 40 }
func isLikelyUploadcare(s string) bool      { return len(s) == 32 }
func isLikelyLoops(s string) bool           { return len(s) == 32 }
func isLikelyCustomerIO(s string) bool      { return len(s) == 24 }
func isLikelyVWO(s string) bool             { return len(s) == 6 }
func isLikelyOptimizely(s string) bool      { return len(s) >= 20 }
func isLikelySplitIO(s string) bool         { return len(s) >= 20 && len(s) <= 40 }
func isLikelyFlagsmith(s string) bool       { return len(s) == 32 }
func isLikelyJune(s string) bool            { return len(s) == 32 }
func isLikelyHeap(s string) bool            { return len(s) >= 10 && len(s) <= 12 }
func isLikelyFullStory(s string) bool       { return len(s) >= 5 && len(s) <= 7 }
func isLikelyLogRocket(s string) bool       { return strings.Contains(s, "/") }
func isLikelySmartlook(s string) bool       { return len(s) == 40 }
func isLikelyCrazyEgg(s string) bool        { return len(s) == 8 }
func isLikelyFBPixel(s string) bool         { return len(s) >= 15 && len(s) <= 16 }
func isLikelyLinkedInPartner(s string) bool { return len(s) >= 6 && len(s) <= 8 }
func isLikelyTikTokPixel(s string) bool     { return len(s) == 20 }
func isLikelyPinterestTag(s string) bool    { return len(s) == 13 }
func isLikelyQuoraPixel(s string) bool      { return len(s) == 32 }
func isLikelyBingAds(s string) bool         { return len(s) >= 7 && len(s) <= 9 }
func isLikelyNIST(s string) bool            { return len(s) >= 4 && len(s) <= 10 }
func isLikelyPCIDSS(s string) bool          { return strings.Count(s, ".") >= 1 }
func isLikelyLinode(s string) bool          { return len(s) == 64 }
func isLikelyVultr(s string) bool           { return len(s) == 36 }
func isLikelyHetzner(s string) bool         { return len(s) == 64 }
func isLikelyCloudways(s string) bool       { return len(s) == 32 }
func isLikelyContentful(s string) bool      { return len(s) == 43 }
func isLikelyStrapi(s string) bool          { return len(s) == 32 }
func isLikelyAmplifyApp(s string) bool      { return len(s) == 25 }
func isLikelyBrowserStack(s string) bool    { return len(s) == 20 }
func isLikelyLambdaTest(s string) bool      { return len(s) >= 20 && len(s) <= 60 }
func isLikelyApiary(s string) bool          { return len(s) == 40 }
func isLikelySwagger(s string) bool         { return len(s) == 32 }
func isLikelyPapertrail(s string) bool      { return len(s) == 20 }
func isLikelyLogDNA(s string) bool          { return len(s) == 32 }

func isSuspiciousBase64(s string) bool {
	if len(s) < 40 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(decoded))
	return strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "key")
}

func isAlphaNumPlus(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

func isLikelyK8sManifest(s string) bool {
	return strings.Contains(s, "apiVersion") || strings.Contains(s, "kind:")
}
