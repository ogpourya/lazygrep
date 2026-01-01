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
	ipv4PortRegex   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	cveRegex        = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
)

type extractor struct {
	regex       *regexp.Regexp
	requiresTLD bool
	normalize   func(string) string
	validate    func(string) bool
	description string
}

var modeExtractors = map[string]extractor{
	// Core network patterns
	"domains":        {regex: domainRegex, requiresTLD: true, normalize: lowerTrim, validate: isValidDomain, description: "Domain names with valid TLDs"},
	"urls":           {regex: urlRegex, requiresTLD: true, normalize: strings.TrimSpace, validate: isValidURL, description: "HTTP/HTTPS URLs"},
	"emails":         {regex: emailRegex, requiresTLD: true, normalize: lowerTrim, validate: isValidEmail, description: "Email addresses"},
	"ipv4":           {regex: ipv4Regex, validate: isIPv4, description: "IPv4 addresses"},
	"ipv6":           {regex: ipv6Regex, validate: isIPv6, description: "IPv6 addresses"},
	"ips":            {regex: ipRegex, validate: isIP, description: "IPv4 or IPv6 addresses"},
	"private-ips":    {regex: ipv4Regex, validate: isIPv4Private, description: "RFC1918 private IPs"},
	"public-ips":     {regex: ipv4Regex, validate: isIPv4Public, description: "Public routable IPv4"},
	"ipv4-with-port": {regex: ipv4PortRegex, validate: isValidIPv4Port, description: "IPv4:port pairs"},
	"ipv4-cidrs":     {regex: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`), validate: isValidCIDR, description: "IPv4 CIDR notation"},

	// Hashes & crypto
	"md5":              {regex: md5Regex, description: "MD5 hashes"},
	"sha1":             {regex: sha1Regex, description: "SHA-1 hashes"},
	"sha256":           {regex: sha256Regex, description: "SHA-256 hashes"},
	"bcrypt":           {regex: bcryptRegex, description: "bcrypt hashes"},
	"jwt":              {regex: jwtRegex, validate: isJWT, description: "JWT tokens"},
	"base64":           {regex: base64Regex, validate: isValidBase64, description: "Base64 strings (20+ chars)"},
	"uuids":            {regex: uuidRegex, description: "UUIDs"},
	"bearer-tokens":    {regex: regexp.MustCompile(`\bBearer\s+[A-Za-z0-9_\-\.]{20,}`), description: "Bearer token headers"},

	// Connection strings
	"connection-strings":  {regex: regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|jdbc|sqlserver)://[^\s"'<>]+`), description: "Database connection strings"},
	"embedded-passwords":  {regex: regexp.MustCompile(`(?i)://[^:]+:[^@]{4,}@[^\s"'<>]+`), description: "URLs with embedded passwords"},
	"cloud-metadata-urls": {regex: regexp.MustCompile(`http://169\.254\.169\.254/[^\s"']*`), description: "Cloud metadata service URLs"},

	// AWS
	"aws-keys":          {regex: awsKeyRegex, description: "AWS access keys (AKIA/ASIA)"},
	"aws-secret-keys":   {regex: regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`), validate: isLikelyAWSSecret, description: "AWS secret access keys"},
	"s3-buckets":        {regex: regexp.MustCompile(`\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b`), description: "S3 bucket domains"},
	"s3-urls":           {regex: regexp.MustCompile(`s3://[a-z0-9.-]+(?:/[^\s"'<>]*)?`), description: "S3 protocol URLs"},
	"lambda-urls":       {regex: regexp.MustCompile(`https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws`), description: "AWS Lambda function URLs"},
	"apigateway-urls":   {regex: regexp.MustCompile(`https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com`), description: "API Gateway URLs"},
	"rds-endpoints":     {regex: regexp.MustCompile(`\b[a-z0-9.-]+\.rds\.amazonaws\.com\b`), description: "RDS database endpoints"},

	// GCP
	"gcp-api-keys":         {regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), description: "GCP API keys"},
	"gcp-service-accounts": {regex: regexp.MustCompile(`\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b`), description: "GCP service accounts"},
	"gcs-buckets":          {regex: regexp.MustCompile(`gs://[a-z0-9._-]+`), description: "Google Cloud Storage buckets"},
	"firebase-urls":        {regex: regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), description: "Firebase Realtime DB URLs"},

	// Azure
	"azure-storage-keys":  {regex: regexp.MustCompile(`\b[A-Za-z0-9+/]{88}==\b`), description: "Azure storage account keys"},
	"azure-connection":    {regex: regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`), description: "Azure storage connections"},
	"azure-blob-urls":     {regex: regexp.MustCompile(`https://[\w-]+\.blob\.core\.windows\.net`), description: "Azure Blob Storage URLs"},
	"azure-keyvault-urls": {regex: regexp.MustCompile(`https://[a-z0-9-]+\.vault\.azure\.net`), description: "Key Vault URLs"},

	// GitHub & GitLab
	"github-pat":   {regex: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,255}\b`), description: "GitHub personal tokens"},
	"github-oauth": {regex: regexp.MustCompile(`\bgho_[A-Za-z0-9]{36,255}\b`), description: "GitHub OAuth tokens"},
	"github-repos": {regex: regexp.MustCompile(`github\.com[/:]([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)`), description: "GitHub repo references"},
	"gitlab-pat":   {regex: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`), description: "GitLab PATs"},

	// Slack
	"slack-webhook":    {regex: slackHookRegex, description: "Slack webhook URLs"},
	"slack-bot-token":  {regex: regexp.MustCompile(`\bxoxb-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,32}\b`), description: "Slack bot tokens"},
	"slack-user-token": {regex: regexp.MustCompile(`\bxoxp-\d{10,13}-\d{10,13}-\d{10,13}-[A-Za-z0-9]{32}\b`), description: "Slack user tokens"},

	// Payment APIs
	"stripe-live-secret": {regex: regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,99}\b`), description: "Stripe live secret keys"},
	"stripe-test-secret": {regex: regexp.MustCompile(`\bsk_test_[0-9a-zA-Z]{24,99}\b`), description: "Stripe test secret keys"},
	"credit-cards":       {regex: cardRegex, normalize: stripSpacesAndHyphens, validate: isValidCard, description: "Credit card numbers (Luhn)"},
	"bitcoin-addresses":  {regex: regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`), description: "Bitcoin addresses"},
	"ethereum-addresses": {regex: regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`), description: "Ethereum addresses"},

	// Communication APIs
	"twilio-sid":      {regex: regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`), description: "Twilio account SIDs"},
	"sendgrid-keys":   {regex: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), description: "SendGrid API keys"},
	"mailgun-keys":    {regex: regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`), description: "Mailgun API keys"},
	"telegram-bot":    {regex: regexp.MustCompile(`\b\d{9,10}:AA[A-Za-z0-9_-]{33}\b`), description: "Telegram bot tokens"},
	"discord-bot":     {regex: regexp.MustCompile(`\b[NM][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b`), description: "Discord bot tokens"},
	"discord-webhook": {regex: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`), description: "Discord webhook URLs"},

	// CI/CD
	"docker-hub-token": {regex: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{32,}\b`), description: "Docker Hub access tokens"},
	"heroku-api-key":   {regex: regexp.MustCompile(`\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), validate: isUUID, description: "Heroku API keys"},
	"terraform-cloud":  {regex: regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b`), description: "Terraform Cloud tokens"},

	// Package managers
	"npm-token":   {regex: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), description: "npm access tokens"},
	"pypi-token":  {regex: regexp.MustCompile(`\bpypi-AgEI[0-9A-Za-z_-]{50,}\b`), description: "PyPI upload tokens"},
	"nuget-key":   {regex: regexp.MustCompile(`\bNU-[A-Za-z0-9]{48}\b`), description: "NuGet API keys"},

	// Database URLs
	"postgres-urls":  {regex: regexp.MustCompile(`postgres(?:ql)?://[^\s"'<>]+`), description: "PostgreSQL URLs"},
	"mysql-urls":     {regex: regexp.MustCompile(`mysql://[^\s"'<>]+`), description: "MySQL URLs"},
	"mongodb-urls":   {regex: regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"'<>]+`), description: "MongoDB URLs"},
	"redis-urls":     {regex: regexp.MustCompile(`redis(?:s)?://[^\s"'<>]+`), description: "Redis URLs"},

	// SaaS APIs
	"datadog-key":   {regex: regexp.MustCompile(`\b[a-f0-9]{32}\b`), validate: isLikelyDatadog, description: "Datadog API keys"},
	"newrelic-key":  {regex: regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`), description: "New Relic keys"},
	"sentry-dsn":    {regex: regexp.MustCompile(`https://[a-f0-9]{32}@[^/]+\.ingest\.sentry\.io/\d+`), description: "Sentry DSN URLs"},
	"cloudflare-key": {regex: regexp.MustCompile(`\b[a-f0-9]{37}\b`), description: "Cloudflare API keys"},
	"auth0-secret":  {regex: regexp.MustCompile(`\b[A-Za-z0-9_-]{64}\b`), validate: isLikelyAuth0, description: "Auth0 client secrets"},
	"okta-token":    {regex: regexp.MustCompile(`\b00[A-Za-z0-9_-]{38,42}\b`), description: "Okta API tokens"},
	"mapbox-token":  {regex: regexp.MustCompile(`\bpk\.[a-zA-Z0-9]{60,}\b`), description: "Mapbox access tokens"},
	"shodan-key":    {regex: regexp.MustCompile(`\b[A-Za-z0-9]{32}\b`), validate: isLikelyShodan, description: "Shodan API keys"},

	// Productivity tools
	"notion-token":  {regex: regexp.MustCompile(`\bsecret_[A-Za-z0-9]{43}\b`), description: "Notion integration tokens"},
	"figma-token":   {regex: regexp.MustCompile(`\bfigd_[A-Za-z0-9_-]{43}\b`), description: "Figma personal tokens"},
	"airtable-key":  {regex: regexp.MustCompile(`\bkey[A-Za-z0-9]{14}\b`), description: "Airtable API keys"},

	// Framework secrets (specific patterns only)
	"laravel-app-key":  {regex: regexp.MustCompile(`APP_KEY=base64:[A-Za-z0-9+/=]{44}`), description: "Laravel app keys"},
	"rails-secret-key": {regex: regexp.MustCompile(`secret_key_base:\s*[a-f0-9]{128}`), description: "Rails secret_key_base"},

	// Private keys
	"ssh-private-keys": {regex: regexp.MustCompile(`-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----`), description: "SSH private key headers"},
	"pgp-private-keys": {regex: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), description: "PGP private key blocks"},

	// Security identifiers
	"cve-ids":  {regex: cveRegex, validate: isValidCVE, description: "CVE identifiers"},
}

var validTLDs = make(map[string]struct{})
var (
	privateIPv4Nets  = mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
	loopbackIPv4Net  = mustCIDR("127.0.0.0/8")
	linkLocalIPv4Net = mustCIDR("169.254.0.0/16")
	multicastIPv4Net = mustCIDR("224.0.0.0/4")
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

func workerMulti(extractors []extractor, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range jobs {
		processFileMulti(path, extractors, results)
	}
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

func isUUID(s string) bool {
	_, err := strconv.ParseUint(strings.ReplaceAll(s, "-", ""), 16, 128)
	return err == nil && len(s) == 36
}

// Heuristic validators
func isLikelyAWSSecret(s string) bool { return len(s) == 40 && isAlphaNumPlus(s) }
func isLikelyDatadog(s string) bool   { return len(s) == 32 }
func isLikelyAuth0(s string) bool     { return len(s) == 64 }
func isLikelyShodan(s string) bool    { return len(s) == 32 }

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
