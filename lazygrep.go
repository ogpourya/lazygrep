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

const (
	ianaURL      = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	workerCount  = 30
	configFolder = ".config/lazygrep"
	legacyConfig = ".config/ezgrep"
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

var (
	domainRegex    = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	urlRegex       = regexp.MustCompile(`https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
	emailRegex     = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	ipv4Regex      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:){1,7}:|(?i)::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}\b|(?i)::1\b|(?i)\b::\b`)
	ipRegex        = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}\b|::1\b|\b::\b`)
	uuidRegex      = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b`)
	sha256Regex    = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	sha1Regex      = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	md5Regex       = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	jwtRegex       = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	cardRegex      = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	awsKeyRegex    = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	slackHookRegex = regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`)
	bcryptRegex    = regexp.MustCompile(`\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}`)
	base64Regex    = regexp.MustCompile(`\b(?:[A-Za-z0-9+/]{20,}={0,2})\b`)
	ipv4PortRegex  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	cveRegex       = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
)

type extractor struct {
	regex       *regexp.Regexp
	requiresTLD bool
	normalize   func(string) string
	validate    func(string) bool
	description string
}

var modeExtractors = map[string]extractor{
	"domains":        {regex: domainRegex, requiresTLD: true, normalize: lowerTrim, validate: isValidDomain, description: "Domain names with valid TLDs"},
	"urls":           {regex: urlRegex, requiresTLD: true, normalize: normalizeURL, validate: isValidURL, description: "HTTP/HTTPS URLs"},
	"emails":         {regex: emailRegex, requiresTLD: true, normalize: lowerTrim, validate: isValidEmail, description: "Email addresses"},
	"ipv4":           {regex: ipv4Regex, validate: isIPv4, description: "IPv4 addresses"},
	"ipv6":           {regex: ipv6Regex, validate: isIPv6, description: "IPv6 addresses"},
	"ips":            {regex: ipRegex, validate: isIP, description: "IPv4 or IPv6 addresses"},
	"private-ips":    {regex: ipv4Regex, validate: isIPv4Private, description: "RFC1918 private IPs"},
	"public-ips":     {regex: ipv4Regex, validate: isIPv4Public, description: "Public routable IPv4"},
	"ipv4-with-port": {regex: ipv4PortRegex, validate: isValidIPv4Port, description: "IPv4:port pairs"},
	"ipv4-cidrs":     {regex: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`), validate: isValidCIDR, description: "IPv4 CIDR notation"},

	"md5":           {regex: md5Regex, description: "MD5 hashes"},
	"sha1":          {regex: sha1Regex, description: "SHA-1 hashes"},
	"sha256":        {regex: sha256Regex, description: "SHA-256 hashes"},
	"bcrypt":        {regex: bcryptRegex, description: "bcrypt hashes"},
	"jwt":           {regex: jwtRegex, validate: isJWT, description: "JWT tokens"},
	"base64":        {regex: base64Regex, validate: isValidBase64, description: "Base64 strings (20+ chars)"},
	"uuids":         {regex: uuidRegex, validate: isUUID, description: "UUIDs"},
	"bearer-tokens": {regex: regexp.MustCompile(`\bBearer\s+[A-Za-z0-9_\-\.]{20,}`), description: "Bearer token headers"},

	"connection-strings":  {regex: regexp.MustCompile(`(?i)(?:mongodb|mysql|postgres|jdbc|sqlserver)://[^\s"'<>]+`), description: "Database connection strings"},
	"embedded-passwords":  {regex: regexp.MustCompile(`(?i)://[^/:@\s]+:[^/@\s]{4,}@[^\s"'<>]+`), description: "URLs with embedded passwords"},
	"cloud-metadata-urls": {regex: regexp.MustCompile(`http://169\.254\.169\.254/[^\s"']*`), description: "Cloud metadata service URLs"},

	"aws-keys":        {regex: awsKeyRegex, description: "AWS access keys (AKIA/ASIA)"},
	"aws-secret-keys": {regex: regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`), validate: isLikelyAWSSecret, description: "AWS secret access keys"},

	"gcp-api-keys": {regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), description: "GCP API keys"},

	"azure-storage-keys": {regex: regexp.MustCompile(`\b[A-Za-z0-9+/]{88}==\b`), description: "Azure storage account keys"},

	"github-pat":   {regex: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,255}\b`), description: "GitHub personal tokens"},
	"github-oauth": {regex: regexp.MustCompile(`\bgho_[A-Za-z0-9]{36,255}\b`), description: "GitHub OAuth tokens"},
	"github-repos": {regex: regexp.MustCompile(`github\.com[/:]([A-Za-z0-9_-]+/[A-Za-z0-9_.-]+)`), normalize: normalizeRepoRef, description: "GitHub repo references"},
	"gitlab-pat":   {regex: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`), description: "GitLab PATs"},

	"slack-webhook":    {regex: slackHookRegex, description: "Slack webhook URLs"},
	"slack-bot-token":  {regex: regexp.MustCompile(`\bxoxb-\d{9,13}-\d{9,13}-[A-Za-z0-9]{24,34}\b`), description: "Slack bot tokens"},
	"slack-user-token": {regex: regexp.MustCompile(`\bxoxp-\d{9,13}-\d{9,13}-\d{9,13}-[A-Za-z0-9]{24,34}\b`), description: "Slack user tokens"},

	"credit-cards": {regex: cardRegex, normalize: stripSpacesAndHyphens, validate: isValidCard, description: "Credit card numbers (Luhn)"},

	"twilio-sid":      {regex: regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`), description: "Twilio account SIDs"},
	"sendgrid-keys":   {regex: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), description: "SendGrid API keys"},
	"mailgun-keys":    {regex: regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`), description: "Mailgun API keys"},
	"telegram-bot":    {regex: regexp.MustCompile(`\b\d{9,10}:AA[A-Za-z0-9_-]{33}\b`), description: "Telegram bot tokens"},
	"discord-bot":     {regex: regexp.MustCompile(`\b[NM][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b`), description: "Discord bot tokens"},
	"discord-webhook": {regex: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`), description: "Discord webhook URLs"},

	"postgres-urls": {regex: regexp.MustCompile(`postgres(?:ql)?://[^\s"'<>]+`), description: "PostgreSQL URLs"},
	"mysql-urls":    {regex: regexp.MustCompile(`mysql://[^\s"'<>]+`), description: "MySQL URLs"},
	"mongodb-urls":  {regex: regexp.MustCompile(`mongodb(?:\+srv)?://[^\s"'<>]+`), description: "MongoDB URLs"},
	"redis-urls":    {regex: regexp.MustCompile(`redis(?:s)?://[^\s"'<>]+`), description: "Redis URLs"},

	"ssh-private-keys": {regex: regexp.MustCompile(`-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----`), description: "SSH private key headers"},
	"pgp-private-keys": {regex: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), description: "PGP private key blocks"},

	"cve-ids": {regex: cveRegex, validate: isValidCVE, description: "CVE identifiers"},
}

var validTLDs = make(map[string]struct{})
var (
	privateIPv4Nets  = mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
	loopbackIPv4Net  = mustCIDR("127.0.0.0/8")
	linkLocalIPv4Net = mustCIDR("169.254.0.0/16")
	multicastIPv4Net = mustCIDR("224.0.0.0/4")
	reservedIPv4Net  = mustCIDR("240.0.0.0/4")
	thisNetIPv4Net   = mustCIDR("0.0.0.0/8")
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

	stat, err := os.Stdin.Stat()
	isPiped := err == nil && (stat.Mode()&os.ModeCharDevice) == 0

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
	reader := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
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
		if err != nil {
			break
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
	host := u.Hostname()
	return isValidDomain(host) || isIP(host)
}

func setupTLDs() error {
	home, err := os.UserHomeDir()
	if err != nil {
		loadFallbackTLDs()
		return nil
	}
	configPath := filepath.Join(home, configFolder)
	filePath := filepath.Join(configPath, tldFile)

	legacyPath := filepath.Join(home, legacyConfig, tldFile)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if _, errLegacy := os.Stat(legacyPath); errLegacy == nil {
			filePath = legacyPath
		}
	}

	if info, err := os.Stat(filePath); os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		_ = os.MkdirAll(configPath, 0755)
		targetFile := filepath.Join(configPath, tldFile)
		if err := downloadFile(targetFile, ianaURL); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to download IANA TLDs (%v), using fallback TLDs\n", err)
			loadFallbackTLDs()
			return nil
		}
		filePath = targetFile
	}

	file, err := os.Open(filePath)
	if err != nil {
		loadFallbackTLDs()
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		validTLDs[strings.ToUpper(line)] = struct{}{}
	}
	if len(validTLDs) == 0 {
		loadFallbackTLDs()
	}
	return scanner.Err()
}

func loadFallbackTLDs() {
	fallbacks := []string{
		"COM", "ORG", "NET", "EDU", "GOV", "MIL", "INT", "IO", "CO", "DEV",
		"AI", "APP", "INFO", "BIZ", "ME", "US", "UK", "CA", "DE", "JP",
		"FR", "AU", "RU", "CH", "IT", "NL", "SE", "NO", "ES", "CC",
		"TV", "XYZ", "ONLINE", "SITE", "TECH", "STORE", "SPACE", "WEBSITE",
		"TOP", "CLUB", "PRO", "MOBI", "ASIA", "VIP", "LIVE", "WORLD",
		"TODAY", "CLOUD", "AGENCY", "DIGITAL", "EMAIL", "NETWORK", "SOLUTIONS",
		"SYSTEMS", "GLOBAL", "ZONE", "GROUP", "MEDIA", "SERVICES", "SECURITY",
		"TOOLS", "TEAM", "STUDIO", "WORKS", "DESIGN", "LINK", "CLICK",
		"NEWS", "BLOG", "SHOP", "LIFE", "ONE", "FUN", "WIN", "ICU",
		"CN", "IN", "BR", "KR", "PL", "CZ", "FI", "DK", "BE", "AT",
		"GR", "PT", "RO", "UA", "TR", "ZA", "MX", "SG", "NZ", "HK",
		"IE", "IL",
	}
	for _, t := range fallbacks {
		validTLDs[t] = struct{}{}
	}
}

func downloadFile(filepath string, rawURL string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	tmpFile := filepath + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, resp.Body)
	closeErr := out.Close()
	if err != nil {
		os.Remove(tmpFile)
		return err
	}
	if closeErr != nil {
		os.Remove(tmpFile)
		return closeErr
	}

	return os.Rename(tmpFile, filepath)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: lazygrep <mode> [mode...]\n")
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

func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimRight(s, ".,;:)\"'>]")
}

func normalizeRepoRef(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimRight(s, ".,;:)\"'>]")
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
	return parsed != nil && parsed.To4() != nil
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil && strings.Contains(ip, ":")
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
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(header) < 2 || header[0] != '{' || header[len(header)-1] != '}' {
		return false
	}
	if !strings.Contains(string(header), `"alg"`) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) < 2 || payload[0] != '{' || payload[len(payload)-1] != '}' {
		return false
	}
	return true
}

func isValidCard(num string) bool {
	if len(num) < 13 || len(num) > 19 || num[0] == '0' {
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
	return sum%10 == 0 && sum > 0
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
	trimmed := strings.TrimRight(s, "=")
	if len(trimmed) < 20 {
		return false
	}
	_, err := base64.RawStdEncoding.DecodeString(trimmed)
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
	if ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return false
	}
	if containsNet(ip, privateIPv4Nets) || loopbackIPv4Net.Contains(ip) || linkLocalIPv4Net.Contains(ip) || multicastIPv4Net.Contains(ip) || reservedIPv4Net.Contains(ip) || thisNetIPv4Net.Contains(ip) {
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
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 || len(s) != 36 {
		return false
	}
	_, err1 := strconv.ParseUint(clean[:16], 16, 64)
	_, err2 := strconv.ParseUint(clean[16:], 16, 64)
	return err1 == nil && err2 == nil
}

func isLikelyAWSSecret(s string) bool { return len(s) == 40 && isAlphaNumPlus(s) }

func isAlphaNumPlus(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}
