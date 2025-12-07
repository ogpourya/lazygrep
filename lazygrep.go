package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	domainRegex = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	urlRegex    = regexp.MustCompile(`https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
)

// Global TLD map
var validTLDs = make(map[string]struct{})

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	if mode != "domains" && mode != "urls" {
		printUsage()
		os.Exit(1)
	}

	// 1. Setup Environment
	if err := setupTLDs(); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up TLDs: %v\n", err)
		os.Exit(1)
	}

	// 2. Channels
	fileJobs := make(chan string, 2000) // Buffer file paths
	results := make(chan string, 2000)
	var wg sync.WaitGroup

	// 3. Start Workers (File Processors)
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go worker(mode, fileJobs, results, &wg)
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
func worker(mode string, jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Reuse buffer for scanner to reduce GC pressure
	// But since we open many files, we allocate inside loop or use a sync.Pool if strictly necessary.
	// For simplicity and safety, we allocate per file here.

	for path := range jobs {
		processFile(path, mode, results)
	}
}

func processFile(path string, mode string, results chan<- string) {
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
		if mode == "domains" {
			// FindAllString is fast enough for per-line
			matches := domainRegex.FindAllString(line, -1)
			for _, m := range matches {
				m = strings.ToLower(strings.TrimSpace(m))
				if isValidDomain(m) {
					results <- m
				}
			}
		} else {
			matches := urlRegex.FindAllString(line, -1)
			for _, m := range matches {
				m = strings.TrimSpace(m)
				if isValidURL(m) {
					results <- m
				}
			}
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
	fmt.Fprintf(os.Stderr, "Usage: ezgrep <mode>\n")
	fmt.Fprintf(os.Stderr, "Modes: domains, urls\n")
}
