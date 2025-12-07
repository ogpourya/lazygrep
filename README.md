# lazygrep

Extract patterns from files in any directory 🔍

## Installation

```bash
GOPROXY=direct go install github.com/ogpourya/lazygrep@latest
````

## Usage

Simply run the tool in any directory. It recursively scans files, ignoring junk like `.git` and `node_modules`.

```bash
# Extract and validate domains
lazygrep domains

# Extract and validate URLs
lazygrep urls
```

## Features

  * **Ultra Fast**: Concurrent worker pool pattern for high-speed processing.
  * **Strict Validation**: Validates domains against the official [IANA TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) and RFC standards.
  * **Smart Filtering**: Automatically ignores binary files and heavy directories (`node_modules`, `vendor`, etc.).
  * **Clean Output**: Results are trimmed, deduplicated, and ready for piping.
