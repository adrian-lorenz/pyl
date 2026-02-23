# pyl

> **pyl** — fast secret scanner for your codebase


A lightweight, zero-config CLI tool written in Rust that scans source code for accidentally committed secrets, credentials, and sensitive data.

---

## Features

- **74 built-in detection rules** covering cloud providers, LLMs, databases, HTTP auth, and more
- **Multiple output formats** — pretty-printed, JSON, and SARIF
- **GitHub Actions integration** — writes a formatted Job Summary to `$GITHUB_STEP_SUMMARY`
- **Inline suppression** — annotate lines with `# pyl-ignore` to silence known false positives
- **Configurable** via `pyl.toml` — restrict file extensions, exclude paths, disable rules
- **Sorted output** — findings ordered by severity (CRITICAL → HIGH → MEDIUM → LOW → WARNING), then by file and line
- **Smart false-positive filtering** — skips template variables, shell variables, and attribute references
- **Binary-safe** — skips non-text files automatically
- **Respects `.env` files** — always excluded from scanning

---

## Installation

### From source

```bash
git clone https://github.com/YOUR_USERNAME/pyl.git
cd pyl
cargo install --path .
```

### Pre-built binaries

Download the latest binary for your platform from the [Releases](https://github.com/YOUR_USERNAME/pyl/releases/latest) page:

| Platform | File |
|----------|------|
| Linux x86_64 | `pyl-linux-amd64` |
| Linux ARM64 | `pyl-linux-arm64` |
| Windows x86_64 | `pyl-windows-amd64.exe` |
| macOS Apple Silicon | `pyl-macos-arm64` |

```bash
# Linux / macOS — make executable and move to PATH
chmod +x pyl-linux-amd64
sudo mv pyl-linux-amd64 /usr/local/bin/pyl
```

---

## Usage

```bash
# Scan the current directory
pyl check

# Scan a specific path
pyl check --source ./src

# JSON output (e.g. for piping)
pyl check --format json

# SARIF output (e.g. for GitHub Code Scanning)
pyl check --format sarif

# Verbose mode (shows every file scanned/skipped)
pyl check --verbose

# Include WARNING-level findings in detail output
pyl check --warnings

# Limit file size (default: 1024 KB)
pyl check --max-size 512

# Use a custom config file
pyl check --config /path/to/pyl.toml

# Write a GitHub Actions Job Summary
pyl check --github-summary

# List all built-in rules
pyl rules

# Generate a default config file
pyl init-config
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings (or only LOW/WARNING severity) |
| `1`  | At least one CRITICAL, HIGH, or MEDIUM finding |

---

## Warnings

WARNING-level findings (e.g. plain HTTP URLs) are counted in the summary but suppressed in the detail output by default to reduce noise. Use `--warnings` to display them:

```bash
pyl check --warnings
```

The summary line always shows the WARNING count regardless of this flag.

---

## Configuration

Run `pyl init-config` to create a `pyl.toml` in the current directory:

```toml
[scan]
# Leave empty to scan all files (except .env and .git).
# Restrict to specific extensions:
# extensions = ["py", "js", "ts", "go", "yaml", "toml"]
extensions = []
exclude_paths = []
exclude_files = []

[rules]
# Disable specific rules by ID:
# disable = ["jwt-token", "http-insecure-url"]
disable = []
```

`pyl.toml` is auto-loaded from the current directory if present.

---

## Suppression

Add a suppression comment to any line to skip it:

```python
api_url = "http://internal-service/api"  # pyl-ignore
```

Supported markers: `# pyl-ignore`, `# noqa-secrets`, `# nosec-secrets`

pyl also automatically skips common false positives:

| Pattern | Example |
|---------|---------|
| Python f-strings / Jinja | `postgresql://{DB_USER}:{DB_PASSWORD}@...` |
| Shell variables | `$DB_PASSWORD` |
| Python `%`-format | `%(password)s` |
| Attribute references | `settings.DB_PASSWORD`, `config.secret_key` |
| localhost HTTP URLs | `http://localhost:8080` |

---

## Detection Coverage

| Category | Examples |
|----------|---------|
| **Cloud / VCS** | AWS keys, GitHub/GitLab PATs, Google API keys, Stripe, Slack, NPM, Docker Hub |
| **LLM / AI** | OpenAI, Anthropic, Cohere, Mistral, Hugging Face, Replicate, Groq, Perplexity |
| **Azure / M365** | Tenant/Client IDs, Storage keys, Service Bus, Cosmos DB, Teams webhooks, Graph API |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, MSSQL, Elasticsearch, RabbitMQ, JDBC |
| **Observability** | Datadog, New Relic, Grafana, Honeycomb, Lightstep, OTLP endpoints |
| **HTTP Auth** | Basic Auth headers, Bearer tokens, credentials in URLs, curl commands |
| **Crypto** | PEM private keys (RSA, EC, DSA, OpenSSH) |
| **Generic** | High-entropy secrets matching common naming patterns, JWT tokens |

Run `pyl rules` to see all 74 rules with IDs, severity levels, and tags.

---

## Severity Levels

| Level | Description |
|-------|-------------|
| `CRITICAL` | Direct credential exposure — rotate immediately |
| `HIGH` | Sensitive token or key with significant access |
| `MEDIUM` | Potentially sensitive, context-dependent |
| `LOW` | Low-risk exposure (e.g. publishable keys) |
| `WARNING` | Best-practice violation (e.g. plain HTTP URLs) — shown with `--warnings` |

---

## GitHub Actions

Two ready-to-use workflows are included in `.github/workflows/`.

### Secret scan on every push — `scan.yml`

Runs `pyl check` on every push and pull request, uploads results to GitHub Code Scanning as SARIF.

> Replace `YOUR_USERNAME` in `scan.yml` with your GitHub username before pushing.

### Release workflow — `release.yml`

Triggered automatically when you push a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow:
1. **Builds** Linux amd64/arm64 and Windows amd64/arm64 in parallel on `ubuntu-latest` using [`cross`](https://github.com/cross-rs/cross)
2. **Builds** macOS arm64 natively on `macos-latest`
3. **Creates** a GitHub Release with all 5 binaries attached and an auto-generated changelog

The release body includes a download table and install instructions automatically.

---

## Project Structure

```
src/
├── main.rs       Entry point, CLI dispatch
├── cli.rs        CLI types (Cli, Commands, OutputFormat)
├── config.rs     Configuration loading (pyl.toml)
├── rules.rs      Built-in detection rules and Severity type
├── scanner.rs    File and directory scanning logic
└── output.rs     Output formatters (pretty, JSON, SARIF, GitHub Summary)
```

---

## License

MIT — Copyright (c) 2026 Adrian Lorenz &lt;a.lorenz@noa-x.de&gt;
