# DeepVioletTools Documentation

DeepVioletTools is a suite of TLS/SSL security scanning tools that provide both graphical and command-line interfaces for analyzing HTTPS servers. It serves as a reference implementation for the [DeepViolet API](https://github.com/spoofzu/DeepViolet/).

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [GUI Application (dvui)](#gui-application-dvui)
- [Command Line Tool (dvcli)](#command-line-tool-dvcli)
- [Report Sections](#report-sections)
- [Saving and Exporting Reports](#saving-and-exporting-reports)
- [JSON Report Schema Reference](#json-report-schema-reference)
- [Common Errors and Troubleshooting](#common-errors-and-troubleshooting)
- [API Integration](#api-integration)
- [Building from Source](#building-from-source)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Overview

DeepVioletTools provides comprehensive TLS/SSL analysis capabilities including:

- **TLS Risk Assessment**: YAML-driven scoring engine with 65 rules across 7 categories (Protocols, Cipher Suites, Certificate, Revocation, Security Headers, DNS Security, Other). Supports user-defined risk rules merged with system rules.
- **Certificate Analysis**: Examine server certificates, trust chains, validity periods, public key details (algorithm, size, EC curve), SAN enumeration, and signing algorithms
- **Cipher Suite Enumeration**: Discover all cipher suites supported by a server with strength evaluations (IANA, OpenSSL, GnuTLS, or NSS naming). Supports replaceable cipher maps via custom YAML definitions.
- **Security Headers Analysis**: Check for HSTS, CSP, X-Frame-Options, and other security response headers
- **Revocation Checking**: OCSP, OCSP Stapling, CRL, OneCRL, Must-Staple, and Certificate Transparency (SCT signature verification from embedded, TLS extension, and OCSP staple sources)
- **TLS Server Fingerprinting**: JARM-inspired 10-probe fingerprinting that characterizes server TLS behavior for grouping and change detection
- **DNS Security**: CAA and DANE/TLSA record checking
- **Fallback SCSV**: RFC 7507 TLS Fallback Signaling detection
- **Connection Analysis**: Review TLS session properties, negotiated protocol and cipher suite, and socket configurations
- **AI-Powered Analysis**: Optional AI evaluation of scan results using Anthropic, OpenAI, or Ollama providers, plus an interactive AI Assistant for conversational Q&A about scan results
- **Certificate Export**: Save server certificates in PEM format for offline analysis
- **Configurable Engine**: Choose which report sections to include, cipher naming conventions, and protocol versions of interest
- **Test Server Library**: Quick access to badssl.com test servers and recently scanned URLs

## Requirements

- **Java 21** or later (JDK or JRE)
- Network access to target HTTPS servers

## Installation

### Pre-built Releases

Download the latest release from the [GitHub Releases](https://github.com/spoofzu/DeepVioletTools/releases) page:

- `dvui.jar` - GUI application
- `dvcli.jar` - Command-line tool

### Building from Source

See [Building from Source](#building-from-source) section below.

## Quick Start

### GUI Application

```bash
java -jar dvui.jar
```

Enter an HTTPS URL (e.g., `https://www.github.com/`) and click **Scan**.

### Command Line Tool

```bash
# Full scan
java -jar dvcli.jar -serverurl https://www.github.com/

# Specific sections only (header, certificate, analysis)
java -jar dvcli.jar -serverurl https://www.github.com/ -s tsa
```

## GUI Application (dvui)

The GUI application provides an intuitive interface for TLS/SSL scanning.

### Features

- **URL Input**: Enter any HTTPS URL to scan
- **Real-time Results**: View scan results as they are generated with syntax highlighting
- **AI Assistant**: Terminal-style chat interface for conversational Q&A about scan results, with scan selector for reviewing saved scans
- **AI Evaluation**: Optional AI-powered analysis section in scan reports
- **Save Reports**: Export scan results to text, HTML, PDF, or JSON
- **Theme Support**: Dark, light, and system presets with full color customization
- **Engine Configuration**: Choose which report sections to include, cipher naming convention, and protocol versions
- **AI Configuration**: Provider selection (Anthropic, OpenAI, Ollama), API key management, model selection, customizable system prompts, and terminal color themes
- **Test Servers**: Quick access to badssl.com test servers and recently scanned URLs
- **Status Bar**: Monitor scan progress in real-time

### Usage

1. Launch the application: `java -jar dvui.jar`
2. Enter the target HTTPS URL in the "Host(IP)" field
3. Click the **Scan** button
4. View results in the main text area
5. Optionally click **Save** to export results

### Main Tabs

The main window has two tabs:

- **Scan** — Unified single and multi-target scanning. Includes URL input bar (Host label, text field, test servers dropdown, Scan/Save buttons) for single-host scans with a read-only styled results text pane, plus a multi-target area with targets text area (supports IPs, hostnames, URLs, CIDR blocks, dash ranges), Load File/Scan/Save buttons, heat map result sub-tabs (Risk, Ciphers, Connection, Fingerprint, Host Details), and a worker status bar at the bottom showing current scan phase per worker.
- **AI Assistant** — Terminal-style chat interface for asking questions about scan results. Includes scan type radio buttons (Individual/Multi-Target), a scan selector dropdown to choose from saved scans, a text input field, and a Send button. The AI tab is enabled when AI is configured in **System > Settings > AI**.

### Menu Bar

| Menu | Item | Description |
|------|------|-------------|
| **System** | Settings | Open the Settings dialog (Reporting, Engine, AI, Cipher Map, User Risks, and Application tabs) |
| **System** | Exit | Save window state and quit |
| **Developer** | Mode | Toggle between advanced and normal mode |
| **Help** | Interface | Open the Interface help dialog (scan output documentation) |
| **Help** | About | Project information and links |

### Test Servers Dialog

The **Test Servers** button (▼) next to the URL input field opens a dialog with two sections:

- **Recent** (top) — The last 5 URLs you scanned, for quick re-testing
- **Test Servers** (bottom) — Pre-configured badssl.com servers covering valid certificates, expired certs, hostname mismatches, self-signed roots, revoked certificates, missing intermediates, and Certificate Transparency edge cases

**Selection behavior:**

- **Double-click** any entry to immediately populate the host field and start scanning
- **Single-click** to highlight, then click **OK** to scan
- **Cancel** returns to the main window without changes

Clicking in one list automatically clears the selection in the other.

### Settings Dialog

Accessed via **System > Settings**, the Settings dialog has six tabs:

#### Reporting Tab

Controls the visual appearance of scan results. The tab has two sub-tabs:

**Host Detail sub-tab:**

- **Font** — Font family and size for scan report output
- **Report Colors** — Background, default text, notice, heading, content, key, value, warning, subsection, risk pass, risk inconclusive, and risk fail colors (arranged in two columns). Also includes a **Risk Graph Scale** spinner (10–50 blocks) that controls the resolution of the risk assessment bar chart.
- **Output** — Hard wrap toggle with wrap width (in characters)
- **Presets** — One-click theme presets (System Default, Light Default, Dark Default). Presets only affect reporting settings; engine settings are preserved.
- **Report Preview** — Live preview of all color and font settings (updates as you change controls)

**Cards sub-tab:**

Configures the appearance of scan host cards.

- **Card Font** — Font family, size, and grade badge size for host cards
- **Card Colors** — Background, text, dim text, border, selected border, and error colors
- **Card Layout** — Interactive grid editor for customizing which metadata elements appear on host cards, where they are placed, and how they are sized. The editor has three sections side by side:
  - **Palette** (left) — Draggable metadata elements: Grade, Score, Host Name, IP, TLS Version, Ciphers, Headers, Cert, Risk Bars. Greyed-out elements are already placed on the card. Drag an element from the palette onto the grid to add it.
  - **Grid Editor** (center) — Visual grid showing the current card layout. Elements appear as colored tiles in their assigned cells. Interactions:
    - **Shift+click** on an element — Adjust alignment within its cell. The cell is divided into a 3×3 grid (left/center/right × top/center/bottom); click the region you want. A small dot indicates the current alignment.
    - **Drag an element** within the grid — Extend the element to span multiple columns and/or rows. Drag right to increase column span, down to increase row span. The span is clamped to avoid overlapping other elements.
    - **Right-click** on an element — Context menu with "Remove from card" (hides the element) and "Reset span to 1×1" (if spanning).
    - **Drag a grid line** — Resize cell proportions by dragging the interior column or row dividers. The cursor changes to a resize arrow when hovering near a grid line.
    - **Drop from palette** — Place a new element into a grid cell.
  - **Controls** (right) — Column and row count spinners (Cols: 1–5, Rows: 2–9), a circular-arrow **reset button** that restores the default 3×5 layout, and a **trash** drop target for removing elements by dragging them off the grid.
- **Card Preview** — Live preview showing a sample host card rendered with the current layout, font, and color settings. Updates in real time as you edit the grid, adjust alignment, resize cells, or change colors.

#### Engine Tab

Controls scan behavior and report content:

- **Report Sections** — Toggle individual report sections on or off:

  | Checkbox | Section |
  |----------|---------|
  | Risk assessment | TLS risk score, grade, and category graph |
  | Header | Version, timestamp, runtime info |
  | Host information | DNS resolution |
  | HTTP response headers | Raw server response headers |
  | Security headers analysis | HSTS, CSP, X-Frame-Options, etc. |
  | Connection characteristics | TLS session properties |
  | Cipher suites | Server cipher enumeration with strength |
  | Certificate chain | End-entity to root chain |
  | Revocation status | OCSP, CRL, OneCRL, CT/SCTs |
  | TLS server fingerprint | Server TLS behavior fingerprint |

  Use **Select All** / **Deselect All** for quick toggling. All sections are enabled by default.

- **Cipher Suite Naming** — Convention used to display cipher suite names:

  | Convention | Description |
  |------------|-------------|
  | IANA | Standard IANA names (default) |
  | OpenSSL | OpenSSL naming convention |
  | GnuTLS | GnuTLS naming convention |
  | NSS | Mozilla NSS naming convention |

- **Protocol Versions** — Select which TLS/SSL protocol versions are of interest:

  | Protocol | Default | Note |
  |----------|---------|------|
  | SSLv3 | Off | Insecure |
  | TLS 1.0 | Off | Deprecated |
  | TLS 1.1 | Off | Deprecated |
  | TLS 1.2 | On | |
  | TLS 1.3 | On | |

All engine settings are persisted to `~/DeepVioletTools/deepviolet.properties` and applied on subsequent scans. The CLI tool (`dvcli`) is unaffected by these preferences — it uses its own `-s` flags for section selection.

#### AI Tab

Configures AI-powered analysis. Has three sub-tabs:

**Configuration sub-tab:**

- **AI Analysis** — Master toggle to enable/disable AI features (enables the AI Assistant tab and AI evaluation report section)
- **Provider** — Select from Anthropic, OpenAI, or Ollama:

  | Provider | API Key Required | Models |
  |----------|-----------------|--------|
  | Anthropic | Yes | claude-sonnet-4-5-20250929, claude-haiku-4-5-20251001 |
  | OpenAI | Yes | gpt-4o, gpt-4o-mini |
  | Ollama | No (local) | llama3.2:latest, mistral:latest, gemma2:latest (auto-fetched from server) |

- **API Key** — Password field for Anthropic/OpenAI keys. Keys are encrypted with AES-GCM before being stored in the properties file. For Ollama, the API key field is replaced with an **Endpoint URL** field (default: `http://localhost:11434`).
- **Model** — Dropdown of available models for the selected provider. The combo box is editable, so custom model names can be entered. When Ollama is selected, models are fetched from the running Ollama instance.
- **Max Tokens** — Maximum tokens in the AI response (256–32768)
- **Temperature** — Sampling temperature (0.0–1.0, default 0.3)
- **Connection Test** — Button to verify the AI provider configuration

**Prompts sub-tab:**

- **Report System Prompt** — Controls the AI Evaluation section in scan reports. The default prompt instructs the AI to analyze each risk assessment finding with What/Why/Remediation sections.
- **Chat System Prompt** — Controls the AI Assistant on the main window. The default prompt enforces a 5-sentence maximum with plain text formatting.

**Terminal Colors sub-tab:**

- 9 color controls for the AI Assistant terminal appearance:
  - System: background, system text, selection background, selection foreground
  - User: prefix color, text color
  - AI: prefix color, text color
  - Error text color
- Live terminal preview that updates as colors are changed

#### Cipher Map Tab

Allows replacing the built-in cipher suite map with a custom YAML definition. When enabled, cipher suite strength ratings in scan reports reflect the custom map instead of the defaults.

- **Enable custom cipher map** — Master toggle to activate the custom map
- **YAML editor** — Text area for editing the cipher map YAML directly. Shows a placeholder example when empty.
- **Load File** — Import a `.yaml` or `.yml` file via file chooser
- **Save to File** — Export the current YAML to a file
- **Clear** — Remove the custom map, uncheck enable, and restore the placeholder

The YAML format uses a `cipher_suites` array where each entry has:
- `id` — Hex cipher suite ID (e.g., `"0x13,0x01"`)
- `names` — Map of naming conventions (IANA, OpenSSL, etc.)
- `strength` — Strength rating: `STRONG`, `MEDIUM`, `WEAK`, or `CLEAR`
- `tls_versions` — List of applicable TLS versions

The custom cipher map YAML is saved to `~/DeepVioletTools/custom-ciphermap.yaml`. The enabled/disabled state is persisted in `deepviolet.properties`.

**CLI:** Use `--ciphermap <path>` to load a custom cipher map from a YAML file. The CLI flag overrides the saved GUI preference.

#### User Risks Tab

Allows defining custom risk assessment rules that are merged with the built-in system rules during scoring. Custom rules use `USR-` prefixed IDs and appear alongside system findings in the risk assessment.

- **Enable user risk rules** — Master toggle to activate custom rules
- **YAML editor** — Text area for editing the risk rules YAML directly. Shows a placeholder example when empty.
- **Load File** — Import a `.yaml` or `.yml` file via file chooser
- **Save to File** — Export the current YAML to a file
- **Clear** — Remove user rules, uncheck enable, and restore the placeholder

The YAML format uses a `categories` map where each category contains:
- `display_name` — Category display name
- `rules` — Map of rule definitions, each with `id` (USR-prefixed), `description`, `score`, `when`, and `enabled` fields

The user risk rules YAML is saved to `~/DeepVioletTools/user-riskrules.yaml`. The enabled/disabled state is persisted in `deepviolet.properties`.

**CLI:** Use `--riskrules <path>` to load user risk rules from a YAML file. The CLI flag overrides the saved GUI preference.

#### Application Tab

Controls application-wide appearance:

- **Application UI Font** — Font family and size for the entire application interface (menus, buttons, dialogs — distinct from the report font in the Reporting tab)
- **Colors** — Window background, window foreground, button background, button foreground
- **Presets** — System, Dark, and Light presets for application-wide appearance

### Screenshot

```
+-------------------------------------------------------+
| [Scan] [AI Assistant]                                  |
|-------------------------------------------------------|
| Host(IP): [https://example.com/   ] [▼] [Scan] [Save] |
|-------------------------------------------------------|
|                                                       |
|  [Report run information]                             |
|  DeepViolet 5.1.17                                    |
|  Report generated on Wed Jan 21 14:00:00 PST 2026    |
|  Target url https://example.com/                      |
|                                                       |
|  [Runtime environment]                                |
|  Java version: 21.0.1                                 |
|  ...                                                  |
|                                                       |
|-------------------------------------------------------|
| Status: Ready, 2345(ms)                               |
+-------------------------------------------------------+
```

## Command Line Tool (dvcli)

The command-line tool is designed for automation, scripting, and headless environments.

### Basic Syntax

```bash
java -jar dvcli.jar -serverurl <url> [options]
```

### Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-u` | `--serverurl` | HTTPS server URL to scan (required for single-host mode) |
| `-s` | `--sections` | Report sections to include (see below) |
| `-o` | `--output` | Write report to file (format inferred from extension) |
| `-f` | `--format` | Explicit output format: `txt`, `html`, `pdf`, `json` |
| `-wc` | `--writecertificate` | Write PEM certificate to file |
| `-rc` | `--readcertificate` | Read and analyze PEM certificate from file |
| | `--scan` | Comma-separated multi-target list (mutually exclusive with `-u`) |
| | `--scan-file` | File with scan targets, one per line (mutually exclusive with `-u`) |
| | `--scan-threads` | Worker thread count for multi-target scans (1–10, default 3) |
| | `--scan-throttle` | Delay in ms between hosts per worker (0–10000, default 150) |
| | `--delta` | Compare two saved `.dvscan` files: `--delta base.dvscan,target.dvscan` |
| | `--ai` | Enable AI evaluation section in report |
| | `--ai-provider` | AI provider: `anthropic`, `openai`, `ollama` |
| | `--ai-model` | AI model name |
| | `--ai-key` | API key (overrides saved key; prefer env var `DV_AI_API_KEY`) |
| | `--ai-endpoint` | Ollama endpoint URL (default: `http://localhost:11434`) |
| | `--validate` | Compare DV API results against openssl for a host (requires openssl) |
| | `--ciphermap` | Custom cipher map YAML file (replaces built-in cipher suite map) |
| | `--riskrules` | User risk rules YAML file (merged with system rules during scoring) |
| | `--proto-sslv3` | Enable SSLv3 protocol testing |
| | `--proto-tls10` | Enable TLS 1.0 protocol testing |
| | `--proto-tls11` | Enable TLS 1.1 protocol testing |
| | `--proto-tls12` | Enable TLS 1.2 protocol testing |
| | `--proto-tls13` | Enable TLS 1.3 protocol testing |
| `-d` | `--debug` | Enable SSL/TLS connection debugging |
| `-d2` | `--debuglogging` | Enable DEBUG level logging |
| `-h` | `--help` | Print help information |

### Section Codes

Use with `-s` option to select specific report sections:

| Code | Section |
|------|---------|
| `a` | TLS risk assessment (score, grade, category graph) |
| `e` | Runtime environment (Java version, OS, trust store) |
| `t` | Report header (multi-target mode) |
| `h` | Host information (DNS resolution) |
| `r` | HTTP response headers |
| `x` | Security headers analysis (HSTS, CSP, etc.) |
| `c` | Connection characteristics |
| `i` | Cipher suite enumeration |
| `s` | Server certificate chain |
| `n` | Certificate chain (alias for `s`) |
| `v` | Revocation status (OCSP, CRL, CT/SCTs) |
| `f` | TLS server fingerprint |

**Note:** The CLI always uses its own `-s` flags for section selection. The GUI engine settings (configured in **System > Settings > Engine**) do not affect CLI behavior.

### Examples

```bash
# Full scan with all sections
java -jar dvcli.jar -serverurl https://www.github.com/

# Header, connection, certificate chain, and fingerprint only
java -jar dvcli.jar -serverurl https://www.github.com/ -s tcsf

# Export server certificate to PEM file
java -jar dvcli.jar -serverurl https://www.github.com/ -wc ~/certs/github.pem

# Analyze a PEM certificate file
java -jar dvcli.jar -rc ~/certs/github.pem

# Save report as JSON
java -jar dvcli.jar -serverurl https://www.github.com/ -o report.json

# Save report as HTML with explicit format
java -jar dvcli.jar -serverurl https://www.github.com/ -o report.html -f html

# Full scan with SSL debugging enabled
java -jar dvcli.jar -serverurl https://www.github.com/ -d

# Full scan with AI evaluation (uses saved API key from Settings)
java -jar dvcli.jar -serverurl https://www.github.com/ --ai

# AI evaluation with explicit provider and model
java -jar dvcli.jar -serverurl https://www.github.com/ --ai --ai-provider anthropic --ai-model claude-sonnet-4-5-20250929

# AI evaluation with Ollama (no API key needed)
java -jar dvcli.jar -serverurl https://www.github.com/ --ai --ai-provider ollama --ai-model llama3.2:latest

# Scan with a custom cipher map
java -jar dvcli.jar -serverurl https://www.github.com/ --ciphermap custom-ciphers.yaml

# Scan with user risk rules
java -jar dvcli.jar -serverurl https://www.github.com/ --riskrules my-rules.yaml

# Combine custom cipher map and user risk rules
java -jar dvcli.jar -serverurl https://www.github.com/ --ciphermap custom-ciphers.yaml --riskrules my-rules.yaml

# Multi-target scan: comma-separated targets
java -jar dvcli.jar --scan "github.com,google.com,example.com"

# Multi-target scan: targets from file (one per line, # comments ignored)
java -jar dvcli.jar --scan-file targets.txt

# Multi-target scan with 4 concurrent workers and 500ms throttle between hosts
java -jar dvcli.jar --scan-file targets.txt --scan-threads 4 --scan-throttle 500

# Multi-target scan with specific sections and output file
java -jar dvcli.jar --scan-file targets.txt -s acf -o scan-report.json

# Multi-target scan with CIDR expansion
java -jar dvcli.jar --scan "10.0.1.0/24" --scan-threads 8

# Delta scan comparing two saved scans
java -jar dvcli.jar --delta base.dvscan,target.dvscan

# Validate DV API results against openssl
java -jar dvcli.jar --validate google.com

# Validate a server with a known bad certificate
java -jar dvcli.jar --validate expired.badssl.com

# Validate with JSON output
java -jar dvcli.jar --validate github.com -f json
```

### Multi-Target Mode

The CLI supports multi-target scanning via `--scan` or `--scan-file`, which are mutually exclusive with `-u` (single-host mode). Multi-target mode scans multiple targets concurrently and produces heat map output.

**Target formats** (same as the GUI Multi-Target Scan tab):
- Hostnames: `example.com`, `example.com:8443`
- IPv4: `10.0.1.5`, `10.0.1.5:8443`
- IPv6: `[2001:db8::1]`, `[::1]:8443`, `2001:db8::1` (bare, auto-bracketed)
- CIDR blocks: `10.0.1.0/24` (IPv4), `2001:db8::/120` (IPv6, capped at configurable limit)
- Dash ranges: `10.0.2.1-50` (IPv4 last-octet range)
- Full URLs: `https://example.com/`

**Scan output:**
1. Console prints heat map tables (Risk, Cipher, Connection, Fingerprint) with percentage-based cell values
2. Error summary for any failed hosts
3. Auto-saves individual host reports to `~/DeepVioletTools/cli/scans/<timestamp>/` as text files
4. If `-o` is specified, exports the full scan report in the requested format (text, HTML, PDF, or JSON)

### Validation Mode

The `--validate` option compares DV API scan results against openssl for the same server in real-time. This is useful for verifying the accuracy of DV API output against an independent source of truth. Requires `openssl` installed locally.

```bash
java -jar dvcli.jar --validate google.com
```

**How it works:**
1. Runs `openssl s_client -connect host:443 -servername host -showcerts` to get connection info and certificate chain
2. Pipes each PEM cert through `openssl x509 -text -noout` for parsed certificate details
3. Runs `DeepVioletFactory.initializeSession()` + `getEngine()` for DV API results
4. Normalizes both sides (e.g., "RSA" vs "rsaEncryption", DN ordering, date formats) and compares field-by-field

**Compared fields (17):** subjectDN, issuerDN, serialNumber, version, signingAlgorithm, publicKeyAlgorithm, publicKeySize, publicKeyCurve (EC only), notValidBefore, notValidAfter, isSelfSigned, sanCount, fingerprint, negotiatedProtocol, negotiatedCipher, chainLength, ocspStapling.

**For bad-cert servers** (expired, self-signed, untrusted): DV session fails (as expected), openssl still connects. The output shows the openssl-only certificate info and notes that DV correctly rejected the connection. Result: PASS.

**Exit codes:** 0 when all fields match or DV correctly rejected a bad cert, 1 when mismatches are found.

**JSON output:** Use `-f json` to get structured JSON output instead of the formatted table.

The validation tool is also available as a standalone JAR in the DeepViolet project (`mvn package -Pvalidate`), runnable without DeepVioletTools:
```bash
java -jar DeepViolet-*-validate.jar google.com
java -jar DeepViolet-*-validate.jar --json github.com
java -jar DeepViolet-*-validate.jar expired.badssl.com
```

## Report Sections

### TLS Risk Assessment (`a`)

Provides an overall security score, letter grade, and risk level for the target server.

#### Score, Grade, and Risk Level

The report header shows three headline values:

- **Overall Score** — Points retained out of 100 after all deductions
- **Grade** — Letter grade derived from the score
- **Risk Level** — Qualitative risk classification

| Grade | Min Score | Risk Level |
|-------|-----------|------------|
| A+    | 95        | LOW        |
| A     | 90        | LOW        |
| B     | 80        | MEDIUM     |
| C     | 70        | HIGH       |
| D     | 60        | CRITICAL   |
| F     | 0         | CRITICAL   |

#### Category Graph

Below the headline values is a fixed-width bar chart with an **Overall** bar followed by seven numbered category bars:

1. **Protocols & Connections** — Supported TLS/SSL protocol versions and connection parameters (e.g., deprecated protocols, compression, renegotiation)
2. **Cipher Suites** — Strength and safety of negotiated and offered cipher suites (e.g., weak key exchange, export-grade ciphers, no forward secrecy)
3. **Certificate & Chain** — Certificate validity, chain completeness, key strength, and signing algorithms (e.g., expired certs, short RSA keys, SHA-1 signatures)
4. **Revocation & Transparency** — OCSP, CRL, and Certificate Transparency status (e.g., missing OCSP stapling, no SCTs, revoked certificates)
5. **Security Headers** — HTTP security headers (e.g., missing HSTS, CSP, X-Frame-Options, Permissions-Policy)
6. **DNS Security** — DNS resolution and DNSSEC status
7. **Other** — Miscellaneous checks including TLS compression, client authentication, fingerprint availability, and SAN (Subject Alternative Name) information disclosure

#### Reading the Bars

Each bar has a configurable number of blocks (default 20, adjustable in Settings). Three block characters represent the state of each portion:

| Symbol | Meaning       | Description                        |
|--------|---------------|------------------------------------|
| `█`    | Pass          | Points retained                    |
| `▐`    | Inconclusive  | Uncertain — could not be verified  |
| `░`    | Fail          | Points deducted                    |

After the bar, the score is shown as `score/100`, followed by an annotation:

```
[RISK_LEVEL] (N.N pts/blk)
```

- **RISK_LEVEL** — The risk level for that category (LOW, MEDIUM, HIGH, CRITICAL)
- **pts/blk** — Points represented by each block (100 ÷ scale), so you can estimate point impact visually

A legend line appears below the last category bar:

```
█ pass   ▐ inconclusive   ░ fail   (scale=20 blocks)
```

#### Footnotes

When a category contains inconclusive findings (items that could not be definitively evaluated), footnote references (`*1`, `*2`, etc.) are appended to that category's bar line. The corresponding footnote text appears in a **Notes** subsection below the graph, explaining what could not be verified.

#### Deduction Details

Below the graph, each category with deductions gets its own numbered subsection showing the category score:

```
N. Category Name (score/100)
```

Each deduction line within a category shows:

- **Rule ID** — The scoring rule identifier (e.g., `SYS-0010100`)
- **Severity** — `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, or `[INFO]`
- **Description** — What the deduction is for
- **Inconclusive marker** — `[INCONCLUSIVE]` if the finding could not be verified
- **Normalized score** — `(score: N.NN)` — the normalized deduction weight

#### Interpretation Tips

- **Focus on CRITICAL and HIGH severity** deductions first — these have the largest impact on the score
- **Inconclusive findings** deserve investigation — they may indicate network restrictions preventing full analysis rather than actual security issues
- **Category scores are independent** — a perfect score in one category does not offset failures in another
- The **Other** category checks for SAN exposure: certificates covering many SANs reveal an organization's hosted services, staging servers, and internal naming conventions. The SAN deduction is tiered (LOW for 2–5 SANs, MEDIUM for 6–20, HIGH for 21+), and only the highest applicable tier is applied
- Grade thresholds and deduction rules are configurable via custom risk rules (`--riskrules` CLI flag or Settings > User Risks in the GUI)

### AI Evaluation

When AI is enabled (GUI: **System > Settings > AI**, CLI: `--ai`), the report includes an AI-powered analysis section after the risk assessment. The scan report generated so far is sent to the configured AI provider, which returns a structured analysis including:

- **Executive Summary** — Overall TLS security posture assessment referencing the score, grade, and risk level
- **Per-Finding Analysis** — For each risk assessment item: what it is, why it matters, and remediation guidance
- **Positive Findings** — Security measures that are properly configured
- **Recommendations** — Prioritized action items referencing specific findings

The analysis is generated by the system prompt configured in **System > Settings > AI > Prompts**. Lines prefixed with "CRITICAL:" or "WARNING:" are highlighted as warnings in the report.

### Report Header (`t`)

Contains run metadata including:
- DeepViolet version
- Report timestamp
- Target URL
- Java runtime information
- Trust store location
- Log file location

### Host Information (`h`)

DNS resolution details:
- Hostname
- IP addresses (IPv4 and IPv6)
- Canonical hostnames

### HTTP Response Headers (`r`)

Server response headers from the HTTPS connection.

### Connection Characteristics (`c`)

TLS session properties including:
- Socket keepalive settings
- Buffer sizes
- TCP nodelay configuration
- Enabled protocols

### Cipher Suite Enumeration (`i`)

All cipher suites supported by the server:
- Suite name (configurable naming convention: IANA, OpenSSL, GnuTLS, or NSS)
- Strength evaluation (STRONG, MEDIUM, WEAK, CLEAR)
- TLS protocol version

The naming convention defaults to IANA. In the GUI, change it via **System > Settings > Engine > Cipher Suite Naming**.

### Security Headers Analysis (`x`)

Checks for the presence and values of key security response headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

Missing headers are flagged as `>>>MISSING<<<`.

### Server Certificate Chain (`s`, `n`)

Full chain analysis from end-entity to root:
- Chain summary with role labels (End-Entity, Intermediate CA, Root CA)
- Revocation status label per node
- Detailed per-certificate information:
  - Subject and Issuer Distinguished Names
  - Serial number
  - Signature algorithm and OID
  - Validity period and state (VALID, EXPIRED, NOT_YET_VALID)
  - Days until expiration (with warnings for <30 days or expired)
  - Trust state (TRUSTED, UNTRUSTED, UNKNOWN)
  - Public key algorithm, size, and curve (for ECC)
  - Certificate fingerprint
  - Critical and non-critical OIDs

### Revocation Status (`v`)

Comprehensive certificate revocation checking for each certificate in the chain:
- **OCSP**: Responder URL, status, response time, signature validation, this/next update
- **OCSP Stapling**: Presence and status of stapled OCSP responses
- **Must-Staple**: Detection with a warning if must-staple is set but stapling is absent
- **CRL**: Distribution point, status, download time, CRL size
- **OneCRL**: Mozilla's centralized revocation list
- **Certificate Transparency (SCTs)**:
  - Embedded SCT count, TLS extension SCTs, OCSP staple SCTs
  - CT log identification (operator, URL, state)
  - SCT signature verification (VALID, INVALID, UNKNOWN_LOG)

### TLS Server Fingerprint (`f`)

Characterizes the server's TLS implementation by sending 10 different probe handshakes and hashing the results:
- Summary line (protocol support, cipher ordering behavior)
- Full fingerprint in colon-delimited hex octets
- Per-probe breakdown (TLS 1.2 standard/reverse/ALPN/no-ECC, TLS 1.1, TLS 1.3 variants, forward secrecy)
- Extension hash for additional server characterization

Useful for grouping servers by implementation, detecting CDN/load balancer configurations, and tracking TLS configuration changes over time.

## Saving and Exporting Reports

### GUI

Click **Save** to export the current scan results. Supported formats:

| Format | Extension | Description |
|--------|-----------|-------------|
| Text | `.txt` | Plain ASCII text |
| HTML | `.html` | Themed HTML with syntax highlighting (uses Reporting tab colors) |
| PDF | `.pdf` | Themed PDF document (uses Reporting tab colors) |
| JSON | `.json` | Structured JSON for programmatic consumption |

### CLI

Use `-o <file>` to write the report to a file. The format is inferred from the file extension, or set explicitly with `-f`:

```bash
java -jar dvcli.jar -serverurl https://example.com/ -o report.json
java -jar dvcli.jar -serverurl https://example.com/ -o report.pdf
java -jar dvcli.jar -serverurl https://example.com/ -o output -f html
```

Without `-o`, the CLI prints plain text to stdout (or JSON if `-f json` is specified).

## Multi-Target Scanning

Multi-target scanning lets you scan multiple hosts concurrently and compare results across targets using heat map visualizations.

### Target Formats

Targets can be entered in the GUI's Multi-Target Scan tab (one per line) or passed to the CLI via `--scan` (comma-separated) or `--scan-file` (file with one target per line, `#` comments ignored).

| Format | Example | Expansion |
|--------|---------|-----------|
| Hostname | `example.com` | `https://example.com:443/` |
| Hostname with port | `example.com:8443` | `https://example.com:8443/` |
| IPv4 address | `10.0.1.5` | `https://10.0.1.5:443/` |
| IPv4 with port | `10.0.1.5:8443` | `https://10.0.1.5:8443/` |
| IPv6 bracketed | `[2001:db8::1]` | `https://[2001:db8::1]:443/` |
| IPv6 with port | `[::1]:8443` | `https://[::1]:8443/` |
| IPv6 bare | `2001:db8::1` | auto-bracketed to `https://[2001:db8::1]:443/` |
| IPv4 CIDR | `10.0.1.0/24` | 254 individual IPs (excludes network/broadcast) |
| IPv6 CIDR | `2001:db8::/120` | individual IPs (capped at configurable max, default 512) |
| IPv4 dash range | `10.0.2.1-50` | `10.0.2.1` through `10.0.2.50` |
| Full URL | `https://example.com/` | used as-is |

CIDR expansion uses `BigInteger` address arithmetic for protocol-agnostic IPv4/IPv6 support. The maximum CIDR expansion is configurable (default 512) and blocks exceeding the limit are rejected.

### Concurrent Execution

Multi-target scans are executed by worker threads, each pulling targets from a shared queue:

- **Worker count**: configurable 1–10 threads (CLI: `--scan-threads`, GUI: Settings). The effective count is capped at the target count.
- **Throttle delay**: configurable delay in ms between hosts per worker (CLI: `--scan-throttle`), useful for rate-limiting.
- **Per-worker progress**: each worker reports its current scan phase (e.g., "TLS risk assessment", "Cipher suites").
- **Cancellation**: scans can be cancelled mid-flight; in-progress targets are marked as cancelled.

### Heat Map Visualization

After a multi-target scan completes, results are aggregated into heat maps — color-coded grids where each column represents one or more hosts and each row represents a data point.

**7 heat map dimensions:**

| Map | Rows | Cell Logic |
|-----|------|------------|
| **Risk** | Individual risk deduction rules grouped by category, plus certificate trust/validity/expiry rows | Rule fired = fail, inconclusive = amber, not fired = pass |
| **Ciphers** | Individual cipher suites grouped by strength (CLEAR, WEAK, MEDIUM, STRONG) | Cipher offered = pass, not offered = fail |
| **Security Headers** | 7 standard headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy) | Present = pass, missing = fail |
| **Connection** | Per-property rows; negotiated protocol/cipher expand to per-value rows | Varies by property type |
| **HTTP Response** | All unique response header names across hosts | Present = pass, absent = fail |
| **Revocation** | 5 rows: OCSP, OCSP Stapling, CRL, OneCRL, CT SCTs | GOOD/PRESENT = pass, REVOKED = fail, else inconclusive |
| **Fingerprint** | 10 TLS probe codes + extension hash | Matches majority = pass, different = fail, probe failed = inconclusive |

**Cell coloring**: each cell blends pass (green), fail (red), and inconclusive (amber) based on the ratio of hosts in that column matching each state. When hosts outnumber columns, multiple hosts are aggregated per column; when there are fewer hosts, each host spans multiple columns proportionally.

**GUI rendering**: `HeatMapPanel` renders the grid with tooltips showing host names, percentages, and pass/fail/inconclusive counts. Category headers separate groups of related rows.

**Text rendering**: percentage-based output with repeated values collapsed to `.` for readability. Suffixes: `E` = error column, `I` = has inconclusive results.

### Scan Results

**GUI auto-save**: `~/DeepVioletTools/ui/scans/scan-report-<date>-<n>.txt`

**CLI auto-save**: individual host reports to `~/DeepVioletTools/cli/scans/<timestamp>/<hostname>.txt`

**Manual export** (GUI Save button or CLI `-o`): Text, HTML (styled tables with colored cells), PDF (landscape A4 with colored cells), or JSON (structured with per-host data and host index).

### Multi-Target Preferences

Multi-target scanning has its own set of engine preferences (separate from single-scan settings), stored in `~/DeepVioletTools/deepviolet.properties`:

- 7 section toggles (risk assessment, HTTP response, security headers, connection, cipher suites, revocation, TLS fingerprint)
- Cipher naming convention (IANA/OpenSSL/GnuTLS/NSS)
- Protocol version flags (SSLv3, TLS 1.0–1.3)
- Worker thread count (1–10, default 3)
- Throttle delay (0–10000ms, default 150)
- Max CIDR expansion (default 512)
- Separate font and 13 color settings for scan report rendering
- Target history (last 5 target groups)

## JSON Report Schema Reference

The JSON export produces a structured object with a top-level `report_version` field followed by one key per report section. JSON consumers should check `report_version` to verify field compatibility — the version is incremented whenever fields are added, renamed, or removed.

### Top-Level Structure

```json
{
  "report_version": "1.0",
  "Runtime environment": { ... },
  "TLS Risk Assessment": { ... },
  "AI Evaluation": { ... },
  "Host information": { ... },
  "HTTP(S) response headers": { ... },
  "Security headers analysis": { ... },
  "Connection characteristics": { ... },
  "Server cipher suites": { ... },
  "Server certificate chain": { ... },
  "Chain details": { ... },
  "Certificate revocation status": { ... },
  "TLS server fingerprint": { ... }
}
```

Only sections enabled for the scan are present. The `report_version` key is always first.

### Field Reference by Section

#### `report_version` (String)

Top-level key. Current value: `"1.0"`. Incremented when the report schema changes.

#### Runtime environment

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Report Version` | String | Report format version | `"1.0"` |
| `Java Version` | String | JVM version | `"21.0.1"` |
| `Java Vendor` | String | JVM vendor | `"Eclipse Adoptium"` |
| `Java Home` | String | JVM install path | `"/usr/lib/jvm/temurin-21"` |
| `OS` | String | Operating system name and version | `"Linux 6.1.0"` |
| `Trust Store` | String | Path to Java trust store | `"/usr/lib/jvm/temurin-21/lib/security/cacerts"` |
| `Log File` | String | Path to scan log file | `"~/DeepVioletTools/ui/scanlog.log"` |

#### TLS Risk Assessment

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Overall Score` | String | Aggregate score | `"85/100"` |
| `Grade` | String | Letter grade | `"B"` |
| `Risk Level` | String | Qualitative risk level | `"MODERATE"` |
| `Details` | Object | Subsection with bar graph content lines | See below |
| `<Category> (<score>/<max>)` | Object | Per-category deduction details | See below |

The `Details` subsection contains a `_content` array with the text bar lines. Category subsections contain a `_content` array with the summary and a `_warnings` array with deduction descriptions.

#### Host information

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Host` | String | Hostname and IP | `"example.com [93.184.216.34]"` |
| `Canonical` | String | Canonical hostname | `"example.com"` |

#### HTTP(S) response headers

Dynamic key-value pairs — one entry per HTTP response header. Keys are header names, values are header values.

#### Security headers analysis

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Strict-Transport-Security (HSTS)` | String | HSTS header status | `"PRESENT (max-age=31536000)"` or `">>>MISSING<<<"` |
| `Content-Security-Policy (CSP)` | String | CSP header status | `"PRESENT (default-src 'self')"` or `">>>MISSING<<<"` |
| `X-Content-Type-Options` | String | Header status | `"PRESENT (nosniff)"` or `">>>MISSING<<<"` |
| `X-Frame-Options` | String | Header status | `"PRESENT (DENY)"` or `">>>MISSING<<<"` |
| `X-XSS-Protection` | String | Header status | `"PRESENT (1; mode=block)"` or `">>>MISSING<<<"` |
| `Referrer-Policy` | String | Header status | `"PRESENT (strict-origin)"` or `">>>MISSING<<<"` |
| `Permissions-Policy` | String | Header status | `"PRESENT (...)"` or `">>>MISSING<<<"` |

#### Connection characteristics

Dynamic key-value pairs from `ISession.SESSION_PROPERTIES`. Keys are session property names, values are their string representations.

#### Server cipher suites

Dynamic key-value pairs — one entry per cipher suite. Key is the suite name (in the configured naming convention), value is `"Strength=<eval>, Protocol=<proto>"`.

#### Server certificate chain

| Field | Type | Description |
|-------|------|-------------|
| `Chain Summary (end-entity --> root)` | Object | Subsection with per-node subsections |
| `NODE<n>(<role>)` | Object | Per-certificate node with `SubjectDN`, `IssuerDN`, `Fingerprint` |

#### Chain details

| Field | Type | Description |
|-------|------|-------------|
| `NODE<n>(<role>)` | Object | Detailed per-certificate subsection |

Each node subsection contains:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Trust State` | String | Trust evaluation | `"TRUSTED"` or `">>>UNTRUSTED<<<"` |
| `Validity Check` | String | Validity state with dates | `"VALID (valid ... to ...)"` |
| `Days Until Expiration` | String | Days remaining | `"365"` |
| `Subject DN` | String | Subject distinguished name | `"CN=example.com, O=..."` |
| `Issuer DN` | String | Issuer distinguished name | `"CN=Let's Encrypt, O=..."` |
| `Serial Number` | String | Certificate serial number | `"123456789"` |
| `Signature Algorithm` | String | Signing algorithm | `"SHA256withRSA"` |
| `Signature Algorithm OID` | String | OID of signing algorithm | `"1.2.840.113549.1.1.11"` |
| `Certificate Version` | String | X.509 version | `"3"` |
| `Public Key Algorithm` | String | Key algorithm | `"RSA"` |
| `Public Key Size` | String | Key size | `"2048 bits"` |
| `Public Key Curve` | String | EC curve (ECC only) | `"secp256r1"` |
| `<digest> Fingerprint` | String | Certificate fingerprint | `"[AB:CD:...]"` |
| `SAN Count` | String | Number of Subject Alternative Names | `"3"` |
| `Non-Critical OIDs` | Object | Non-critical extension OIDs | Key-value pairs |
| `Critical OIDs` | Object | Critical extension OIDs | Key-value pairs |

#### Certificate revocation status

Each certificate in the chain has a subsection keyed by `[<role>] <SubjectDN>`:

| Field | Type | Description |
|-------|------|-------------|
| `OCSP Check` | Object | OCSP subsection with `Status`, `Responder URL`, `Response Time`, etc. |
| `OCSP Stapling` | String | `"PRESENT"` or `"NOT PRESENT"` |
| `Stapled Status` | String | Stapled OCSP response status |
| `Must-Staple` | String | `"PRESENT"` or `"NOT PRESENT"` |
| `CRL Check` | Object | CRL subsection with `Status`, `Distribution Point`, `Download Time`, `CRL Size`, etc. |
| `OneCRL Check` | Object | OneCRL subsection with `Status` |
| `Certificate Transparency (SCTs)` | Object | SCT counts and per-SCT details |

SCT detail fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Embedded SCTs` | String | Count of embedded SCTs | `"3"` |
| `TLS Extension SCTs` | String | Count or `"*Note 1"` | `"0"` |
| `OCSP Staple SCTs` | String | Count of OCSP staple SCTs | `"0"` |
| `Embedded #<n>` | String | SCT detail string | `"Version=0 LogID=... Timestamp=..."` |
| `CT Log` | String | CT log operator and description | `"Google 'Argon2024' (usable)"` |
| `Log Server` | String | CT log server URL | `"https://ct.googleapis.com/logs/argon2024/"` |
| `Signature` | String | SCT signature verification result | `"VALID"`, `">>>INVALID<<<"`, `"NOT VERIFIED (...)"` |

#### TLS server fingerprint

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Summary` | String | Protocol support summary | `"TLS 1.2+1.3, server-preferred order"` |
| `Fingerprint` | String | Full fingerprint in hex octets | `"61:33:30:61:..."` |
| `Fingerprint Aggregation` | Object | Per-probe breakdown subsection | See below |

Fingerprint Aggregation fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `Probe  1` – `Probe 10` | String | Per-probe result | `"61:33:30 (OK) TLS 1.2 standard cipher order"` |
| `Extension Hash` | String | Extension hash in hex octets | `"AB:CD:EF:..."` |

### Special JSON Keys

| Key | Type | Description |
|-----|------|-------------|
| `_warnings` | Array of String | Warning messages within a section or subsection |
| `_content` | Array of String | Content/notice lines within a section or subsection |

These appear only when a section contains warning or content nodes.

## Common Errors and Troubleshooting

This section documents warning and error messages that may appear in scan reports, their causes, and suggested actions.

### Report Markers

DeepVioletTools uses `>>>` and `<<<` markers to highlight issues that need attention. Messages wrapped in these markers indicate a security concern or operational problem.

### Certificate Validity Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>>EXPIRED<<< (valid ... to ...)` | The server certificate's validity period has ended. | The certificate must be renewed. Browsers will reject this certificate. |
| `>>>NOT YET VALID<<< (valid ... to ...)` | The certificate's "Not Before" date is in the future. | Check the server clock and certificate issuance date. The certificate may have been issued with incorrect dates. |
| `>>> Certificate EXPIRED N days ago! <<<` | The certificate expired N days ago. | Renew the certificate immediately. |
| `>>> Certificate expires in N days! <<<` | The certificate will expire within 30 days. | Schedule certificate renewal before expiration to avoid service disruption. |

### Trust State Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>>UNTRUSTED<<<` | The certificate chain could not be verified against the Java trust store. | The server may be using a self-signed certificate, an untrusted CA, or may be missing intermediate certificates. |
| `>>>UNKNOWN<<<` | The trust state could not be determined. | Check the scan log for details. This may indicate a problem with the trust store or certificate chain. |
| `>>>REVOKED<<<` | At least one revocation mechanism (OCSP, CRL, or OneCRL) reports the certificate as revoked. | The certificate has been invalidated by its issuing CA. Stop using it and obtain a new certificate. |

### OCSP Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>> Error: OCSP responder rejected unauthorized request <<<` | The OCSP responder refused the request. Common with some CAs that require specific request formatting or have rate limits. | This is often normal for intermediate/root CA certificates whose OCSP responders only accept requests for certificates they directly issued. Try again later if this affects the end-entity certificate. |
| `>>> Error: OCSP responder unreachable <<<` | The OCSP responder URL could not be contacted. | Check network connectivity. The responder may be temporarily down, or a firewall may be blocking the request. |
| `>>> Error: Invalid OCSP response <<<` | The OCSP responder returned a malformed or unexpected response. | This may indicate a misconfigured OCSP responder on the CA side. |
| `NOT CHECKED (...)` | OCSP checking was skipped, with the reason in parentheses. | The certificate may not include an OCSP responder URL (Authority Information Access extension), or the responder could not be reached. |
| `>>>REVOKED<<<` (OCSP Status) | The OCSP responder confirmed the certificate is revoked. | The CA has revoked this certificate. It should no longer be used. |

### OCSP Stapling Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>> WARNING: Must-Staple set but no OCSP stapling response! <<<` | The certificate includes the Must-Staple extension (RFC 7633) but the server did not provide a stapled OCSP response. | Configure the server to enable OCSP stapling. Browsers that enforce Must-Staple will reject connections without a stapled response. |

### CRL Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>> Error: CRL download timeout <<<` | The CRL distribution point did not respond in time. | The CRL file may be very large or the server may be slow. Check network connectivity. |
| `>>> Error: Invalid CRL format <<<` | The downloaded CRL could not be parsed. | This may indicate a misconfigured CRL distribution point on the CA side. |
| `NOT CHECKED (...)` | CRL checking was skipped, with the reason in parentheses. | The certificate may not include a CRL Distribution Points extension. |
| `>>>REVOKED<<<` (CRL Status) | The certificate serial number was found in the CRL. | The CA has revoked this certificate. |

### OneCRL Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>>FOUND IN OneCRL<<<` | The certificate appears in Mozilla's centralized revocation list (OneCRL). | This is a critical finding — Mozilla has explicitly revoked trust in this certificate. |
| `NOT CHECKED` | OneCRL lookup was not performed. | The OneCRL list may not have been available for download. |

### Certificate Transparency (SCT) Errors

| Message | Cause | Action |
|---------|-------|--------|
| `>>> WARNING: CT log is retired <<<` | The CT log that signed the SCT has been retired and is no longer operated. | The SCT is still valid but the log is no longer accepting new submissions. Newer certificates should use active logs. |
| `>>> WARNING: CT log is rejected <<<` | The CT log has been rejected by browser trust programs. | SCTs from rejected logs may not satisfy CT requirements. The certificate should have SCTs from trusted logs. |
| `>>> WARNING: SCT signature verification FAILED <<<` | The cryptographic signature on the SCT did not verify against the CT log's public key. | This is a serious finding — the SCT may be forged or corrupted. Investigate whether the certificate was legitimately logged. |
| `>>>INVALID<<<` (Signature) | Same as above — the SCT signature is invalid. | See above. |
| `NOT VERIFIED (unknown log)` | The SCT references a CT log not found in the known CT log list. | The log may be new, private, or the CT log list may be outdated. |
| `NOT VERIFIED (issuer certificate unavailable)` | SCT signature verification requires the issuer certificate, which was not available. | The server may not be sending the full certificate chain. |
| `NOT VERIFIED (key error)` | The CT log's public key could not be loaded for verification. | The CT log list entry may have an invalid or unsupported key format. |
| `NOT VERIFIED (unsupported algorithm)` | The SCT uses a signature algorithm not supported by the verifier. | This is uncommon — the log may use a non-standard algorithm. |
| `NOT VERIFIED (verification error)` | A general error occurred during SCT signature verification. | Check the scan log for detailed error information. |
| `Unknown CT Log` | The CT log ID in the SCT does not match any known log. | The log may have been removed from the public log list or may be a test/private log. |
| `Note 1: TLS Extension SCTs not available, FUTURE` | TLS extension-delivered SCTs are not yet supported by the scanner. | This is an informational note, not an error. Embedded and OCSP staple SCTs are still checked. |

### Security Headers Warnings

| Message | Cause | Action |
|---------|-------|--------|
| `>>>MISSING<<<` | A recommended security response header is not present. | Configure the web server to send the missing header. See OWASP Secure Headers Project for recommended values. |

### TLS Fingerprint Warnings

| Message | Cause | Action |
|---------|-------|--------|
| `>>> WARNING: All probes failed - server may not support TLS <<<` | None of the 10 TLS probe handshakes succeeded. | The server may not support TLS, may be behind a firewall that blocks probes, or may only support unusual configurations. |
| `NOT AVAILABLE` | The fingerprint could not be generated. | The server may not have been reachable during the fingerprint phase. Check network connectivity. |
| `FAIL` (Probe status) | An individual probe handshake did not complete. | This is normal — not all servers support all probe configurations (e.g., a TLS 1.3-only server will fail TLS 1.1 probes). |

### Risk Assessment Warnings

| Message | Cause | Action |
|---------|-------|--------|
| `>>> -N pts [SEVERITY] description <<<` | Points were deducted from the risk score for a specific finding. | Review the deduction description and severity. HIGH and CRITICAL deductions should be addressed. |
| `>>> -3 pts [LOW] Certificate covers 2-5 SANs (minor attack surface disclosure) <<<` | The certificate lists 2–5 Subject Alternative Names, mildly disclosing hosted services. | Consider using separate certificates per service if confidentiality of infrastructure names is a concern. |
| `>>> -8 pts [MEDIUM] Certificate covers 6-20 SANs (moderate attack surface disclosure) <<<` | The certificate lists 6–20 SANs, revealing a moderate amount of the organization's hosting infrastructure. | Evaluate whether a wildcard certificate or per-service certificates would reduce unnecessary exposure. |
| `>>> -15 pts [HIGH] Certificate covers 21+ SANs (significant attack surface disclosure) <<<` | The certificate lists 21 or more SANs, significantly exposing the organization's attack surface to passive reconnaissance. | Strongly consider splitting services across multiple certificates or using wildcard certificates to reduce information leakage. |

### General Errors

| Message | Cause | Action |
|---------|-------|--------|
| `Error=...` | An unexpected exception occurred during a report section. | Check the scan log at `~/DeepVioletTools/ui/scanlog.log` for the full stack trace. Common causes include network timeouts, DNS resolution failures, and TLS handshake errors. |
| `Problem fetching host cipher suites. See log for details.` | The cipher suite enumeration failed, typically because the host interfaces could not be resolved. | Verify the target URL is correct and the server is reachable. Check the scan log for details. |
| `Error writing certificate to disk. msg=...` | The PEM certificate export failed. | Check that the target directory exists and is writable. |

### Common Scenarios

**Self-signed certificate scan:**
Expect `>>>UNTRUSTED<<<` trust state, `NOT CHECKED` for OCSP/CRL (no responder URLs), and possible OCSP "unauthorized request" errors for chain certificates.

**Expired certificate scan:**
Expect `>>>EXPIRED<<<` validity check, expiration warnings, and potentially degraded OCSP responses since some responders stop serving status for expired certificates.

**Server behind CDN/load balancer:**
TLS fingerprint results may vary between scans if the CDN routes to different backend servers. OCSP stapling behavior may also differ.

**Corporate proxy or firewall:**
OCSP responder and CRL download errors are common when outbound HTTP is blocked. CT log list download may also fail, resulting in `Unknown CT Log` entries.

## API Integration

DeepVioletTools is built on the [DeepViolet API](https://github.com/spoofzu/DeepViolet/) (5.1.18-SNAPSHOT). Developers can integrate the API directly into Java applications.

### Basic Scanning

```java
// Initialize a session (captures negotiated protocol, cipher suite, OCSP stapling)
URL url = new URL("https://example.com/");
ISession session = DeepVioletFactory.initializeSession(url);

// Create an engine
IEngine engine = DeepVioletFactory.getEngine(session, CIPHER_NAME_CONVENTION.IANA);

// Get cipher suites
ICipherSuite[] ciphers = engine.getCipherSuites();
for (ICipherSuite cipher : ciphers) {
    System.out.println(cipher.getSuiteName() + " - " + cipher.getStrengthEvaluation());
}

// Get server certificate with full details
IX509Certificate cert = engine.getCertificate();
System.out.println("Subject: " + cert.getSubjectDN());
System.out.println("Valid: " + cert.getValidityState());
System.out.println("Key: " + cert.getPublicKeyAlgorithm() + " " + cert.getPublicKeySize() + " bits");
System.out.println("Expires in: " + cert.getDaysUntilExpiration() + " days");
System.out.println("SANs: " + cert.getSubjectAlternativeNames());
```

### Risk Scoring

```java
// Risk scoring with default system rules (65 rules, 7 categories)
IRiskScore score = engine.getRiskScore();
System.out.println("Score: " + score.getTotalScore() + "/100");
System.out.println("Grade: " + score.getLetterGrade());
System.out.println("Risk: " + score.getRiskLevel());

// Per-category breakdown
for (IRiskScore.ICategoryScore cat : score.getCategoryScores()) {
    System.out.println(cat.getCategory() + ": " + cat.getScore() + "/" + cat.getMaxScore());
}

// Risk scoring with user-defined rules merged with system rules
IRiskScore customScore = engine.getRiskScore(new FileInputStream("my-rules.yaml"));
```

### Revocation and Certificate Transparency

```java
// Per-certificate revocation status
IRevocationStatus revStatus = cert.getRevocationStatus();
System.out.println("OCSP: " + revStatus.getOcspStatus());
System.out.println("CRL: " + revStatus.getCrlStatus());
System.out.println("OneCRL: " + revStatus.getOneCrlStatus());
System.out.println("OCSP Stapling: " + revStatus.isOcspStaplingPresent());
System.out.println("Must-Staple: " + revStatus.isMustStaplePresent());
System.out.println("Embedded SCTs: " + revStatus.getEmbeddedSctCount());
```

### TLS Fingerprinting and DNS Security

```java
// JARM-inspired TLS fingerprint (10 probes)
String fingerprint = engine.getTlsFingerprint();
System.out.println("Fingerprint: " + fingerprint);

// DNS security checks
IDnsStatus dns = engine.getDnsStatus();
System.out.println("CAA records: " + dns.hasCaaRecords());
System.out.println("DANE/TLSA records: " + dns.hasTlsaRecords());

// Fallback SCSV (RFC 7507)
Boolean fallbackScsv = engine.getFallbackScsvSupported();
System.out.println("Fallback SCSV: " + fallbackScsv);
```

### Custom Cipher Map

```java
// Replace the built-in cipher map with a custom YAML definition
DeepVioletFactory.loadCipherMap(new FileInputStream("custom-ciphers.yaml"));

// Restore the default cipher map
DeepVioletFactory.resetCipherMap();
```

### Protocol Filtering

```java
// Restrict which TLS versions are probed
Set<Integer> protocols = Set.of(0x0303, 0x0304); // TLS 1.2 and 1.3 only
IEngine engine = DeepVioletFactory.getEngine(session, CIPHER_NAME_CONVENTION.IANA, task, protocols);
```

### Multi-Target Scanning (API-Level)

The DeepViolet API includes a multi-target scanning framework using Java 21 virtual threads:

```java
// Configure a multi-target scan
ScanConfig config = new ScanConfig.Builder()
        .targets(List.of("github.com", "google.com", "example.com"))
        .threadCount(5)
        .perHostTimeoutMs(60000)
        .sectionDelayMs(200)
        .cipherNameConvention(CIPHER_NAME_CONVENTION.IANA)
        .listener(new IScanListener() {
            public void onHostStarted(String host) { System.out.println("Started: " + host); }
            public void onHostCompleted(String host, IScanResult result) {
                IRiskScore score = result.getEngine().getRiskScore();
                System.out.println(host + ": " + score.getLetterGrade());
            }
            public void onScanCompleted() { System.out.println("Done!"); }
            // ... other callbacks
        })
        .build();

// Run the multi-target scan
TlsScanner scanner = new TlsScanner(config);
IScanMonitor monitor = scanner.scan();

// Poll progress
while (monitor.isRunning()) {
    System.out.printf("Progress: %d/%d hosts, %d active threads%n",
            monitor.getCompletedHostCount(), monitor.getTotalHostCount(),
            monitor.getActiveThreadCount());
    Thread.sleep(1000);
}
```

### Key Public Interfaces

| Interface | Description |
|-----------|-------------|
| `IEngine` | Main scanning engine — cipher suites, certificates, fingerprinting, risk scoring, DNS security |
| `IX509Certificate` | Certificate details — subject, validity, public key, SANs, revocation status |
| `ISession` | TLS session — negotiated protocol/cipher, OCSP stapling, session properties |
| `IRiskScore` | Risk score result — total score, grade, risk level, per-category breakdowns |
| `IRevocationStatus` | Per-certificate revocation — OCSP, CRL, OneCRL, stapling, Must-Staple, SCTs |
| `IDnsStatus` | DNS security — CAA and DANE/TLSA record presence |
| `DeepVioletFactory` | Factory methods — session initialization, engine creation, cipher map management |
| `TlsScanner` | Multi-target scan orchestrator — virtual-thread concurrency, configurable timeouts |
| `ScanConfig` | Multi-target configuration builder — targets, threads, timeouts, listeners |
| `IScanResult` | Per-host scan result — session and engine references for post-scan analysis |
| `IScanMonitor` | Scan progress monitor — thread counts, host progress, running state |
| `IScanListener` | Scan event callbacks — host started/completed, section progress, scan completed |

For more examples, see the [DeepViolet API samples](https://github.com/spoofzu/DeepViolet/tree/master/src/main/java/com/mps/deepviolet/samples).

## Building from Source

### Prerequisites

- JDK 21 or later
- Apache Maven 3.6.3 or later

### Build Steps

```bash
# Clone the repository
git clone https://github.com/spoofzu/DeepVioletTools.git
cd DeepVioletTools

# Build with Maven
mvn clean package

# The JAR files are created in the target directory
ls target/*.jar
# dvui.jar - GUI application
# dvcli.jar - Command line tool
```

### Running Tests

```bash
mvn test
```

## Project Structure

```
DeepVioletTools/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   ├── com/mps/deepviolettools/
│   │   │   │   ├── bin/          # Entry points (StartUI, StartCMD)
│   │   │   │   ├── job/          # Background scan tasks
│   │   │   │   ├── model/        # Data model (ScanNode tree)
│   │   │   │   ├── ui/           # GUI components (MainFrm, dialogs)
│   │   │   │   └── util/         # Utilities (preferences, logging, AI, export)
│   │   │   └── org/ms/terminal/gui/  # Terminal emulation library (AI chat UI)
│   │   └── resources/
│   │       ├── deepviolet-logo.png
│   │       ├── interface-help.html
│   │       └── logback.xml
│   └── test/java/                # JUnit 5 + Mockito tests
├── docs/                         # Documentation
├── .github/workflows/            # GitHub Actions CI/CD
├── pom.xml                       # Maven configuration
└── README.md
```

## Configuration

GUI preferences are stored in `~/DeepVioletTools/deepviolet.properties`. This file is created automatically on first use and updated when you change settings. It contains:

- **Theme settings** — report font, report colors, hard wrap options, application font, application colors
- **Engine settings** — report section toggles, cipher naming convention, protocol version selections
- **AI settings** — provider, API key (encrypted with AES-GCM), model, endpoint URL, max tokens, temperature, report system prompt, chat system prompt, terminal colors, AI enabled state
- **Window state** — position and size
- **URL history** — last 5 scanned URLs (shown in the Test Servers dialog)
- **Save preferences** — last export folder and format

API keys are never stored in plaintext. An AES-GCM encryption seed is generated on first run and used to encrypt/decrypt API keys in the properties file.

All settings are loaded on application startup and saved when changed through the GUI. The CLI tool reads the same properties file for shared settings (e.g., AI configuration, URL history) but uses its own command-line flags for section selection and does not modify engine settings. CLI AI options (`--ai-key`, `--ai-provider`, etc.) override saved preferences for that invocation.

## Logging

DeepVioletTools uses Logback for logging. Logs are written to:
- Console output
- `~/DeepVioletTools/ui/scanlog.log` — scan activity and errors (rolling file, 3 MB, 3 backups)
- `~/DeepVioletTools/ui/aichat.log` — AI Assistant chat history (rolling file, 3 MB, 3 backups)

Enable debug logging with the `-d2` flag or by modifying `logback.xml`. The logback configuration is copied to `~/DeepVioletTools/ui/logback.xml` on first run and can be customized there.

## Acknowledgements

This project implements ideas, code, and takes inspiration from:

- [Qualys SSL Labs](https://www.ssllabs.com/) and Ivan Ristić
- [OpenSSL](https://www.openssl.org/)
- Oracle's Java Security Team
- Thomas Pornin (TLS handshake and cipher suite handling examples)

## License

DeepVioletTools is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

---

*This project leverages the works of other open source community projects and is provided for educational purposes. Use at your own risk.*
