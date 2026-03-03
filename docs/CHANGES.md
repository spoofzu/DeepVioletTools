# Changes from Upstream

The upstream repository (github.com/spoofzu/DeepVioletTools) last received meaningful updates in **July 2019**. The local repository represents a major modernization effort.

**Upstream:** Basic Swing GUI + CLI, Java 8, text-only output, no settings persistence.
**Local:** Modern 3-tab GUI, enhanced CLI with multi-target mode, AI integration, multi-format export, comprehensive settings.

For changes to the underlying DeepViolet API, see the [DeepViolet CHANGES](https://github.com/spoofzu/DeepViolet/blob/master/docs/CHANGES.md).

---

### 1. Multi-Target Scanning System (new)
- **GUI:** Scan tab with multi-line targets area, Load File / Scan / Save buttons, per-worker status bar
- **CLI:** `--scan`, `--scan-file`, `--scan-threads` (1-10), `--scan-throttle` (ms delay)
- `TargetParser` expands hostnames, IPs, URLs, CIDR blocks (`10.0.1.0/24`), and dash ranges (`10.0.2.1-50`)
- `ScanTask` orchestrates concurrent multi-threaded scanning with per-worker progress tracking
- Auto-saves individual host reports with timestamps

### 2. Heat Map Visualization (new)
- Custom `HeatMapPanel` renders color-coded grids for scan results
- 7 dimensions: Risk, Cipher Suites, Security Headers, Connection, HTTP Response, Revocation, TLS Fingerprint
- Cell color interpolation based on pass/fail/inconclusive ratios
- Smart scaling for varying host counts; error detection with "E" suffix markers
- CLI text-based heat map output for terminal environments

### 3. AI Assistant Integration (new)
- **GUI:** Terminal-style chat tab with scan selector, streaming responses, animated processing indicator
- Three provider backends: **Anthropic** (Claude), **OpenAI** (GPT-4o), **Ollama** (local models with dynamic discovery)
- Conversational Q&A about scan results
- `--ai` CLI flag for automated AI evaluation section in reports
- Configurable system prompts for report analysis and chat
- AES-GCM encrypted API key storage

### 4. Multi-Format Report Export (new)
- `ReportExporter` supports **Text**, **HTML** (themed/styled), **PDF** (OpenPDF with colors), **JSON** (Gson)
- CLI: `-o file.pdf` auto-infers format from extension; `-f format` for explicit override
- GUI: Save dialog with format selection

### 5. Hierarchical Scan Node Model (new)
- `ScanNode` tree replaces flat StringBuffer output
- 8 node types (ROOT, SECTION, SUBSECTION, KEY_VALUE, NOTICE, WARNING, CONTENT, BLANK)
- Thread-safe `CopyOnWriteArrayList`; visitor pattern via `walkVisible()` for rendering

### 6. Settings Dialog (new — `FontChooserDialog`)
- **Reporting tab:** Two sub-tabs:
  - **Host Detail** — Font, 12 color controls, hard-wrap, theme presets (Dark/Light/System), live preview
  - **Cards** — Card font/colors, interactive grid-based card layout editor with palette, grid, controls, and live card preview
- **Engine tab:** 11 section toggles, cipher naming convention (IANA/OpenSSL/GnuTLS/NSS), protocol versions (SSLv3, TLS 1.0-1.3)
- **AI tab:** Provider/model/key config, system prompts, 9 terminal color controls
- **Application tab:** App-wide font, accent color, risk scale slider

### 6a. Card Layout Editor (new)
- **`CardGridEditor`** — Interactive grid editor with drag-and-drop element placement, Shift+click cell alignment (3×3 regions), drag-to-span multi-cell spanning, right-click context menu (remove, reset span), and grid line dragging to resize cell proportions
- **`CardMetaPalette`** — Draggable palette of 9 metadata elements (Grade, Score, Hostname, IP, TLS Version, Ciphers, Headers, Cert, Risk Bars)
- **`CardTrashPanel`** — Grid dimension spinners (Cols 1–5, Rows 2–9), circular-arrow reset button, and trash can drop target
- **`CardLayoutPreview`** — Live card preview using sample data with `CardRenderer`, updates in real time during all editing operations
- **`CardRenderer`** — Shared rendering engine for host cards with span-aware cell bounds
- **`CardSlotConfig`** — Element placement model with colSpan/rowSpan support and 7-field serialization (backward compatible with 5-field and legacy 4-field formats)
- **`CardLayout`** — Span-aware grid layout model with `getSlotAt()` covering span rectangles

### 7. Comprehensive Preferences System (new — `FontPreferences`)
- All settings persisted to `~/DeepVioletTools/deepviolet.properties`
- Covers: engine booleans, reporting colors/fonts, AI config, scan settings, window bounds, URL history
- AES-GCM encryption for API keys with automatic seed management

### 8. Modern UI / Look & Feel
- **FlatLaf 3.7** replaces default Swing L&F
- macOS dark/light mode auto-detection (`apple.awt.application.appearance`)
- Accent color support with theme-aware component coloring
- Window bounds persistence (saved on exit, restored on launch)

### 9. Test Servers Dialog (new)
- Recent scans list (last 5 URLs) + pre-configured badssl.com test servers table
- Double-click auto-populates host field and triggers scan

### 10. Enhanced CLI Options
- Protocol filtering: `--proto-sslv3`, `--proto-tls10`, `--proto-tls11`, `--proto-tls12`, `--proto-tls13`
- AI flags: `--ai`, `--ai-provider`, `--ai-model`, `--ai-key` (or `DV_AI_API_KEY` env var), `--ai-endpoint`
- Scan flags: `--scan`, `--scan-file`, `--scan-threads`, `--scan-throttle`
- Report format: `-f txt|html|pdf|json`, `-o <file>` with format auto-detection

### 11. CT Log Verification (new)
- `CTLogLookup` downloads/caches Google's CT log list for log operator identification
- `SctVerifier` verifies SCT signatures per RFC 6962

### 12. CI/CD Pipelines (new)
- **build.yml:** Matrix build on Java 21 + 24, uploads JARs as artifacts, smoke-tests CLI
- **release.yml:** Tag-triggered (`v*`) release with auto-generated notes and JAR attachments

### 13. Logging Overhaul
- Dual loggers: `scanlog` + `aichat` (separate log files)
- User-customizable `logback.xml` copied to `~/DeepVioletTools/ui/`
- Stale config detection and auto-upgrade

### 14. Documentation
- `docs/DeepVioletTools.md` — 44KB comprehensive user guide
- `docs/DeepViolet.md` — consolidated project wiki
- Updated README with all new features
- `CLAUDE.md` — architecture guide for AI-assisted development
- Screenshot assets in `media/`

### 15. Delta Scanning (new)
- Compare two saved `.dvscan` scan files to identify changes over time
- **`DeltaScanner`** — engine that diffs two scans, producing per-section deltas (risk, ciphers, security headers, connection, HTTP response, fingerprint)
- **`DeltaScanDialog`** — GUI dialog for selecting base and target scans
- Delta models: `DeltaScanResult`, `HostDelta`, `RiskDelta`, `CipherDelta`, `MapDelta`, `FingerprintDelta`, `DeltaDirection`, `DeltaHeatMapBuilder`
- CLI: `--delta base.dvscan,target.dvscan` flag
- `DeltaResultsPanel` and `DeltaCard` for GUI results display

### 16. API Validation Tool (new)
- **`--validate <host>`** CLI option compares DV API scan results against openssl field-by-field in real-time
- 17 fields compared: subjectDN, issuerDN, serialNumber, version, signingAlgorithm, publicKeyAlgorithm, publicKeySize, publicKeyCurve, notValidBefore, notValidAfter, isSelfSigned, sanCount, fingerprint, negotiatedProtocol, negotiatedCipher, chainLength, ocspStapling
- `FieldNormalizer` handles cross-tool differences: key algorithm mapping (rsaEncryption→RSA), ECDSA signing algorithm normalization, DN ordering, hex serial formatting, date format parsing, EC curve name mapping
- For bad-cert servers (expired, self-signed): DV session fails correctly, openssl shows why, result is PASS
- JSON output via `-f json`; exit code 0 on match, 1 on mismatch
- Also available as standalone JAR via `mvn package -Pvalidate` in the DeepViolet project (`dvvalidate.jar`)

### 17. Interface Help as HTML Resource
- Extracted ~600-line HTML help content from `InterfaceHelpDialog.java` into `src/main/resources/interface-help.html`
- HTML template uses `{{PLACEHOLDER}}` tokens for 8 dynamic CSS values (colors, fonts) substituted at runtime
- Help content is now a standalone HTML file that can be opened in any browser for inspection and editing

---

## DeepViolet API Changes (5.1.17 → 5.1.18)

The underlying [DeepViolet API](https://github.com/spoofzu/DeepViolet/) has been substantially upgraded. These API improvements power new capabilities in DeepVioletTools.

For the full API changelog, see the [DeepViolet CHANGES](https://github.com/spoofzu/DeepViolet/blob/master/docs/CHANGES.md).

### New Public Interfaces

- **`IRiskScore`** — Risk score result with total score (0–100), letter grade (A+ through F), risk level, per-category breakdowns, deductions, and scoring diagnostics. Supports 7 scoring categories: Protocols, Cipher Suites, Certificate, Revocation, Security Headers, DNS Security, and Other.
- **`IRevocationStatus`** — Comprehensive per-certificate revocation status covering OCSP, CRL, OCSP Stapling, Must-Staple, OneCRL, and Certificate Transparency SCTs (embedded, TLS extension, and OCSP staple sources).
- **`IDnsStatus`** — DNS security status: CAA record presence and DANE/TLSA record presence.
- **`IScanResult`** — Per-host scan result providing access to the `ISession` and `IEngine` for post-scan analysis.
- **`IScanMonitor`** — Pollable progress monitor for scans: active/sleeping/idle thread counts, completed host count, per-thread status.
- **`IScanListener`** — Event callback interface for scan lifecycle: `onHostStarted()`, `onSectionStarted()`, `onSectionCompleted()`, `onHostCompleted()`, `onScanCompleted()`, `onHostStatus()`.
- **`IThreadStatus`** — Per-thread status during scanning: thread name, state (EXECUTING/SLEEPING/IDLE), current host URL, current scan section, status message.

### Scanning Infrastructure (new)

The API now includes a complete multi-host scanning framework using Java 21 virtual threads:

- **`TlsScanner`** — Orchestrates concurrent multi-host scanning using `newVirtualThreadPerTaskExecutor()` with semaphore-based concurrency control (default 10 threads). Supports configurable per-host timeout (default 60s), inter-section delay (default 200ms), and both polling (`IScanMonitor`) and callback (`IScanListener`) progress tracking.
- **`ScanConfig`** — Builder-pattern configuration for scans: target list, thread count, per-host timeout, section delay, cipher naming convention, enabled protocols, scan section selection, and listener registration.
- **`ScanResult`** — Per-host result containing session and engine references for post-scan analysis (risk scores, cipher suites, certificates, fingerprints, etc.).
- **`ScanMonitor`** — Real-time progress monitor with `getActiveThreadCount()`, `getSleepingThreadCount()`, `getIdleThreadCount()`, `getCompletedHostCount()`, `getTotalHostCount()`, `isRunning()`, and `getThreadStatuses()`.
- **`ThreadState`** — Thread state enum: `EXECUTING`, `SLEEPING`, `IDLE`.
- **`ThreadStatus`** — Per-thread status tracking: thread name, state, current host, current section, status message.
- **`ScanSection`** — Scan phase enum defining the scan sections: `RISK_SCORING`, `CIPHER_ENUMERATION`, `CERTIFICATE_RETRIEVAL`, `REVOCATION_CHECK`, `DNS_SECURITY`, `SESSION_INIT`, `TLS_FINGERPRINT`.
- **`TargetSpec`** — API-level target parsing supporting hostnames, IPv4/IPv6 addresses, CIDR blocks, and IP ranges.

### New IEngine Methods (9)

| Method | Description |
|--------|-------------|
| `getTlsFingerprint()` | JARM-inspired 10-probe TLS server fingerprint |
| `getSCTs()` | Signed Certificate Timestamps from all 3 delivery methods |
| `getTlsMetadata()` | Raw TLS handshake metadata (ServerHello extensions, certificates) |
| `getFallbackScsvSupported()` | RFC 7507 Fallback SCSV detection |
| `getDnsStatus()` | DNS security checks (CAA and DANE/TLSA records) |
| `getRiskScore()` | Risk scoring with default system rules |
| `getRiskScore(String)` | Risk scoring with custom YAML rules file |
| `getRiskScore(InputStream)` | Risk scoring with user rules merged with system rules |

### New IX509Certificate Methods (6)

| Method | Description |
|--------|-------------|
| `getPublicKeyAlgorithm()` | RSA, EC, DSA, etc. |
| `getPublicKeySize()` | Key size in bits |
| `getPublicKeyCurve()` | EC curve name (e.g., secp256r1), null for non-EC |
| `getDaysUntilExpiration()` | Days until expiry (negative if expired) |
| `getSubjectAlternativeNames()` | DNS names, IPs, emails, URIs |
| `getRevocationStatus()` | Full revocation status per certificate |

### New ISession Features

- `NEGOTIATED_PROTOCOL` and `NEGOTIATED_CIPHER_SUITE` session properties
- `getStapledOcspResponse()` — OCSP stapled response captured during TLS handshake

### New DeepVioletFactory Methods

- `getEngine()` overload with `Set<Integer> enabledProtocols` for protocol version filtering
- `loadCipherMap(InputStream)` — replace the built-in cipher map at runtime
- `resetCipherMap()` — restore the default cipher map

### New Internal Packages

- **`tls/`** (10 classes) — Custom raw TLS socket: configurable ClientHello, ServerHello parsing, extension extraction, key exchange analysis, GREASE detection
- **`fingerprint/`** (2 classes) — JARM-inspired TLS fingerprinting with 10 probes
- **`scoring/`** (12 classes) — YAML-driven risk scoring engine with custom expression DSL, user rule merging, and grade/severity mapping
- **`util/`** additions (4 classes) — Pure Java replacements for Bouncy Castle: `DerParser`, `OcspClient`, `X509Extensions`, `ECCurveNames`

### Configuration Resources

- **`risk-scoring-rules.yaml`** — 65 rules across 7 categories with severity mapping, grade mapping, and expression-based conditions
- **`ciphermap.yaml`** — 338 cipher suites with IANA/OpenSSL/GnuTLS/NSS names and strength ratings (replaces `ciphermap.json`)

### Removed / Breaking

- **`VULNERABILITY_ASSESSMENTS` enum removed** from `ISession` — replaced by `IEngine.getRiskScore()` YAML-driven scoring
- **Bouncy Castle dependency removed** — all ASN.1/extension parsing replaced with pure Java implementations
- **`ciphermap.json` deleted** — replaced by `ciphermap.yaml`
- **Java 21+ required** (upgraded from Java 8)
- **JUnit 4 → JUnit 5**, **Mockito 3 → 5**

### Quality

- 21 test classes, 324 test methods (up from ~4 classes)
- 7 sample programs (up from 2)
- Javadoc fixes across all public interfaces (typo corrections, stale reference cleanup)

---

## Summary

| Category | # | Details |
|----------|---|---------|
| Multi-Target Operations | 2 | Multi-target scanning, heat map visualization |
| AI Integration | 1 | 3 providers, chat + automated evaluation |
| Export & Reporting | 2 | Multi-format export, hierarchical scan node model |
| UI Modernization | 5 | FlatLaf, settings dialog, card layout editor, test servers, preferences |
| CLI Enhancement | 2 | Protocol/AI/scan/format flags, API validation tool |
| Delta Scanning | 1 | Compare saved scans over time, delta models, GUI + CLI |
| Infrastructure | 4 | CI/CD, logging, CT log verification, HTML help resource |
| Documentation | 1 | Guides, architecture docs, screenshots |
| API — Scanning | 1 | Virtual-thread scanner with monitor, callbacks, target parsing |
| API — New Interfaces | 3 | Risk scoring, revocation status, DNS security |
| API — New Methods | 3 | IEngine (9), IX509Certificate (6), DeepVioletFactory (3) |
| API — Infrastructure | 3 | Fingerprinting, Bouncy Castle removal, YAML configs |

**Total: 28 significant improvements** (18 in DeepVioletTools + 10 categories of API enhancements) transforming a basic 2019-era reference tool into a comprehensive, production-ready TLS security analysis suite.
