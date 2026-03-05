package com.mps.deepviolettools.job;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.mps.deepviolettools.util.FontPreferences;

import com.mps.deepviolet.api.BackgroundTask;
import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IHost;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;
import com.mps.deepviolet.api.ISession.SESSION_PROPERTIES;
import com.mps.deepviolet.api.IRevocationStatus;
import com.mps.deepviolet.api.IX509Certificate;
import com.mps.deepviolet.api.IX509Certificate.ValidState;
import com.mps.deepviolet.api.tls.ClientHelloConfig;
import com.mps.deepviolet.api.scoring.rules.RuleContext;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint;
import com.mps.deepviolettools.model.ScanNode;
import com.mps.deepviolettools.util.AiAnalysisService;
import com.mps.deepviolettools.util.CTLogLookup;
import com.mps.deepviolettools.util.SctVerifier;

/**
 * Coordinates the order and execution of scan tasks.
 * Builds a hierarchical {@link ScanNode} tree instead of flat text.
 *
 * @author Milton Smith
 */
public class UIBackgroundScanTask extends BackgroundTask {

	/** Per-section outcome status, ordered by severity for ordinal comparison. */
	private enum SectionStatus { SUCCESS, INCONCLUSIVE, ERROR, CANCELLED }

	/** Records the outcome of a single report section. */
	private record SectionOutcome(String name, SectionStatus status, String evidence) {}

	/** Report format version, incremented when fields are added/renamed/removed. */
	public static final String REPORT_VERSION = "1.0";

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.job.UIBackgroundScanTask");
	private static final Logger scanlog = LoggerFactory.getLogger("scanlog");

	private final String sessionId = UUID.randomUUID().toString();
	private String hostname;
	private final LinkedHashMap<String, Long> networkTimings = new LinkedHashMap<>();
	private final LinkedHashMap<String, Long> analyticalTimings = new LinkedHashMap<>();
	private boolean scanFailed;
	private boolean scanCancelled;
	private String failureMessage;
	private final List<SectionOutcome> sectionOutcomes = new ArrayList<>();
	private volatile String lastBuildError;

	private final ScanNode root = ScanNode.createRoot();

	private IEngine eng;
	private ISession session;
	private URL url;
	private String filename;

	/**
	 * Set the filename for certificate read/write operations.
	 *
	 * @param filename path to the PEM file
	 */
	public void setFilename(String filename) {
		this.filename = filename;
	}

	public volatile boolean bRiskAssessmentSection = true;
	public volatile boolean bHeader = true;
	public volatile boolean bRuntimeEnvironmentSection = true;
	public volatile boolean bHostSection = true;
	public volatile boolean bHTTPResponseSection = true;
	public volatile boolean bConnectionSection = true;
	public volatile boolean bCipherSuiteSection = true;
	public volatile boolean bCertChainSection = true;
	public volatile boolean bSecurityHeadersSection = true;
	public volatile boolean bRevocationSection = true;
	public volatile boolean bTlsFingerprintSection = true;
	public volatile boolean bWriteCertificate = false;
	public volatile boolean bReadCertificate = false;

	public volatile boolean protocolSslv3 = false;
	public volatile boolean protocolTls10 = false;
	public volatile boolean protocolTls11 = false;
	public volatile boolean protocolTls12 = true;
	public volatile boolean protocolTls13 = true;

	private volatile CIPHER_NAME_CONVENTION cipherConvention = CIPHER_NAME_CONVENTION.IANA;
	private volatile int riskScale = 20;

	/** When true, all data capture runs regardless of section flags. */
	public volatile boolean bMultiTargetMode = false;

	public volatile boolean bAiEvaluationSection = false;
	private String aiApiKey = "";
	private String aiProvider = "Anthropic";
	private String aiModel = "claude-sonnet-4-5-20250929";
	private int aiMaxTokens = 4096;
	private double aiTemperature = AiAnalysisService.DEFAULT_TEMPERATURE;
	private String aiSystemPrompt = AiAnalysisService.DEFAULT_SYSTEM_PROMPT;
	private String aiEndpointUrl = AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT;

	/** User risk rules YAML to merge with system rules during risk scoring. */
	private volatile String userRiskRulesYaml;

	/**
	 * Set user risk rules YAML to merge with system rules during risk scoring.
	 *
	 * @param yaml the YAML content, or null to use system rules only
	 */
	public void setUserRiskRulesYaml(String yaml) {
		this.userRiskRulesYaml = yaml;
	}

	/**
	 * Set the cipher suite naming convention for this scan.
	 *
	 * @param convention the naming convention to use
	 */
	public void setCipherConvention(CIPHER_NAME_CONVENTION convention) {
		this.cipherConvention = convention;
	}

	/**
	 * Set the risk graph scale (number of blocks per bar).
	 * Higher values yield finer resolution (fewer points per block).
	 *
	 * @param scale number of blocks (10-50)
	 */
	public void setRiskScale(int scale) {
		this.riskScale = Math.max(10, Math.min(50, scale));
	}

	/**
	 * Build a set of protocol version codes from the protocol boolean flags.
	 * Returns null if all protocols are enabled (no filtering).
	 *
	 * @return set of enabled protocol version codes, or null for all
	 */
	private Set<Integer> buildEnabledProtocols() {
		// If all are enabled, return null (no filter)
		if (protocolSslv3 && protocolTls10 && protocolTls11
				&& protocolTls12 && protocolTls13) {
			return null;
		}
		Set<Integer> protocols = new HashSet<>();
		if (protocolSslv3) protocols.add(ClientHelloConfig.SSL_3_0);
		if (protocolTls10) protocols.add(ClientHelloConfig.TLS_1_0);
		if (protocolTls11) protocols.add(ClientHelloConfig.TLS_1_1);
		if (protocolTls12) protocols.add(ClientHelloConfig.TLS_1_2);
		if (protocolTls13) protocols.add(ClientHelloConfig.TLS_1_3);
		return protocols.isEmpty() ? null : protocols;
	}

	/**
	 * Set AI analysis configuration for this scan.
	 *
	 * @param apiKey       API key for the provider (ignored for Ollama)
	 * @param provider     provider name ("Anthropic", "OpenAI", or "Ollama")
	 * @param model        model identifier
	 * @param maxTokens    max response tokens
	 * @param systemPrompt system prompt for the AI
	 * @param endpointUrl  endpoint URL for Ollama (ignored for other providers)
	 */
	public void setAiConfig(String apiKey, String provider, String model,
							int maxTokens, double temperature, String systemPrompt,
							String endpointUrl) {
		this.aiApiKey = apiKey;
		this.aiProvider = provider;
		this.aiModel = model;
		this.aiMaxTokens = maxTokens;
		this.aiTemperature = temperature;
		this.aiSystemPrompt = systemPrompt;
		this.aiEndpointUrl = endpointUrl;
	}

	// Scan data capture fields
	private volatile IRiskScore lastRiskScore;
	private volatile ICipherSuite[] lastCipherSuites;
	private volatile Map<String, String> lastSecurityHeaders;
	private volatile Map<String, String> lastConnProperties;
	private volatile Map<String, String> lastHttpHeaders;
	private volatile String lastFingerprint;
	private volatile Map<String, Object> lastRuleContextMap;

	private IHost[] dvHosts;
	IX509Certificate dvCert;

	/**
	 * CTOR
	 *
	 * @param url
	 *            Target URL of TLS scan
	 * @throws DeepVioletException
	 *             thrown on host initialization problems
	 */
	public UIBackgroundScanTask(URL url) throws DeepVioletException {

		this.url = url;
		this.hostname = url.getHost();

	}

	/** @return the unique session ID for this scan */
	public String getSessionId() {
		return sessionId;
	}

	private String logPrefix() {
		return hostname + "(" + sessionId + ")";
	}

	private String formatTimings(LinkedHashMap<String, Long> timings) {
		if (timings.isEmpty()) return "(none)";
		StringBuilder sb = new StringBuilder();
		long total = 0;
		for (Map.Entry<String, Long> e : timings.entrySet()) {
			if (sb.length() > 0) sb.append(", ");
			sb.append(e.getKey()).append("=").append(e.getValue()).append("ms");
			total += e.getValue();
		}
		sb.append(", total=").append(total).append("ms");
		return sb.toString();
	}

	/**
	 * Run a single report section with cancel check, timing, error handling,
	 * and outcome recording.
	 *
	 * @param name           short section name for logging (e.g. "Risk")
	 * @param timings        map to record elapsed time into
	 * @param statusMessage  status bar message shown during execution
	 * @param section        the section method to execute
	 * @return false if cancelled (caller should return), true otherwise
	 */
	private boolean runSection(String name, LinkedHashMap<String, Long> timings,
							   String statusMessage, Runnable section) {
		if (isCancelled()) {
			scanCancelled = true;
			sectionOutcomes.add(new SectionOutcome(name, SectionStatus.CANCELLED, null));
			return false;
		}
		setStatusBarMessage(statusMessage);
		lastBuildError = null;
		long t0 = System.currentTimeMillis();
		try {
			section.run();
			long elapsed = System.currentTimeMillis() - t0;
			timings.put(name, elapsed);
			if (lastBuildError != null) {
				sectionOutcomes.add(new SectionOutcome(name, SectionStatus.ERROR, lastBuildError));
			} else {
				sectionOutcomes.add(new SectionOutcome(name, SectionStatus.SUCCESS, null));
			}
		} catch (Exception e) {
			long elapsed = System.currentTimeMillis() - t0;
			timings.put(name, elapsed);
			sectionOutcomes.add(new SectionOutcome(name, SectionStatus.ERROR, e.getMessage()));
			logger.error("Section {} failed", name, e);
		}
		return true;
	}

	/**
	 * Upgrade the last recorded section outcome to the given status with evidence,
	 * but only if the new status is more severe (higher ordinal).
	 */
	private void upgradeLastOutcome(SectionStatus newStatus, String evidence) {
		if (sectionOutcomes.isEmpty()) return;
		int lastIdx = sectionOutcomes.size() - 1;
		SectionOutcome last = sectionOutcomes.get(lastIdx);
		if (newStatus.ordinal() > last.status().ordinal()) {
			sectionOutcomes.set(lastIdx, new SectionOutcome(last.name(), newStatus, evidence));
		}
	}

	/**
	 * Format section outcome counts for log output.
	 * e.g. "[8 success, 1 inconclusive, 0 error, 0 cancelled]"
	 */
	private String formatSectionCounts() {
		int success = 0, inconclusive = 0, error = 0, cancelled = 0;
		for (SectionOutcome o : sectionOutcomes) {
			switch (o.status()) {
				case SUCCESS -> success++;
				case INCONCLUSIVE -> inconclusive++;
				case ERROR -> error++;
				case CANCELLED -> cancelled++;
			}
		}
		return "[" + success + " success, " + inconclusive + " inconclusive, "
				+ error + " error, " + cancelled + " cancelled]";
	}

	/**
	 * Format evidence strings for non-success sections.
	 * Returns null if all sections are successful.
	 */
	private String formatEvidence() {
		StringBuilder sb = new StringBuilder();
		for (SectionOutcome o : sectionOutcomes) {
			if (o.status() != SectionStatus.SUCCESS && o.evidence() != null) {
				if (sb.length() > 0) sb.append("; ");
				sb.append(o.name()).append("[").append(o.status().name().toLowerCase())
						.append("] ").append(o.evidence());
			}
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	/**
	 * Check if the risk assessment produced any inconclusive deductions
	 * and upgrade the last outcome accordingly.
	 */
	private void checkRiskInconclusive() {
		if (lastRiskScore == null) return;
		StringBuilder evidence = new StringBuilder();
		for (ICategoryScore cat : lastRiskScore.getCategoryScores()) {
			for (IDeduction d : cat.getDeductions()) {
				if (d.isInconclusive()) {
					if (evidence.length() > 0) evidence.append("; ");
					evidence.append(d.getRuleId()).append(": ").append(d.getDescription());
				}
			}
		}
		if (evidence.length() > 0) {
			upgradeLastOutcome(SectionStatus.INCONCLUSIVE, evidence.toString());
		}
	}

	/**
	 * Check if any revocation check produced errors and upgrade the last outcome.
	 */
	private void checkRevocationErrors() {
		if (dvCert == null) return;
		try {
			IRevocationStatus rev = dvCert.getRevocationStatus();
			if (rev == null) return;
			StringBuilder evidence = new StringBuilder();
			if (rev.getOcspErrorMessage() != null) {
				evidence.append("OCSP: ").append(rev.getOcspErrorMessage());
			}
			if (rev.getCrlErrorMessage() != null) {
				if (evidence.length() > 0) evidence.append("; ");
				evidence.append("CRL: ").append(rev.getCrlErrorMessage());
			}
			if (rev.getOneCrlErrorMessage() != null) {
				if (evidence.length() > 0) evidence.append("; ");
				evidence.append("OneCRL: ").append(rev.getOneCrlErrorMessage());
			}
			if (evidence.length() > 0) {
				upgradeLastOutcome(SectionStatus.INCONCLUSIVE, evidence.toString());
			}
		} catch (Exception e) {
			logger.debug("Could not check revocation errors for evidence", e);
		}
	}

	/**
	 * Check if the TLS fingerprint is null or indicates no TLS support,
	 * and upgrade the last outcome to inconclusive.
	 */
	private void checkFingerprintInconclusive() {
		if (lastFingerprint == null) {
			upgradeLastOutcome(SectionStatus.INCONCLUSIVE, "fingerprint not available");
		} else if (TlsServerFingerprint.isNoTlsSupport(lastFingerprint)) {
			upgradeLastOutcome(SectionStatus.INCONCLUSIVE, "all probes failed, no TLS support");
		}
	}

	private String determineStatus() {
		boolean hasError = false;
		boolean hasInconclusive = false;
		for (SectionOutcome o : sectionOutcomes) {
			switch (o.status()) {
				case CANCELLED -> { return "cancelled"; }
				case ERROR -> hasError = true;
				case INCONCLUSIVE -> hasInconclusive = true;
				default -> {}
			}
		}
		if (scanFailed) return "error";
		if (hasError) return "error";
		if (hasInconclusive) return "inconclusive";
		return "success";
	}

	/**
	 * Return the current URL
	 *
	 * @return Host URL
	 */
	public URL getURL() {

		return url;

	}

	/**
	 * Return the scan result tree root node.
	 *
	 * @return the root ScanNode
	 */
	public ScanNode getResultTree() {
		return root;
	}

	/**
	 * Render the result tree to plain text for CLI output and save-as-text.
	 *
	 * @return formatted plain text
	 */
	public String toPlainText() {
		StringBuilder sb = new StringBuilder();
		root.walkVisible(node -> {
			String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
			switch (node.getType()) {
				case SECTION:
					sb.append("\n[").append(node.getKey()).append("]\n");
					break;
				case SUBSECTION:
					sb.append(indent).append(node.getKey()).append(":\n");
					break;
				case KEY_VALUE:
					sb.append(indent).append(node.getKey()).append("=").append(node.getValue()).append("\n");
					break;
				case WARNING:
					sb.append(indent).append(node.getKey()).append("\n");
					break;
				case NOTICE:
					sb.append(node.getKey()).append("\n");
					break;
				case CONTENT:
					sb.append(indent).append(node.getKey()).append("\n");
					break;
				case BLANK:
					sb.append("\n");
					break;
				default:
					break;
			}
		});
		return sb.toString();
	}

	/**
	 * Build the report header with run information.
	 */
	public void buildReportHeader() {

		setStatusBarMessage("Report run information");

		Date d = new Date();
		root.addBlank();
		root.addNotice("  ██████  ███████ ███████ ██████  ██    ██ ██  ██████  ██      ███████ ████████");
		root.addNotice("  ██   ██ ██      ██      ██   ██ ██    ██ ██ ██    ██ ██      ██         ██   ");
		root.addNotice("  ██   ██ █████   █████   ██████  ██    ██ ██ ██    ██ ██      █████      ██   ");
		root.addNotice("  ██   ██ ██      ██      ██       ██  ██  ██ ██    ██ ██      ██         ██   ");
		root.addNotice("  ██████  ███████ ███████ ██        ████   ██  ██████  ███████ ███████    ██    ");
		root.addBlank();
		root.addNotice("  DeepViolet Version " + eng.getDeepVioletStringVersion());
		root.addNotice("  Report Generated On " + d.toString());
		if (session.getURL() != null) {
			root.addNotice("  Server Target " + session.getURL().toString());
		}
		root.addBlank();
		root.addNotice("  This software is provided for research purposes.");
		root.addNotice("  See project information on GitHub for further details:");
		root.addNotice("    https://github.com/spoofzu/DeepVioletTools");
		root.addNotice("    https://github.com/spoofzu/DeepViolet");
		root.addBlank();

	}

	/**
	 * Build the runtime environment section: Java version, vendor, home,
	 * OS, trust store, and log file locations.
	 */
	private void buildRuntimeEnvironment() {
		setStatusBarMessage("Runtime environment");

		ScanNode runtime = root.addSection("Runtime environment");
		runtime.addKeyValue("Report Version", REPORT_VERSION);
		runtime.addKeyValue("Java Version", System.getProperty("java.version"));
		runtime.addKeyValue("Java Vendor", System.getProperty("java.vendor"));
		runtime.addKeyValue("Java Home", System.getProperty("java.home"));
		runtime.addKeyValue("OS", System.getProperty("os.name") + " " + System.getProperty("os.version"));

		// Trust store location
		String trustStore = System.getProperty("javax.net.ssl.trustStore");
		if (trustStore == null) {
			trustStore = System.getProperty("java.home") + "/lib/security/cacerts";
		}
		runtime.addKeyValue("Trust Store", trustStore);

		// Log file location
		String logFile = FontPreferences.getHomeDir().getPath() + File.separator
				+ "ui" + File.separator + "logs" + File.separator + "data" + File.separator + "scanlog.log";
		runtime.addKeyValue("Log File", logFile);
	}

	/**
	 * Build the TLS risk assessment section with score, grade, and text graph.
	 * Every category bar has exactly {@code riskScale} blocks.  Each block
	 * represents {@code maxScore / riskScale} points of that category's
	 * maximum, so categories with fewer possible points have a coarser
	 * resolution (more points per block).
	 */
	public void buildRiskAssessment() {

		ScanNode section = root.addSection("TLS Risk Assessment");

		try {
			// Build context explicitly for capture and scoring
			RuleContext ctx = eng.buildRuleContext();
			this.lastRuleContextMap = ctx.toSerializableMap();

			IRiskScore score;
			if (userRiskRulesYaml != null && !userRiskRulesYaml.isBlank()) {
				score = eng.getRiskScore(ctx, new ByteArrayInputStream(
						userRiskRulesYaml.getBytes(StandardCharsets.UTF_8)));
			} else {
				score = eng.getRiskScore(ctx);
			}
			this.lastRiskScore = score;
			int scale = this.riskScale;

			// Overall score and grade
			String grade = score.getLetterGrade().toDisplayString();
			section.addKeyValue("Overall Score", score.getTotalScore() + "/100");
			section.addKeyValue("Grade", grade);
			section.addKeyValue("Risk Level", score.getRiskLevel().toString());

			ICategoryScore[] categories = score.getCategoryScores();

			// Find longest label for alignment (include "Overall" and numbered categories)
			int maxNameLen = "Overall".length();
			int catCount = 0;
			for (ICategoryScore cat : categories) {
				catCount++;
				String numbered = catCount + ". " + cat.getDisplayName();
				maxNameLen = Math.max(maxNameLen, numbered.length());
			}

			// Details: overall bar + per-category bars
			ScanNode details = section.addSubsection("Details");
			details.addContent(buildScoreBar(padRight("Overall", maxNameLen), score.getTotalScore(), 100, scale));

			// Collect footnotes across all categories
			List<String> footnotes = new ArrayList<>();

			int barCatNum = 0;
			for (ICategoryScore cat : categories) {
				barCatNum++;

				// Compute inconclusive portion of this category's lost points
				double totalDeductionScore = 0;
				double inconclusiveDeductionScore = 0;
				List<String> catFootnotes = new ArrayList<>();
				for (IDeduction d : cat.getDeductions()) {
					totalDeductionScore += d.getScore();
					if (d.isInconclusive()) {
						inconclusiveDeductionScore += d.getScore();
						catFootnotes.add(d.getDescription());
					}
				}
				int totalPointsLost = 100 - cat.getScore();
				int inconclusivePoints = totalDeductionScore > 0
						? (int) Math.round(totalPointsLost * (inconclusiveDeductionScore / totalDeductionScore))
						: 0;

				String label = padRight(barCatNum + ". " + cat.getDisplayName(), maxNameLen);
				String bar = buildScoreBar(label, cat.getScore(), 100, inconclusivePoints, scale);
				// Resolution: points represented by each block in this category
				double ptsPerBlock = 100.0 / scale;
				String annotation = String.format(" [%s] (%.1f pts/blk)", cat.getRiskLevel(), ptsPerBlock);

				// Append footnote references to bar line
				StringBuilder refs = new StringBuilder();
				for (String fn : catFootnotes) {
					footnotes.add(fn);
					refs.append(" *").append(footnotes.size());
				}

				details.addContent(bar + annotation + refs);
			}

			// Legend (under the last category bar)
			details.addContent("\u2588 pass   \u2590 inconclusive   \u2591 fail   (scale=" + scale + " blocks)");

			// Footnotes section
			if (!footnotes.isEmpty()) {
				ScanNode notes = section.addSubsection("Notes");
				for (int i = 0; i < footnotes.size(); i++) {
					notes.addContent("*" + (i + 1) + " " + footnotes.get(i));
				}
			}

			// Deduction details per category (numbered to match bar chart)
			int detCatNum = 0;
			for (ICategoryScore cat : categories) {
				detCatNum++;
				IDeduction[] deductions = cat.getDeductions();
				if (deductions.length > 0) {
					ScanNode catNode = section.addSubsection(detCatNum + ". " + cat.getDisplayName() + " (" + cat.getScore() + "/100)");
					catNode.addContent(cat.getSummary());
					for (IDeduction d : deductions) {
						String marker = d.isInconclusive() ? " [INCONCLUSIVE]" : "";
						catNode.addWarning(d.getRuleId()
								+ " [" + d.getSeverity() + "] "
								+ d.getDescription() + marker
								+ String.format(" (score: %.2f)", d.getScore()),
								d.getSeverity());
					}
				}
			}

		} catch (Exception e) {
			lastBuildError = e.getMessage();
			section.addKeyValue("Error", e.getMessage());
			logger.error("Risk assessment error", e);
		}
	}

	/**
	 * Build a fixed-width text bar for a score.  Every bar has exactly
	 * {@code scale} blocks.  Each block represents
	 * {@code maxScore / scale} points, so different categories may have
	 * different resolutions (points per block).
	 * <pre>
	 *   █ = pass  (points retained)
	 *   ▐ = inconclusive  (uncertain deductions)
	 *   ░ = fail  (points deducted)
	 * </pre>
	 *
	 * @param label    left-aligned label
	 * @param score    achieved score (points retained)
	 * @param maxScore maximum possible score for this category
	 * @param scale    total number of blocks in every bar
	 * @return formatted bar string
	 */
	private String buildScoreBar(String label, int score, int maxScore, int scale) {
		return buildScoreBar(label, score, maxScore, 0, scale);
	}

	private String buildScoreBar(String label, int score, int maxScore,
								  int inconclusivePoints, int scale) {
		int totalDeducted = maxScore - score;
		int clampedInconclusive = Math.min(inconclusivePoints, totalDeducted);

		int passBlocks = maxScore > 0
				? (int) Math.round((double) score / maxScore * scale) : 0;
		passBlocks = Math.min(passBlocks, scale);
		int inconclusiveBlocks = maxScore > 0
				? (int) Math.round((double) clampedInconclusive / maxScore * scale) : 0;
		int failBlocks = scale - passBlocks - inconclusiveBlocks;
		if (failBlocks < 0) { inconclusiveBlocks += failBlocks; failBlocks = 0; }

		StringBuilder bar = new StringBuilder();
		bar.append(label).append("  ");
		for (int i = 0; i < passBlocks; i++)         bar.append('\u2588');  // █ pass
		for (int i = 0; i < inconclusiveBlocks; i++) bar.append('\u2590');  // ▐ inconclusive (vertical stripes)
		for (int i = 0; i < failBlocks; i++)         bar.append('\u2591');  // ░ fail
		bar.append("  ").append(score).append("/").append(maxScore);
		return bar.toString();
	}

	/**
	 * Pad a string to the right with spaces.
	 */
	private String padRight(String s, int width) {
		if (s.length() >= width) return s;
		return s + " ".repeat(width - s.length());
	}

	/**
	 * Build DNS host information (hostname, IP address, canonical name).
	 */
	public void buildHostInformation() {

		ScanNode section = root.addSection("Host information");

		try {

			IHost[] hosts = this.dvHosts;

			for (IHost host : hosts) {
				section.addKeyValue("Host", host.getHostName() + " [" + host.getHostIPAddress() + "]");
				section.addKeyValue("Canonical", host.getHostCannonicalName());
			}

		} catch (Exception e) {
			lastBuildError = e.getMessage();
			section.addKeyValue("Error", e.getMessage());
			logger.error("Can't fetch host. err={}", e.getMessage(), e);
		}

	}

	/**
	 * Build HTTP(S) response headers returned by the target server.
	 */
	public void buildHostHttpResponseHeaders() {

		ScanNode section = root.addSection("HTTP(S) response headers");

		Map<String, List<String>> headers = session.getHttpResponseHeaders();

		Map<String, String> capturedHeaders = new LinkedHashMap<>();
		for (Map.Entry<String, List<String>> entry : headers.entrySet()) {

			String key = entry.getKey();

			List<String> vlist = entry.getValue();

			for (String value : vlist) {

				key = (key == null) ? "<null>" : key;
				key = (key.length() > 5000) ? key.substring(0, 5000) + "[truncated sz=" + key.length() + "]" : key;

				value = (value == null) ? "<null>" : value;
				value = (value.length() > 5000) ? value.substring(0, 5000) + "[truncated sz=" + value.length() + "]" : value;

				section.addKeyValue(key, value);
				capturedHeaders.put(key, value);

			}

		}
		this.lastHttpHeaders = capturedHeaders;

	}

	/**
	 * Build TLS connection characteristics (protocol, cipher, key exchange, etc.).
	 */
	public void buildConnectionCharacteristics() {

		ScanNode section = root.addSection("Connection characteristics");

		Map<String, String> capturedProps = new LinkedHashMap<>();
		for (ISession.SESSION_PROPERTIES key : ISession.SESSION_PROPERTIES.values()) {
			String value = session.getSessionPropertyValue(key);
			section.addKeyValue(key.toString(), value);
			capturedProps.put(key.toString(), value);
		}
		this.lastConnProperties = capturedProps;

	}

	/**
	 * Build the server's supported cipher suites with strength and protocol info.
	 */
	public void buildSupportedCipherSuites() {

		ScanNode section = root.addSection("Server cipher suites");

		try {

			IHost[] hosts = this.dvHosts;

			if (hosts != null) {

				ICipherSuite[] ciphers = eng.getCipherSuites();
				this.lastCipherSuites = ciphers;

				for (ICipherSuite cipher : ciphers) {
					section.addKeyValue(cipher.getSuiteName(),
							"Strength=" + cipher.getStrengthEvaluation() +
							", Protocol=" + cipher.getHandshakeProtocol());
				}

			} else {
				lastBuildError = "hosts null";
				section.addKeyValue("Error", "Problem fetching host cipher suites. See log for details.");
				logger.error("Problem processing server ciphers. err=hosts null");
			}

		} catch (Exception e) {
			lastBuildError = e.getMessage();
			section.addKeyValue("Error", e.getMessage());
			logger.error("Problem processing server ciphers. err={}", e.getMessage(), e);
		}
	}

	/**
	 * Build the server certificate chain from end-entity to root.
	 */
	public void buildServerCertificateChain() {

		ScanNode section = root.addSection("Server certificate chain");

		ScanNode summary = section.addSubsection("Chain Summary (end-entity --> root)");

		IX509Certificate[] certs;

		try {
			certs = dvCert.getCertificateChain();
			int n = 0;
			boolean firstcert = true;
			IX509Certificate root_cert = null;

			for (IX509Certificate ldvCert : certs) {

				// If this is a self-signed cert (root), save it for printing after the loop
				if (ldvCert.isSelfSignedCertificate()) {
					root_cert = ldvCert;
					break;
				}

				String role = firstcert ? "End-Entity" : "Intermediate CA";
				String revLabel = getRevocationLabel(ldvCert);

				ScanNode certNode = summary.addSubsection("NODE" + n + "(" + role + ")" + revLabel);
				certNode.addKeyValue("SubjectDN", ldvCert.getSubjectDN());
				certNode.addKeyValue("IssuerDN", ldvCert.getIssuerDN());
				certNode.addKeyValue("Fingerprint", ldvCert.getSigningAlgorithm() + " [" + ldvCert.getCertificateFingerPrint() + "]");

				firstcert = false;
				n++;
			}

			// Print root certificate if found in chain
			if (root_cert != null) {
				String rootRole;
				if (root_cert.isJavaRootCertificate()) {
					rootRole = "Java Root CA";
				} else {
					rootRole = "Self-Signed CA";
				}
				String revLabel = getRevocationLabel(root_cert);

				ScanNode rootNode = summary.addSubsection("NODE" + n + "(" + rootRole + ")" + revLabel);
				rootNode.addKeyValue("SubjectDN", root_cert.getSubjectDN());
				rootNode.addKeyValue("Fingerprint", root_cert.getSigningAlgorithm() + " [" + root_cert.getCertificateFingerPrint() + "]");

			} else if (n > 0) {
				// Server did not send the root CA (common). Check if the
				// last cert's issuer is a Java root and show it.
				IX509Certificate lastCert = certs[n - 1];
				if (lastCert.isJavaRootCertificate()) {
					ScanNode rootNode = summary.addSubsection("NODE" + n + "(Java Root CA)");
					rootNode.addKeyValue("SubjectDN", lastCert.getIssuerDN());
					rootNode.addContent("(not sent by server, found in Java trust store)");
				}
			}

			ScanNode details = root.addSection("Chain details");

			int n1 = 0;
			for (IX509Certificate ldvCert : certs) {
				String role;
				if (n1 == 0) {
					role = "End-Entity";
				} else if (ldvCert.isSelfSignedCertificate()) {
					role = ldvCert.isJavaRootCertificate() ? "Java Root CA" : "Self-Signed CA";
				} else {
					role = "Intermediate CA";
				}
				String revLabel = getRevocationLabel(ldvCert);
				ScanNode certDetail = details.addSubsection("NODE" + n1 + "(" + role + ")" + revLabel);
				if (n1 == 0) {
					buildTrustState(certDetail, ldvCert);
				}
				buildX509Certificate(certDetail, ldvCert);
				n1++;
			}

		} catch (Exception e) {
			lastBuildError = e.getMessage();
			section.addKeyValue("Error", e.getMessage());
			section.addBlank();
			logger.error("Problem fetching certificates. err={}", e.getMessage(), e);
		}

	}

	/**
	 * Build X509 certificate details as child nodes.
	 *
	 * @param parent Parent node to attach details to
	 * @param ldvCert Host certificate to describe
	 */
	private void buildX509Certificate(ScanNode parent, IX509Certificate ldvCert) {

		logger.trace(ldvCert.toString());

		String not_before = ldvCert.getNotValidBefore();
		String not_after = ldvCert.getNotValidAfter();

		ValidState validity_state = ldvCert.getValidityState();

		if (validity_state == IX509Certificate.ValidState.VALID) {
			parent.addKeyValue("Validity Check", "VALID (valid " + not_before + " to " + not_after + ")");
		} else if (validity_state == IX509Certificate.ValidState.NOT_YET_VALID) {
			parent.addKeyValue("Validity Check", ">>>NOT YET VALID<<< (valid " + not_before + " to " + not_after + ")");
		} else if (validity_state == IX509Certificate.ValidState.EXPIRED) {
			parent.addKeyValue("Validity Check", ">>>EXPIRED<<< (valid " + not_before + " to " + not_after + ")");
		}

		// Certificate expiration warning
		long daysLeft = ldvCert.getDaysUntilExpiration();
		if (daysLeft < 0) {
			parent.addWarning(">>> Certificate EXPIRED " + Math.abs(daysLeft) + " days ago! <<<");
		} else if (daysLeft < 30) {
			parent.addWarning(">>> Certificate expires in " + daysLeft + " days! <<<");
		} else {
			parent.addKeyValue("Days Until Expiration", String.valueOf(daysLeft));
		}

		parent.addKeyValue("Subject DN", ldvCert.getSubjectDN());
		parent.addKeyValue("Issuer DN", ldvCert.getIssuerDN());
		parent.addKeyValue("Serial Number", ldvCert.getCertificateSerialNumber().toString());
		parent.addKeyValue("Signature Algorithm", ldvCert.getSigningAlgorithm());
		parent.addKeyValue("Signature Algorithm OID", ldvCert.getSigningAlgorithmOID());
		parent.addKeyValue("Certificate Version", String.valueOf(ldvCert.getCertificateVersion()));
		parent.addKeyValue("Public Key Algorithm", ldvCert.getPublicKeyAlgorithm());
		parent.addKeyValue("Public Key Size", ldvCert.getPublicKeySize() + " bits");
		if (ldvCert.getPublicKeyCurve() != null) {
			parent.addKeyValue("Public Key Curve", ldvCert.getPublicKeyCurve());
		}

		String signature_algo = ldvCert.getSigningAlgorithm();
		String digest_algo = signature_algo.substring(0, signature_algo.indexOf("with"));
		parent.addKeyValue(digest_algo + " Fingerprint", "[" + ldvCert.getCertificateFingerPrint() + "]");

		List<String> sans = ldvCert.getSubjectAlternativeNames();
		if (sans != null && !sans.isEmpty()) {
			parent.addKeyValue("SAN Count", String.valueOf(sans.size()));
		}

		ScanNode nonCritOids = parent.addSubsection("Non-Critical OIDs");
		buildNonCritOIDs(nonCritOids, ldvCert);

		ScanNode critOids = parent.addSubsection("Critical OIDs");
		buildCritOIDs(critOids, ldvCert);

	}

	/**
	 * Build the trust state of a certificate (TRUSTED, UNTRUSTED, or REVOKED).
	 *
	 * @param parent Parent node to attach to
	 * @param ldvCert Certificate to evaluate
	 */
	private void buildTrustState(ScanNode parent, IX509Certificate ldvCert) {

		logger.debug("ldvCert=" + ldvCert + " ldvCert.getTrustState()=" + ldvCert.getTrustState());

		// Revoked overrides everything
		String revLabel = getRevocationLabel(ldvCert);
		if (!revLabel.isEmpty()) {
			parent.addKeyValue("Trust State", ">>>REVOKED<<<");
			return;
		}

		String trust_state = "<ERROR>";

		if (ldvCert.getTrustState() == IX509Certificate.TrustState.TRUSTED) {
			trust_state = "TRUSTED";
		} else if (ldvCert.getTrustState() == IX509Certificate.TrustState.UNKNOWN) {
			trust_state = "UNKNOWN";
		} else if (ldvCert.getTrustState() == IX509Certificate.TrustState.UNTRUSTED) {
			trust_state = "UNTRUSTED";
		}

		if (trust_state.equals("TRUSTED")) {
			parent.addKeyValue("Trust State", "TRUSTED");
		} else {
			parent.addKeyValue("Trust State", ">>>" + trust_state + "<<<");
		}

	}

	/**
	 * Check if any revocation mechanism reports the certificate as revoked.
	 *
	 * @param rev Revocation status to check
	 * @return true if OCSP, CRL, or OneCRL reports REVOKED
	 */
	private boolean isRevoked(IRevocationStatus rev) {
		if (rev == null) return false;
		return rev.getOcspStatus() == IRevocationStatus.RevocationResult.REVOKED
				|| rev.getCrlStatus() == IRevocationStatus.RevocationResult.REVOKED
				|| rev.getOneCrlStatus() == IRevocationStatus.RevocationResult.REVOKED;
	}

	/**
	 * Return a revocation warning label for a certificate.
	 *
	 * @param cert Certificate to check
	 * @return "(REVOKED)" if revoked, empty string otherwise
	 */
	private String getRevocationLabel(IX509Certificate cert) {
		try {
			IRevocationStatus rev = cert.getRevocationStatus();
			return isRevoked(rev) ? "(REVOKED)" : "";
		} catch (Exception e) {
			logger.debug("Could not check revocation for label", e);
			return "";
		}
	}

	/**
	 * Build non-critical OIDs as child nodes.
	 *
	 * @param parent Parent subsection node
	 * @param ldvCert Host certificate
	 */
	private void buildNonCritOIDs(ScanNode parent, IX509Certificate ldvCert) {

		String[] keys = ldvCert.getNonCritOIDProperties();

		if (keys.length == 0) {
			parent.addContent("(none)");
			return;
		}

		for (String key : keys) {
			String value = ldvCert.getNonCritPropertyValue(key);
			parent.addKeyValue(key, value);
		}

	}

	/**
	 * Build critical OIDs as child nodes.
	 *
	 * @param parent Parent subsection node
	 * @param ldvCert Host certificate
	 */
	private void buildCritOIDs(ScanNode parent, IX509Certificate ldvCert) {

		String[] keys = ldvCert.getCritOIDProperties();

		if (keys.length == 0) {
			parent.addContent("(none)");
			return;
		}

		for (String key : keys) {
			String value = ldvCert.getCritPropertyValue(key);
			parent.addKeyValue(key, value);
		}

	}

	/**
	 * Build security headers analysis section.
	 */
	public void buildSecurityHeadersAnalysis() {

		ScanNode section = root.addSection("Security headers analysis");

		Map<String, List<String>> headers = session.getHttpResponseHeaders();

		// Build a case-insensitive lookup
		Map<String, String> headerLookup = new HashMap<>();
		for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
			if (entry.getKey() != null && entry.getValue() != null && !entry.getValue().isEmpty()) {
				headerLookup.put(entry.getKey().toLowerCase(), String.join(", ", entry.getValue()));
			}
		}

		String[][] secHeaders = {
			{"strict-transport-security", "Strict-Transport-Security (HSTS)"},
			{"content-security-policy", "Content-Security-Policy (CSP)"},
			{"x-content-type-options", "X-Content-Type-Options"},
			{"x-frame-options", "X-Frame-Options"},
			{"x-xss-protection", "X-XSS-Protection"},
			{"referrer-policy", "Referrer-Policy"},
			{"permissions-policy", "Permissions-Policy"},
		};

		Map<String, String> capturedSecHeaders = new LinkedHashMap<>();
		for (String[] pair : secHeaders) {
			String value = headerLookup.get(pair[0]);
			if (value != null) {
				section.addKeyValue(pair[1], "PRESENT (" + value + ")");
				capturedSecHeaders.put(pair[1], value);
			} else {
				section.addKeyValue(pair[1], ">>>MISSING<<<");
				capturedSecHeaders.put(pair[1], "MISSING");
			}
		}
		this.lastSecurityHeaders = capturedSecHeaders;
	}

	/**
	 * Build certificate revocation status for end-entity and chain certificates.
	 */
	public void buildRevocationStatus() {

		ScanNode section = root.addSection("Certificate revocation status");

		// Download CT log list for SCT log name lookups
		CTLogLookup ctLogLookup = new CTLogLookup();

		// Verify SCT signatures against CT log public keys
		setStatusBarMessage("Verifying SCT signatures");
		Map<String, SctVerifier.SctResult> sctResults = SctVerifier.verifyEmbeddedScts(url, ctLogLookup);

		try {
			// Build responder->nodes maps by scanning all certs first
			Map<String, List<String>> ocspResponderNodes = new LinkedHashMap<>();
			Map<String, List<String>> crlResponderNodes = new LinkedHashMap<>();

			// Collect all certs with their labels
			IX509Certificate[] chainCerts = dvCert.getCertificateChain();

			// End-entity cert is NODE0
			addResponderNodes(dvCert, 0, ocspResponderNodes, crlResponderNodes);

			// Chain certs are NODE1, NODE2, etc.
			for (int i = 1; i < chainCerts.length; i++) {
				addResponderNodes(chainCerts[i], i, ocspResponderNodes, crlResponderNodes);
			}

			// Build revocation for the end-entity cert
			buildCertRevocation(section, dvCert, "End-Entity", ocspResponderNodes, crlResponderNodes, ctLogLookup, sctResults);

			// Build revocation for chain certs
			for (int i = 1; i < chainCerts.length; i++) {
				IX509Certificate chainCert = chainCerts[i];
				String label = chainCert.isSelfSignedCertificate() ? "Root CA" : "Intermediate CA";
				buildCertRevocation(section, chainCert, label, ocspResponderNodes, crlResponderNodes, ctLogLookup, sctResults);
			}
		} catch (Exception e) {
			lastBuildError = e.getMessage();
			section.addKeyValue("Error", e.getMessage());
			logger.error("Revocation status error", e);
		}
	}

	/**
	 * Add a certificate's OCSP and CRL responder URLs to the node maps.
	 */
	private void addResponderNodes(IX509Certificate cert, int nodeIndex,
			Map<String, List<String>> ocspResponderNodes, Map<String, List<String>> crlResponderNodes) {

		IRevocationStatus rev = cert.getRevocationStatus();
		if (rev == null) {
			return;
		}

		String nodeId = "NODE" + nodeIndex;

		if (rev.getOcspResponderUrl() != null) {
			ocspResponderNodes.computeIfAbsent(rev.getOcspResponderUrl(), k -> new ArrayList<>()).add(nodeId);
		}
		if (rev.getCrlDistributionPoint() != null) {
			crlResponderNodes.computeIfAbsent(rev.getCrlDistributionPoint(), k -> new ArrayList<>()).add(nodeId);
		}
	}

	/**
	 * Build revocation details for a single certificate.
	 */
	private void buildCertRevocation(ScanNode section, IX509Certificate cert, String label,
			Map<String, List<String>> ocspResponderNodes, Map<String, List<String>> crlResponderNodes,
			CTLogLookup ctLogLookup, Map<String, SctVerifier.SctResult> sctResults) {

		IRevocationStatus rev = cert.getRevocationStatus();
		if (rev == null) {
			ScanNode certNode = section.addSubsection("[" + label + "] " + cert.getSubjectDN());
			certNode.addKeyValue("Revocation Check", "NOT AVAILABLE");
			return;
		}

		ScanNode certNode = section.addSubsection("[" + label + "] " + rev.getCertSubjectDN());

		// OCSP
		ScanNode ocsp = certNode.addSubsection("OCSP Check");
		if (rev.getOcspStatus() == IRevocationStatus.RevocationResult.NOT_CHECKED) {
			String msg = "NOT CHECKED";
			if (rev.getOcspErrorMessage() != null) {
				msg += " (" + rev.getOcspErrorMessage() + ")";
			}
			ocsp.addKeyValue("Status", msg);
		} else {
			if (rev.getOcspResponderUrl() != null) {
				ocsp.addKeyValue("Responder URL", rev.getOcspResponderUrl());
				List<String> ocspNodes = ocspResponderNodes.get(rev.getOcspResponderUrl());
				if (ocspNodes != null && !ocspNodes.isEmpty()) {
					ocsp.addKeyValue("Responder Nodes", String.join(", ", ocspNodes));
				}
			}
			if (rev.getOcspStatus() == IRevocationStatus.RevocationResult.REVOKED) {
				ocsp.addKeyValue("Status", ">>>REVOKED<<<");
			} else {
				ocsp.addKeyValue("Status", rev.getOcspStatus().toString());
			}
			ocsp.addKeyValue("Response Time", rev.getOcspResponseTimeMs() + "ms");
			if (rev.getOcspThisUpdate() != null) {
				ocsp.addKeyValue("This Update", rev.getOcspThisUpdate());
			}
			if (rev.getOcspNextUpdate() != null) {
				ocsp.addKeyValue("Next Update", rev.getOcspNextUpdate());
			}
			ocsp.addKeyValue("Signature Valid", String.valueOf(rev.isOcspSignatureValid()));
			if (rev.getOcspStatus() == IRevocationStatus.RevocationResult.ERROR && rev.getOcspErrorMessage() != null) {
				ocsp.addWarning(">>> Error: " + rev.getOcspErrorMessage() + " <<<");
			}
		}

		// OCSP Stapling
		if (rev.isOcspStaplingPresent()) {
			certNode.addKeyValue("OCSP Stapling", "PRESENT");
			if (rev.getStapledOcspStatus() == IRevocationStatus.RevocationResult.REVOKED) {
				certNode.addKeyValue("Stapled Status", ">>>REVOKED<<<");
			} else {
				certNode.addKeyValue("Stapled Status", rev.getStapledOcspStatus().toString());
			}
		} else {
			certNode.addKeyValue("OCSP Stapling", "NOT PRESENT");
		}

		// Must-Staple
		certNode.addKeyValue("Must-Staple", rev.isMustStaplePresent() ? "PRESENT" : "NOT PRESENT");
		if (rev.isMustStaplePresent() && !rev.isOcspStaplingPresent()) {
			certNode.addWarning(">>> WARNING: Must-Staple set but no OCSP stapling response! <<<");
		}

		// CRL
		ScanNode crl = certNode.addSubsection("CRL Check");
		if (rev.getCrlStatus() == IRevocationStatus.RevocationResult.NOT_CHECKED) {
			String msg = "NOT CHECKED";
			if (rev.getCrlErrorMessage() != null) {
				msg += " (" + rev.getCrlErrorMessage() + ")";
			}
			crl.addKeyValue("Status", msg);
		} else {
			if (rev.getCrlDistributionPoint() != null) {
				crl.addKeyValue("Distribution Point", rev.getCrlDistributionPoint());
				List<String> crlNodes = crlResponderNodes.get(rev.getCrlDistributionPoint());
				if (crlNodes != null && !crlNodes.isEmpty()) {
					crl.addKeyValue("Responder Nodes", String.join(", ", crlNodes));
				}
			}
			if (rev.getCrlStatus() == IRevocationStatus.RevocationResult.REVOKED) {
				crl.addKeyValue("Status", ">>>REVOKED<<<");
			} else {
				crl.addKeyValue("Status", rev.getCrlStatus().toString());
			}
			crl.addKeyValue("Download Time", rev.getCrlResponseTimeMs() + "ms");
			crl.addKeyValue("CRL Size", rev.getCrlSizeBytes() + " bytes");
			if (rev.getCrlThisUpdate() != null) {
				crl.addKeyValue("This Update", rev.getCrlThisUpdate());
			}
			if (rev.getCrlNextUpdate() != null) {
				crl.addKeyValue("Next Update", rev.getCrlNextUpdate());
			}
			if (rev.getCrlStatus() == IRevocationStatus.RevocationResult.ERROR && rev.getCrlErrorMessage() != null) {
				crl.addWarning(">>> Error: " + rev.getCrlErrorMessage() + " <<<");
			}
		}

		// OneCRL
		ScanNode oneCrl = certNode.addSubsection("OneCRL Check");
		if (rev.getOneCrlStatus() == IRevocationStatus.RevocationResult.NOT_CHECKED) {
			oneCrl.addKeyValue("Status", "NOT CHECKED");
		} else if (rev.getOneCrlStatus() == IRevocationStatus.RevocationResult.GOOD) {
			oneCrl.addKeyValue("Status", "NOT FOUND (certificate not in Mozilla revocation list)");
		} else if (rev.getOneCrlStatus() == IRevocationStatus.RevocationResult.REVOKED) {
			oneCrl.addKeyValue("Status", ">>>FOUND IN OneCRL<<<");
		} else {
			String msg = rev.getOneCrlStatus().toString();
			if (rev.getOneCrlErrorMessage() != null) {
				msg += " (" + rev.getOneCrlErrorMessage() + ")";
			}
			oneCrl.addKeyValue("Status", msg);
		}

		// Certificate Transparency SCTs
		ScanNode scts = certNode.addSubsection("Certificate Transparency (SCTs)");

		int embedded = rev.getEmbeddedSctCount();
		int tlsExt = rev.getTlsExtensionSctCount();
		int ocspStaple = rev.getOcspStaplingSctCount();

		String tlsExtDisplay = (tlsExt < 0) ? "*Note 1" : String.valueOf(tlsExt);
		scts.addKeyValue("Embedded SCTs", String.valueOf(embedded));
		scts.addKeyValue("TLS Extension SCTs", tlsExtDisplay);
		scts.addKeyValue("OCSP Staple SCTs", String.valueOf(ocspStaple));

		// Show details for embedded SCTs
		if (embedded > 0) {
			String[] embeddedDetails = rev.getEmbeddedSctDetails();
			for (int i = 0; i < embeddedDetails.length; i++) {
				ScanNode sctNode = scts.addKeyValue("Embedded #" + (i + 1), embeddedDetails[i]);
				addCtLogInfo(sctNode, embeddedDetails[i], ctLogLookup, sctResults);
			}
		}

		// Show details for TLS extension SCTs (if available)
		if (tlsExt > 0) {
			String[] tlsExtDetails = rev.getTlsExtensionSctDetails();
			for (int i = 0; i < tlsExtDetails.length; i++) {
				ScanNode sctNode = scts.addKeyValue("TLS Extension #" + (i + 1), tlsExtDetails[i]);
				addCtLogInfo(sctNode, tlsExtDetails[i], ctLogLookup, sctResults);
			}
		} else if (tlsExt < 0) {
			scts.addContent("Note 1: TLS Extension SCTs not available, FUTURE");
		}

		// Show details for OCSP stapling SCTs
		if (ocspStaple > 0) {
			String[] ocspStapleDetails = rev.getOcspStaplingSctDetails();
			for (int i = 0; i < ocspStapleDetails.length; i++) {
				ScanNode sctNode = scts.addKeyValue("OCSP Staple #" + (i + 1), ocspStapleDetails[i]);
				addCtLogInfo(sctNode, ocspStapleDetails[i], ctLogLookup, sctResults);
			}
		}
	}

	/**
	 * Add CT log info and SCT signature verification as child nodes.
	 * Parses the LogID from the detail string and looks it up in the CT log list.
	 *
	 * @param sctNode    the SCT detail node to add children to
	 * @param detail     the SCT detail string (e.g. "Version=0 LogID=... Timestamp=...")
	 * @param ctLogLookup the CT log lookup instance
	 * @param sctResults  map of LogID to verification result
	 */
	private void addCtLogInfo(ScanNode sctNode, String detail, CTLogLookup ctLogLookup,
			Map<String, SctVerifier.SctResult> sctResults) {
		String logId = extractLogId(detail);
		if (logId == null) {
			return;
		}

		CTLogLookup.CTLogInfo info = ctLogLookup.lookup(logId);
		if (info != null) {
			sctNode.addKeyValue("CT Log", info.toDisplayString());
			if (info.url() != null) {
				sctNode.addKeyValue("Log Server", info.url());
			}
			if ("retired".equals(info.state()) || "rejected".equals(info.state())) {
				sctNode.addWarning(">>> WARNING: CT log is " + info.state() + " <<<");
			}
		} else if (ctLogLookup.isLoaded()) {
			sctNode.addKeyValue("CT Log", "Unknown CT Log");
		}

		// SCT signature verification result
		SctVerifier.SctResult result = sctResults != null ? sctResults.get(logId) : null;
		if (result != null) {
			switch (result.status()) {
				case VALID:
					sctNode.addKeyValue("Signature", "VALID");
					break;
				case INVALID:
					sctNode.addKeyValue("Signature", ">>>INVALID<<<");
					sctNode.addWarning(">>> WARNING: SCT signature verification FAILED <<<");
					break;
				case UNKNOWN_LOG:
					sctNode.addKeyValue("Signature", "NOT VERIFIED (unknown log)");
					break;
				case VERIFICATION_ERROR:
					sctNode.addKeyValue("Signature", "NOT VERIFIED (" + result.message() + ")");
					break;
			}
		}
	}

	/**
	 * Extract the Base64-encoded LogID from an SCT detail string.
	 * Expected format: "Version=0 LogID=&lt;base64&gt; Timestamp=..."
	 *
	 * @param detail SCT detail string
	 * @return the LogID value, or null if not found
	 */
	static String extractLogId(String detail) {
		if (detail == null) {
			return null;
		}
		int start = detail.indexOf("LogID=");
		if (start < 0) {
			return null;
		}
		start += "LogID=".length();

		// LogID ends at the next space or end of string
		int end = detail.indexOf(' ', start);
		if (end < 0) {
			end = detail.length();
		}
		String logId = detail.substring(start, end).trim();
		return logId.isEmpty() ? null : logId;
	}

	/**
	 * Build TLS server fingerprint for the target host.
	 * Probe codes and the extension hash are rendered as colon-delimited
	 * hex octets.  Failed probes are represented as 00:00:00.
	 */
	public void buildTlsFingerprint() {

		ScanNode section = root.addSection("TLS server fingerprint");

		try {
			String fingerprint = eng.getTlsFingerprint();
			this.lastFingerprint = fingerprint;

			if (fingerprint == null) {
				section.addKeyValue("Fingerprint", "NOT AVAILABLE");
				return;
			}

			// Parse and display summary first
			String summary = TlsServerFingerprint.summarize(fingerprint);
			section.addKeyValue("Summary", summary);
			section.addKeyValue("Fingerprint", fingerprintToOctets(fingerprint));

			// Check if server has no TLS support
			if (TlsServerFingerprint.isNoTlsSupport(fingerprint)) {
				section.addWarning(">>> WARNING: All probes failed - server may not support TLS <<<");
				return;
			}

			// Parse components for detailed view
			TlsServerFingerprint.FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);
			if (components != null) {
				ScanNode agg = section.addSubsection("Fingerprint Aggregation");

				String[] probeDescriptions = {
					"TLS 1.2 standard cipher order",
					"TLS 1.2 reverse cipher order",
					"TLS 1.2 with ALPN h2",
					"TLS 1.2 no ECC support",
					"TLS 1.1 only",
					"TLS 1.3 only (TLS 1.3 ciphers)",
					"TLS 1.3 with TLS 1.2 fallback",
					"TLS 1.3 with ALPN h2",
					"TLS 1.3 reverse cipher order",
					"TLS 1.2 forward secrecy only"
				};

				for (int i = 1; i <= 10; i++) {
					String code = components.getProbeCode(i);
					boolean success = components.probeSucceeded(i);
					String status = success ? "OK" : "FAIL";
					agg.addKeyValue(String.format("Probe %2d", i),
							probeCodeToOctets(code) + " (" + status + ") " + probeDescriptions[i - 1]);
				}

				agg.addKeyValue("Extension Hash", hexToOctets(components.getExtensionHash()));
			}

		} catch (Exception e) {
			lastBuildError = e.getMessage();
			section.addKeyValue("Error", e.getMessage());
			logger.error("TLS fingerprint error", e);
		}
	}

	/**
	 * Convert a 3-character probe code to colon-delimited hex octets.
	 * Failed probes ("|||") become "00:00:00".
	 *
	 * @param code 3-character probe code (e.g. "a30" or "|||")
	 * @return hex octets (e.g. "61:33:30" or "00:00:00")
	 */
	private static String probeCodeToOctets(String code) {
		if ("|||".equals(code)) {
			return "00:00:00";
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < code.length(); i++) {
			if (i > 0) sb.append(':');
			sb.append(String.format("%02X", (int) code.charAt(i)));
		}
		return sb.toString();
	}

	/**
	 * Convert a hex string (e.g. "00112233aabb") to colon-delimited octets
	 * (e.g. "00:11:22:33:AA:BB").
	 *
	 * @param hex even-length hex string
	 * @return colon-delimited uppercase hex octets
	 */
	private static String hexToOctets(String hex) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < hex.length() - 1; i += 2) {
			if (sb.length() > 0) sb.append(':');
			sb.append(hex.substring(i, i + 2).toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * Convert a full 62-character fingerprint string to colon-delimited
	 * hex octets.  The first 30 characters (10 x 3-char probe codes) are
	 * each converted via {@link #probeCodeToOctets}; the remaining 32
	 * characters (extension hash hex) are converted via {@link #hexToOctets}.
	 *
	 * @param fingerprint 62-character raw fingerprint
	 * @return colon-delimited hex octets for the entire fingerprint
	 */
	private static String fingerprintToOctets(String fingerprint) {
		if (fingerprint == null || fingerprint.length() != 62) {
			return fingerprint != null ? fingerprint : "";
		}
		StringBuilder sb = new StringBuilder();
		// 10 probes, 3 chars each
		for (int p = 0; p < 10; p++) {
			if (sb.length() > 0) sb.append(':');
			String code = fingerprint.substring(p * 3, p * 3 + 3);
			sb.append(probeCodeToOctets(code));
		}
		// Extension hash (32 hex chars → 16 octets)
		String hash = fingerprint.substring(30);
		sb.append(':');
		sb.append(hexToOctets(hash));
		return sb.toString();
	}

	/**
	 * Install a permissive SSLContext as the JVM default.
	 */
	private static synchronized void installTrustAllSslContext() throws Exception {
		// Obtain the default TrustManager backed by the Java trust store
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(
				TrustManagerFactory.getDefaultAlgorithm());
		tmf.init((KeyStore) null); // null = use default cacerts
		X509TrustManager defaultTm = null;
		for (TrustManager tm : tmf.getTrustManagers()) {
			if (tm instanceof X509TrustManager) {
				defaultTm = (X509TrustManager) tm;
				break;
			}
		}
		final X509TrustManager originalTm = defaultTm;

		TrustManager[] permissive = new TrustManager[] {
			new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() {
					// Delegate to original so Java root CA checks still work
					return originalTm != null
							? originalTm.getAcceptedIssuers()
							: new X509Certificate[0];
				}
				public void checkClientTrusted(X509Certificate[] certs, String authType) {}
				public void checkServerTrusted(X509Certificate[] certs, String authType) {}
			}
		};
		SSLContext sc = SSLContext.getInstance("TLS");
		sc.init(null, permissive, new SecureRandom());
		SSLContext.setDefault(sc);
	}

	/**
	 * Build the AI evaluation section by sending the report generated so far
	 * to the configured AI provider for analysis.
	 *
	 * <p>The system prompt instructs the AI to return structured text using
	 * {@code [Section Name]} delimiters.  The parser splits on those
	 * delimiters and maps each section into a {@link ScanNode} subsection.
	 * Lines prefixed with {@code CRITICAL:} or {@code WARNING:} become
	 * WARNING nodes for visual emphasis; everything else becomes CONTENT.</p>
	 */
	private void buildAiEvaluation() {

		ScanNode section = root.addSection("AI Evaluation");

		// Build severity map from risk assessment WARNING nodes (ruleId -> severity)
		java.util.Map<String, String> severityMap = new java.util.HashMap<>();
		root.walk(node -> {
			if (node.getType() == ScanNode.NodeType.WARNING && node.getSeverity() != null) {
				String key = node.getKey();
				if (key != null) {
					// Extract rule ID (first token, e.g. "SYS-0000900")
					int space = key.indexOf(' ');
					if (space > 0) {
						severityMap.put(key.substring(0, space), node.getSeverity());
					}
				}
			}
		});

		// Send all report sections generated so far as context
		String reportSoFar = toPlainText();

		try {
			AiAnalysisService service = new AiAnalysisService();
			String analysis = service.analyze(reportSoFar, aiApiKey, aiProvider,
					aiModel, aiMaxTokens, aiTemperature, aiSystemPrompt, aiEndpointUrl);

			AiAnalysisService.parseAiResponse(section, analysis, severityMap);
		} catch (AiAnalysisService.AiAnalysisException e) {
			lastBuildError = e.getMessage();
			section.addWarning(">>> AI evaluation failed: " + e.getMessage() + " <<<");
			logger.error("AI evaluation failed", e);
		}
	}

	/**
	 * Execute sections of a scan report. Set the status bar message on each
	 * step for the user.
	 *
	 * <p>Emits 4-5 structured log entries to scanlog per scan:
	 * <ol>
	 *   <li>Scan started</li>
	 *   <li>Network timings (session init, revocation, fingerprint, AI)</li>
	 *   <li>Analysis timings (header, runtime, risk, host, headers, etc.)</li>
	 *   <li>Scan completed with overall status, section counts, and elapsed time</li>
	 *   <li>Evidence details (only when non-success sections exist)</li>
	 * </ol>
	 */
	protected void doInBackground() throws Exception {

		MDC.put("host", hostname);
		MDC.put("sessionid", sessionId);

		long scanStartTime = System.currentTimeMillis();
		scanlog.info("Scan started url={}", url);

		try {
			// Install trust-all SSLContext so DeepVioletFactory can connect to servers
			// with untrusted certificates (self-signed, expired, etc.)
			installTrustAllSslContext();

			// Initialize the DV libraries (network).
			setStatusBarMessage("Starting scan");
			long t0 = System.currentTimeMillis();
			this.session = DeepVioletFactory.initializeSession(url);
			eng = DeepVioletFactory.getEngine(session, cipherConvention, this, buildEnabledProtocols());
			dvCert = eng.getCertificate();
			dvHosts = session.getHostInterfaces();
			networkTimings.put("Session init", System.currentTimeMillis() - t0);

			// All sections are always built so saved results contain full metadata.
			// Section booleans only control display filtering downstream.

			// --- Analytical sections ---

			if (!runSection("Report header", analyticalTimings, "Report run information", this::buildReportHeader)) return;
			if (!runSection("Runtime env", analyticalTimings, "Runtime environment", this::buildRuntimeEnvironment)) return;

			if (!runSection("Risk", analyticalTimings, "TLS risk assessment", this::buildRiskAssessment)) return;
			checkRiskInconclusive();

			// AI evaluation (network)
			if (bAiEvaluationSection) {
				if (!runSection("AI evaluation", networkTimings, "AI evaluation", this::buildAiEvaluation)) return;
			}

			if (bWriteCertificate) {
				if (!runSection("Write cert", analyticalTimings, "Write certificate to disk", () -> {
					try {
						eng.writeCertificate(filename);
					} catch (DeepVioletException e) {
						String err = "Error writing certificate to disk. msg=" + e.getMessage();
						root.addKeyValue("Error", err);
						logger.error("{}", err, e);
						lastBuildError = e.getMessage();
					}
				})) return;
			}

			if (!runSection("Host info", analyticalTimings, "Host information", this::buildHostInformation)) return;
			if (!runSection("HTTP headers", analyticalTimings, "HTTP response headers", this::buildHostHttpResponseHeaders)) return;
			if (!runSection("Security headers", analyticalTimings, "Security headers analysis", this::buildSecurityHeadersAnalysis)) return;
			if (!runSection("Connection", analyticalTimings, "Connection characteristics", this::buildConnectionCharacteristics)) return;
			if (!runSection("Cipher suites", analyticalTimings, "Server cipher suites", this::buildSupportedCipherSuites)) return;
			if (!runSection("Cert chain", analyticalTimings, "Server certificate chain", this::buildServerCertificateChain)) return;

			// Certificate revocation status (network)
			if (!runSection("Revocation", networkTimings, "Certificate revocation status", this::buildRevocationStatus)) return;
			checkRevocationErrors();

			// TLS server fingerprint (network)
			if (!runSection("TLS fingerprint", networkTimings, "TLS server fingerprint", this::buildTlsFingerprint)) return;
			checkFingerprintInconclusive();

		} catch (Exception e) {
			scanFailed = true;
			failureMessage = e.getMessage();
			throw e;
		} finally {
			long totalElapsed = System.currentTimeMillis() - scanStartTime;
			scanlog.info("Network: {}", formatTimings(networkTimings));
			scanlog.info("Analysis: {}", formatTimings(analyticalTimings));
			scanlog.info("Scan completed status={}, sections={}, totalElapsed={}ms",
					determineStatus(), formatSectionCounts(), totalElapsed);
			String evidence = formatEvidence();
			if (evidence != null) {
				scanlog.info("Evidence: {}", evidence);
			}
			MDC.remove("host");
			MDC.remove("sessionid");
		}

	}

	// ---- scan data accessors ----

	/** @return the root ScanNode of this scan */
	public ScanNode getRoot() {
		return root;
	}

	/** @return the risk score from the last scan, or null */
	public IRiskScore getLastRiskScore() {
		return lastRiskScore;
	}

	/** @return the serialized RuleContext map from the last scan, or null */
	public Map<String, Object> getLastRuleContextMap() {
		return lastRuleContextMap;
	}

	/** @return the cipher suites from the last scan, or null */
	public ICipherSuite[] getLastCipherSuites() {
		return lastCipherSuites;
	}

	/** @return the security headers from the last scan, or null */
	public Map<String, String> getLastSecurityHeaders() {
		return lastSecurityHeaders;
	}

	/** @return the connection properties from the last scan, or null */
	public Map<String, String> getLastConnProperties() {
		return lastConnProperties;
	}

	/** @return the HTTP response headers from the last scan, or null */
	public Map<String, String> getLastHttpHeaders() {
		return lastHttpHeaders;
	}

	/** @return the TLS fingerprint from the last scan, or null */
	public String getLastFingerprint() {
		return lastFingerprint;
	}

}
