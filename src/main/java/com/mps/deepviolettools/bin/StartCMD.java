package com.mps.deepviolettools.bin;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.Timer;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;
import com.mps.deepviolet.validate.ApiValidator;
import com.mps.deepviolettools.job.ScanTask;
import com.mps.deepviolettools.job.UIBackgroundScanTask;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.util.FontPreferences;
import com.mps.deepviolettools.util.LogUtils;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.util.DeltaScanner;
import com.mps.deepviolettools.util.ReportExporter;
import com.mps.deepviolettools.util.TargetParser;

/**
 * Entry point to start DeepViolet and run headless. Useful for running
 * DeepViolet from scripts.
 *
 * <p>Supports the {@code -s} option to select report sections:
 * a=risk assessment, e=runtime environment, h=host, r=HTTP response,
 * c=connection characteristics, i=cipher suites, s=server certificate,
 * n=certificate chain, v=revocation status, x=security headers,
 * f=TLS Probe Fingerprint.</p>
 *
 * @author Milton Smith
 */
public class StartCMD {

	// Initialize logging before we do anything
	static {
		LogUtils.logInit();
	}

	public static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolettools.bin.StartCMD");

	private static final String EOL = System.getProperty("line.separator");

	/**
	 * Main entry point for the headless CLI scanner.
	 *
	 * @param args Command line arguments (use {@code -h} for usage)
	 */
	public static void main(String[] args) {
		new StartCMD().init(args);
	}

	/**
	 * Initialization
	 */
	private void init(String[] args) {

		logger.info("Starting headless via dvcli");

		FontPreferences.ensureEncryptionSeed();

		try {

			// Create command line options
			Options options = new Options();
			options.addOption("wc", "writecertificate", true,
					"Optional, write PEM encoded certificate to disk. Ex: -wc ~/certs/mycert.pem");
			options.addOption("s", "sections", true,
					"Optional, unspecified prints all sections or specify sections. [a|t|h|r|c|i|s|n|v|x|f]");
			options.addOption("o", "output", true,
					"Optional, write report to file. Ex: -o report.pdf");
			options.addOption("f", "format", true,
					"Optional, output format: txt, html, pdf, json. Inferred from -o extension if omitted.");
			options.addOption("d", "debug", false, "Optional, debug SSL/TLS connection.");
			options.addOption("d2", "debuglogging", false, "Optional, enable logback DEBUG logging.");
			options.addOption(null, "ai", false, "Optional, enable AI evaluation section in report.");
			options.addOption(null, "ai-provider", true, "Optional, AI provider: anthropic, openai, ollama.");
			options.addOption(null, "ai-model", true, "Optional, AI model name.");
			options.addOption(null, "ai-key", true, "Optional, API key (overrides saved; prefer env var DV_AI_API_KEY).");
			options.addOption(null, "ai-endpoint", true, "Optional, Ollama endpoint URL (default: http://localhost:11434).");
			options.addOption(null, "proto-sslv3", false, "Optional, enable SSLv3 probing.");
			options.addOption(null, "proto-tls10", false, "Optional, enable TLS 1.0 probing.");
			options.addOption(null, "proto-tls11", false, "Optional, enable TLS 1.1 probing.");
			options.addOption(null, "proto-tls12", false, "Optional, enable TLS 1.2 probing.");
			options.addOption(null, "proto-tls13", false, "Optional, enable TLS 1.3 probing.");
			options.addOption(null, "scan-threads", true,
					"Optional, worker thread count for scan mode (default: 3, range 1-10).");
			options.addOption(null, "scan-throttle", true,
					"Optional, delay in ms between hosts in scan mode (default: 150, range 0-10000).");
			options.addOption(null, "max-retries", true,
					"Optional, max connection retry attempts per section (default: 3, range 0-10).");
			options.addOption(null, "retry-delay", true,
					"Optional, initial retry delay in ms (default: 500, range 100-10000).");
			options.addOption(null, "retry-max-delay", true,
					"Optional, max retry delay in ms (default: 4000, range 100-30000).");
			options.addOption(null, "retry-budget", true,
					"Optional, total retry budget in ms (default: 15000, range 1000-120000).");
			options.addOption(null, "restore-point", true,
					"Optional, save checkpoint every N hosts (default: 20, range 5-1000).");
			options.addOption(null, "resume", false,
					"Optional, resume scan from last checkpoint if available.");
			options.addOption(null, "ciphermap", true,
					"Optional, custom cipher map YAML file (replaces built-in).");
			options.addOption(null, "riskrules", true,
					"Optional, user risk rules YAML file (merged with system rules).");
			options.addOption(null, "sysriskrules", true,
					"Optional, system risk rules overlay YAML file (replaces built-in).");
			options.addOption(null, "password-env", true,
					"Optional, env var name containing transfer password for .dvscan files.");
			options.addOption(null, "password-file", true,
					"Optional, file containing transfer password for .dvscan files.");

			// Mutually exclusive options
			OptionGroup certsource = new OptionGroup();
			certsource.addOption(new Option("h", "help", false, "Optional, print dvcli help options."));
			certsource.addOption(new Option("u", "serverurl", true,
					"Required for all options except -readcertificate, HTTPS server URL to scan."));
			certsource.addOption(new Option("rc", "readcertificate", true,
					"Optional, read PEM encoded certificate from disk. Ex: -rc ~/certs/mycert.pem"));
			certsource.addOption(Option.builder().longOpt("scan").hasArg()
					.desc("Comma-separated targets for scan.").build());
			certsource.addOption(Option.builder().longOpt("scan-file").hasArg()
					.desc("File containing targets (one per line).").build());
			certsource.addOption(Option.builder().longOpt("delta").hasArg()
					.desc("Compare two .dvscan files: --delta base.dvscan,target.dvscan").build());
			certsource.addOption(Option.builder().longOpt("validate").hasArg()
					.desc("Validate DV API results against openssl for a host.").build());
			certsource.setRequired(true);
			options.addOptionGroup(certsource);

			// Use DefaultParser instead of deprecated BasicParser
			CommandLineParser p = new DefaultParser();
			CommandLine cmdline = null;

			try {
				cmdline = p.parse(options, args);
			} catch (ParseException e) {
				String msg = e.getMessage();
				if (msg != null && msg.startsWith("Missing required option")) {
					System.err.println("Error: No command specified. Use -h for help.");
				} else {
					System.err.println("Error: " + msg);
					System.err.println("Use -h for help.");
				}
				System.exit(-1);
			}

			if (cmdline == null) {
				logger.error("Null cmdline returned from parse, exiting.");
				System.exit(-1);
			}

			// Check for delta mode
			if (cmdline.hasOption("delta")) {
				runDeltaMode(cmdline);
				return;
			}

			// Check for validate mode
			if (cmdline.hasOption("validate")) {
				runValidateMode(cmdline);
				return;
			}

			// Check for scan mode
			boolean isScanMode = cmdline.hasOption("scan") || cmdline.hasOption("scan-file");

			if (!isScanMode && !cmdline.hasOption("u")) {
				if (!cmdline.hasOption("h") && !cmdline.hasOption("rc")) {
					logger.error("No HTTPS server specified, exiting.");
					System.exit(-1);
				}
			} else if (!isScanMode && cmdline.hasOption("u")) {

				String host = cmdline.getOptionValue('u');
				if (!host.startsWith("https")) {
					logger.error("Requires URL scheme type, HTTPS, exiting.");
					System.exit(-1);
				}
			}

			// Process debug option
			if (cmdline.hasOption("d")) {
				System.setProperty("javax.net.debug", "all");
			} else {
				System.getProperties().remove("javax.net.debug");
			}

			// Process debug option
			if (cmdline.hasOption("d2")) {
				System.setProperty("dv_user_level", "DEBUG");
			}

			// print help options
			if (cmdline.hasOption("h")) {
				// Generate help options

				StringBuilder hm = new StringBuilder();
				hm.append("java -jar dvcli.jar -serverurl <host|ip> [-wc <file> | -rc <file>] [-h -s{t|h|r|c|i|s|n|v|x|f}] [-o <file> -f <format>]")
						.append(EOL);
				hm.append("Ex: dvcli.jar -serverurl https://www.host.com/ -sections ts").append(EOL);
				hm.append("Ex: dvcli.jar -serverurl https://www.host.com/ -o report.pdf").append(EOL);
				hm.append("Ex: dvcli.jar -serverurl https://www.host.com/ -o report.html -f html").append(EOL);
				hm.append("Ex: dvcli.jar -serverurl https://www.host.com/ -o report.json").append(EOL);
				hm.append("-d SSL/TLS connection debugging").append(EOL);
				hm.append("-d2 Enable logback DEBUG level logging").append(EOL);
				hm.append("-o Write report to file (txt, html, pdf, json). Format inferred from extension.").append(EOL);
				hm.append("-f Explicit format: txt, html, pdf, json. Overrides extension inference.").append(EOL);
				hm.append("With -s option, sections are the following,").append(EOL);
				hm.append("a=TLS risk assessment section, e=runtime environment,").append(EOL);
				hm.append("h=host section, r=http response section,").append(EOL);
				hm.append("c=connection characteristics section, i=cipher suites section,").append(EOL);
				hm.append("s=server certificate section, n=certificate chain section,").append(EOL);
				hm.append("v=certificate revocation status section, x=security headers analysis,").append(EOL);
				hm.append("f=TLS Probe Fingerprint section").append(EOL);
				hm.append("--ai Enable AI evaluation section in report").append(EOL);
				hm.append("--ai-provider AI provider: anthropic, openai, ollama (default: from saved config)").append(EOL);
				hm.append("--ai-model AI model name (default: from saved config)").append(EOL);
				hm.append("--ai-key API key (overrides saved; prefer env var DV_AI_API_KEY)").append(EOL);
				hm.append("--ai-endpoint Ollama endpoint URL (default: http://localhost:11434)").append(EOL);
				hm.append("--proto-sslv3 Enable SSLv3 probing").append(EOL);
				hm.append("--proto-tls10 Enable TLS 1.0 probing").append(EOL);
				hm.append("--proto-tls11 Enable TLS 1.1 probing").append(EOL);
				hm.append("--proto-tls12 Enable TLS 1.2 probing").append(EOL);
				hm.append("--proto-tls13 Enable TLS 1.3 probing").append(EOL);
				hm.append("When any --proto-* flag is present, only those protocols are probed.").append(EOL);
				hm.append("").append(EOL);
				hm.append("Multi-target scanning:").append(EOL);
				hm.append("Ex: dvcli.jar --scan example.com,google.com").append(EOL);
				hm.append("Ex: dvcli.jar --scan-file targets.txt -o scan-report.html").append(EOL);
				hm.append("--scan Comma-separated targets for scan").append(EOL);
				hm.append("--scan-file File containing targets (one per line, # comments)").append(EOL);
				hm.append("--scan-threads Worker thread count (default: 3, range 1-10)").append(EOL);
				hm.append("--scan-throttle Delay in ms between hosts (default: 150, range 0-10000)").append(EOL);
				hm.append("--max-retries  Max retry attempts per section (default: 3, range 0-10)").append(EOL);
				hm.append("--retry-delay  Initial retry delay in ms (default: 500, range 100-10000)").append(EOL);
				hm.append("--retry-max-delay Max retry delay in ms (default: 4000, range 100-30000)").append(EOL);
				hm.append("--retry-budget Total retry budget in ms (default: 15000, range 1000-120000)").append(EOL);
				hm.append("--restore-point Save checkpoint every N hosts (default: 20, range 5-1000)").append(EOL);
				hm.append("--resume        Resume scan from last checkpoint if available").append(EOL);
				hm.append("").append(EOL);
				hm.append("Delta scanning:").append(EOL);
				hm.append("Ex: dvcli.jar --delta base.dvscan,target.dvscan").append(EOL);
				hm.append("Ex: dvcli.jar --delta base.dvscan,target.dvscan -o delta-report.html").append(EOL);
				hm.append("--delta Compare two .dvscan files (comma-separated paths)").append(EOL);
				hm.append("").append(EOL);
				hm.append("Custom overlays:").append(EOL);
				hm.append("--ciphermap <path> Custom cipher map YAML file (replaces built-in)").append(EOL);
				hm.append("--riskrules <path> User risk rules YAML file (merged with system rules)").append(EOL);
				hm.append("--sysriskrules <path> System risk rules overlay YAML file (replaces built-in)").append(EOL);
				hm.append("").append(EOL);
				hm.append("Transfer password (for cross-machine .dvscan files):").append(EOL);
				hm.append("--password-env <var> Env var name containing transfer password").append(EOL);
				hm.append("--password-file <path> File containing transfer password").append(EOL);
				hm.append("").append(EOL);
				hm.append("Validation:").append(EOL);
				hm.append("Ex: dvcli.jar --validate google.com").append(EOL);
				hm.append("Ex: dvcli.jar --validate expired.badssl.com").append(EOL);
				hm.append("--validate <host> Compare DV API results against openssl (requires openssl installed)").append(EOL);
				hm.append("").append(EOL);

				HelpFormatter formatter = new HelpFormatter();
				formatter.printHelp(hm.toString(), options);

				System.exit(0);
			}

			// ---- Scan mode ----
			if (isScanMode) {
				runScanMode(cmdline);
				return;
			}

			// ---- Single-host mode ----
			URL url = cmdline.hasOption("u") ? new URL(cmdline.getOptionValue("u")) : null;
			final UIBackgroundScanTask st = new UIBackgroundScanTask(url);

			st.bReadCertificate = cmdline.hasOption("rc");
			st.bWriteCertificate = cmdline.hasOption("wc");
			if (st.bWriteCertificate) st.setFilename(cmdline.getOptionValue("wc"));
			if (st.bReadCertificate) st.setFilename(cmdline.getOptionValue("rc"));

			// Protocol version filtering
			boolean hasProtoFlags = cmdline.hasOption("proto-sslv3")
					|| cmdline.hasOption("proto-tls10") || cmdline.hasOption("proto-tls11")
					|| cmdline.hasOption("proto-tls12") || cmdline.hasOption("proto-tls13");
			if (hasProtoFlags) {
				// When any --proto-* flag is present, use explicit selection
				st.protocolSslv3 = cmdline.hasOption("proto-sslv3");
				st.protocolTls10 = cmdline.hasOption("proto-tls10");
				st.protocolTls11 = cmdline.hasOption("proto-tls11");
				st.protocolTls12 = cmdline.hasOption("proto-tls12");
				st.protocolTls13 = cmdline.hasOption("proto-tls13");
			}
			// else defaults: TLS 1.2 + TLS 1.3

			// grab all section options
			String section_options = cmdline.getOptionValue("s");

			// If no sections specified default to all
			if (!cmdline.hasOption("s")) {

				// Unless we are writing a certificate to a file.
				// In which case we default to no sections.
				if (cmdline.hasOption("wc")) {
					st.bRiskAssessmentSection = false;
					st.bHeader = true; // URL not required
					st.bRuntimeEnvironmentSection = false;
					st.bHostSection = false;
					st.bHTTPResponseSection = false;
					st.bConnectionSection = false;
					st.bCipherSuiteSection = false;
					st.bCertChainSection = false;
					st.bSecurityHeadersSection = false;
					st.bRevocationSection = false;
					st.bTlsFingerprintSection = false;
					st.bReadCertificate = false;
				} else if (cmdline.hasOption("rc")) {
					st.bRiskAssessmentSection = false;
					st.bHeader = false;
					st.bRuntimeEnvironmentSection = false;
					st.bHostSection = false;
					st.bHTTPResponseSection = false;
					st.bConnectionSection = false;
					st.bCipherSuiteSection = false;
					st.bReadCertificate = true;
					st.bCertChainSection = false;
					st.bSecurityHeadersSection = false;
					st.bRevocationSection = false;
					st.bTlsFingerprintSection = false;
				} else {
					st.bRiskAssessmentSection = true;
					st.bHeader = true;
					st.bRuntimeEnvironmentSection = true;
					st.bHostSection = true;
					st.bHTTPResponseSection = true;
					st.bConnectionSection = true;
					st.bCipherSuiteSection = true;
					st.bCertChainSection = true;
					st.bSecurityHeadersSection = true;
					st.bRevocationSection = true;
					st.bTlsFingerprintSection = true;
					st.bReadCertificate = false;
				}

				// Sections are specified
			} else {

				// If certificate is being read from file fail on s settings
				if (!cmdline.hasOption("rc")) {

					// s options=aehrcisnavxf

					// Print risk assessment section
					st.bRiskAssessmentSection = section_options.lastIndexOf('a') > -1;

					// Header is always included
					st.bHeader = true;

					// Print runtime environment section
					st.bRuntimeEnvironmentSection = section_options.lastIndexOf('e') > -1;

					// Print host section
					st.bHostSection = section_options.lastIndexOf('h') > -1;

					// Print HTTP response header section
					st.bHTTPResponseSection = section_options.lastIndexOf('r') > -1;

					// Print connections characteristics section
					st.bConnectionSection = section_options.lastIndexOf('c') > -1;

					// Print supported cipher suites section
					st.bCipherSuiteSection = section_options.lastIndexOf('i') > -1;

					// Print server certificate chain section ('s' or 'n')
					st.bCertChainSection = section_options.lastIndexOf('s') > -1
							|| section_options.lastIndexOf('n') > -1;

					// Print certificate revocation status section
					st.bRevocationSection = section_options.lastIndexOf('v') > -1;

					// Print security headers analysis section
					st.bSecurityHeadersSection = section_options.lastIndexOf('x') > -1;

					// Print TLS Probe Fingerprint section
					st.bTlsFingerprintSection = section_options.lastIndexOf('f') > -1;

					st.bReadCertificate = false;

				} else {

					logger.error("'rc' option and 's' option are mutually exclusive, exiting.");
					System.exit(-1);
				}

			}

			// AI evaluation
			if (cmdline.hasOption("ai")) {
				st.bAiEvaluationSection = true;

				FontPreferences savedPrefs = FontPreferences.load();
				String apiKey = cmdline.getOptionValue("ai-key");
				if (apiKey == null) apiKey = System.getenv("DV_AI_API_KEY");
				if (apiKey == null) apiKey = savedPrefs.getAiApiKey();

				String provider = cmdline.hasOption("ai-provider")
						? cmdline.getOptionValue("ai-provider") : savedPrefs.getAiProvider();
				String model = cmdline.hasOption("ai-model")
						? cmdline.getOptionValue("ai-model") : savedPrefs.getAiModel();
				String endpointUrl = cmdline.hasOption("ai-endpoint")
						? cmdline.getOptionValue("ai-endpoint") : savedPrefs.getAiEndpointUrl();

				st.setAiConfig(apiKey, provider, model,
						savedPrefs.getAiMaxTokens(), savedPrefs.getAiTemperature(),
						savedPrefs.getAiSystemPrompt(), endpointUrl);
			}

			// Resolve output file and format
			String outputPath = cmdline.getOptionValue("o");
			String formatOpt = cmdline.getOptionValue("f");
			String format = resolveFormat(outputPath, formatOpt);

			if ("pdf".equals(format) && outputPath == null) {
				logger.error("PDF format requires -o <file>, exiting.");
				System.exit(-1);
			}

			// Custom cipher map
			if (cmdline.hasOption("ciphermap")) {
				File cmFile = new File(cmdline.getOptionValue("ciphermap"));
				if (!cmFile.exists()) {
					logger.error("Cipher map file not found: " + cmFile.getAbsolutePath());
					System.exit(-1);
				}
				DeepVioletFactory.loadCipherMap(new java.io.FileInputStream(cmFile));
			} else {
				FontPreferences savedPrefs2 = FontPreferences.load();
				if (savedPrefs2.isCustomCipherMapEnabled()) {
					String cmYaml = FontPreferences.loadCustomCipherMapYaml();
					if (cmYaml != null && !cmYaml.isBlank()) {
						DeepVioletFactory.loadCipherMap(new java.io.ByteArrayInputStream(
								cmYaml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
					}
				}
			}

			// System risk rules overlay
			if (cmdline.hasOption("sysriskrules")) {
				File srrFile = new File(cmdline.getOptionValue("sysriskrules"));
				if (!srrFile.exists()) {
					logger.error("System risk rules file not found: " + srrFile.getAbsolutePath());
					System.exit(-1);
				}
				st.setSystemRiskRulesYaml(java.nio.file.Files.readString(
						srrFile.toPath(), java.nio.charset.StandardCharsets.UTF_8));
			} else {
				FontPreferences savedPrefs2b = FontPreferences.load();
				if (savedPrefs2b.isSystemRiskRulesEnabled()) {
					String srrYaml = FontPreferences.loadSystemRiskRulesYaml();
					if (srrYaml != null && !srrYaml.isBlank()) {
						st.setSystemRiskRulesYaml(srrYaml);
					}
				}
			}

			// User risk rules
			if (cmdline.hasOption("riskrules")) {
				File rrFile = new File(cmdline.getOptionValue("riskrules"));
				if (!rrFile.exists()) {
					logger.error("Risk rules file not found: " + rrFile.getAbsolutePath());
					System.exit(-1);
				}
				st.setUserRiskRulesYaml(java.nio.file.Files.readString(
						rrFile.toPath(), java.nio.charset.StandardCharsets.UTF_8));
			} else {
				FontPreferences savedPrefs3 = FontPreferences.load();
				if (savedPrefs3.isUserRiskRulesEnabled()) {
					String rrYaml = FontPreferences.loadUserRiskRulesYaml();
					if (rrYaml != null && !rrYaml.isBlank()) {
						st.setUserRiskRulesYaml(rrYaml);
					}
				}
			}

			// Fire up the worker thread and update status
			long start = System.currentTimeMillis();

			st.start();
			updateLongRunningCMDStatus(st);

			// Block until background thread completes.
			while (st.isWorking()) {
				Thread.yield();
			}

			// Filter the tree to only include sections the user requested.
			// The scan always runs all sections; the -s flags control display.
			Set<String> hideSections = new HashSet<>();
			if (!st.bRuntimeEnvironmentSection) hideSections.add("Runtime environment");
			if (!st.bRiskAssessmentSection) hideSections.add("TLS Risk Assessment");
			if (!st.bHostSection) hideSections.add("Host information");
			if (!st.bHTTPResponseSection) hideSections.add("HTTP(S) response headers");
			if (!st.bSecurityHeadersSection) hideSections.add("Security headers analysis");
			if (!st.bConnectionSection) hideSections.add("Connection characteristics");
			if (!st.bCipherSuiteSection) hideSections.add("Server cipher suites");
			if (!st.bCertChainSection) {
				hideSections.add("Server certificate chain");
				hideSections.add("Chain details");
			}
			if (!st.bRevocationSection) hideSections.add("Certificate revocation status");
			if (!st.bTlsFingerprintSection) hideSections.add("TLS Probe Fingerprint");
			if (!hideSections.isEmpty()) {
				st.getResultTree().removeSections(hideSections);
			}

			// Output results
			if (outputPath != null) {
				File outFile = new File(outputPath);
				// Add extension if missing
				if (!outFile.getName().contains(".")) {
					outFile = new File(outputPath + "." + format);
				}
				FontPreferences prefs = FontPreferences.load();
				switch (format) {
					case "html":
						ReportExporter.saveAsHtml(outFile, st.getResultTree(), prefs);
						break;
					case "pdf":
						ReportExporter.saveAsPdf(outFile, st.getResultTree(), prefs);
						break;
					case "json":
						ReportExporter.saveAsJson(outFile, st.getResultTree());
						break;
					default:
						ReportExporter.saveAsText(outFile, st.getResultTree());
						break;
				}
				logger.info("Report written to " + outFile.getAbsolutePath() + " (" + format + ")");
			} else if ("json".equals(format)) {
				System.out.print(ReportExporter.toJsonString(st.getResultTree()));
			} else {
				System.out.print(st.toPlainText());
			}

			long finish = System.currentTimeMillis();
			logger.info("Processing complete, execution(ms)=" + (finish - start));

		} catch (Throwable t) {

			logger.error(t.getMessage(), t);
			System.exit(-1);
		}

	}

	/**
	 * Resolve the output format from explicit -f option, file extension,
	 * or the last saved format from shared config.
	 */
	private String resolveFormat(String outputPath, String formatOpt) {
		// Explicit -f takes precedence
		if (formatOpt != null) {
			String f = formatOpt.toLowerCase().trim();
			if ("txt".equals(f) || "html".equals(f) || "pdf".equals(f) || "json".equals(f)) {
				return f;
			}
			logger.warn("Unknown format '" + formatOpt + "', inferring from file extension or config.");
		}
		// Infer from file extension
		if (outputPath != null) {
			String lower = outputPath.toLowerCase();
			if (lower.endsWith(".html") || lower.endsWith(".htm")) return "html";
			if (lower.endsWith(".pdf")) return "pdf";
			if (lower.endsWith(".json")) return "json";
			if (lower.endsWith(".txt")) return "txt";
		}
		// Fall back to last saved format from shared config
		String lastFormat = FontPreferences.loadLastSaveFormat();
		if ("html".equals(lastFormat) || "pdf".equals(lastFormat) || "json".equals(lastFormat)) {
			return lastFormat;
		}
		return "txt";
	}

	/**
	 * Run multi-target scanning mode. Parses targets from --scan or --scan-file,
	 * scans each target, and outputs heat map results.
	 */
	private void runScanMode(CommandLine cmdline) throws Exception {
		FontPreferences prefs = FontPreferences.load();

		// Apply CIDR expansion limit from preferences
		TargetParser.setMaxCidrExpansion(prefs.getMaxCidrExpansion());

		// Parse targets
		List<String> targetUrls;
		if (cmdline.hasOption("scan")) {
			targetUrls = TargetParser.parse(cmdline.getOptionValue("scan"));
		} else {
			File targetFile = new File(cmdline.getOptionValue("scan-file"));
			if (!targetFile.exists()) {
				logger.error("Scan file not found: " + targetFile.getAbsolutePath());
				System.exit(-1);
				return;
			}
			targetUrls = TargetParser.parseFile(targetFile);
		}

		if (targetUrls.isEmpty()) {
			logger.error("No valid targets found, exiting.");
			System.exit(-1);
			return;
		}

		int scanScale = FontPreferences.SCAN_SCALE;

		logger.info("Scan: " + targetUrls.size() + " targets, scale=" + scanScale);

		// Determine engine preferences from -s options or scan-specific prefs
		boolean bRiskAssessment, bHeader = false, bHost = false, bHttpResponse;
		boolean bConnection, bCipherSuites, bCertChain, bSecurityHeaders;
		boolean bRevocation, bTlsFingerprint;

		String sectionOptions = cmdline.getOptionValue("s");
		if (sectionOptions != null) {
			bRiskAssessment = sectionOptions.indexOf('a') > -1;
			bHeader = sectionOptions.indexOf('t') > -1;
			bHost = sectionOptions.indexOf('h') > -1;
			bHttpResponse = sectionOptions.indexOf('r') > -1;
			bConnection = sectionOptions.indexOf('c') > -1;
			bCipherSuites = sectionOptions.indexOf('i') > -1;
			bCertChain = sectionOptions.indexOf('s') > -1 || sectionOptions.indexOf('n') > -1;
			bSecurityHeaders = sectionOptions.indexOf('x') > -1;
			bRevocation = sectionOptions.indexOf('v') > -1;
			bTlsFingerprint = sectionOptions.indexOf('f') > -1;
		} else {
			// Use scan-specific preferences from saved config
			bRiskAssessment = prefs.isScanSectionRiskAssessment();
			bHttpResponse = prefs.isScanSectionHttpResponse();
			bConnection = prefs.isScanSectionConnection();
			bCipherSuites = prefs.isScanSectionCipherSuites();
			bCertChain = prefs.isScanSectionRiskAssessment(); // cert chain needed for risk cert rows
			bSecurityHeaders = prefs.isScanSectionSecurityHeaders();
			bRevocation = prefs.isScanSectionRevocation();
			bTlsFingerprint = prefs.isScanSectionTlsFingerprint();
		}

		// Protocol flags — CLI flags override scan preferences
		boolean hasProtoFlags = cmdline.hasOption("proto-sslv3")
				|| cmdline.hasOption("proto-tls10") || cmdline.hasOption("proto-tls11")
				|| cmdline.hasOption("proto-tls12") || cmdline.hasOption("proto-tls13");
		boolean sslv3, tls10, tls11, tls12, tls13;
		if (hasProtoFlags) {
			sslv3 = cmdline.hasOption("proto-sslv3");
			tls10 = cmdline.hasOption("proto-tls10");
			tls11 = cmdline.hasOption("proto-tls11");
			tls12 = cmdline.hasOption("proto-tls12");
			tls13 = cmdline.hasOption("proto-tls13");
		} else {
			sslv3 = prefs.isScanProtocolSslv3();
			tls10 = prefs.isScanProtocolTls10();
			tls11 = prefs.isScanProtocolTls11();
			tls12 = prefs.isScanProtocolTls12();
			tls13 = prefs.isScanProtocolTls13();
		}

		CIPHER_NAME_CONVENTION convention = CIPHER_NAME_CONVENTION.IANA;
		try {
			convention = CIPHER_NAME_CONVENTION.valueOf(prefs.getScanCipherConvention());
		} catch (IllegalArgumentException e) {
			logger.warn("Unknown cipher convention, defaulting to IANA");
		}
		int riskScale = prefs.getRiskScale();

		// Create and configure scan task
		ScanTask scanTask = new ScanTask(targetUrls);
		scanTask.applyPreferences(
				bRiskAssessment, bHeader, bHost, bHttpResponse, bConnection,
				bCipherSuites, bCertChain, bSecurityHeaders, bRevocation, bTlsFingerprint,
				sslv3, tls10, tls11, tls12, tls13, convention, riskScale);

		// Worker threads and throttle delay
		int workerThreads = prefs.getScanWorkerThreads();
		if (cmdline.hasOption("scan-threads")) {
			try {
				workerThreads = Integer.parseInt(cmdline.getOptionValue("scan-threads"));
				workerThreads = Math.max(1, Math.min(10, workerThreads));
			} catch (NumberFormatException e) {
				logger.warn("Invalid scan-threads value, using default: " + workerThreads);
			}
		}
		scanTask.setWorkerThreadCount(workerThreads);

		long throttleDelay = prefs.getScanThrottleDelayMs();
		if (cmdline.hasOption("scan-throttle")) {
			try {
				throttleDelay = Long.parseLong(cmdline.getOptionValue("scan-throttle"));
				throttleDelay = Math.max(0, Math.min(10000, throttleDelay));
			} catch (NumberFormatException e) {
				logger.warn("Invalid scan-throttle value, using default: " + throttleDelay);
			}
		}
		scanTask.setThrottleDelayMs(throttleDelay);

		// Connection retry settings
		int maxRetries = prefs.getMaxRetries();
		if (cmdline.hasOption("max-retries")) {
			try {
				maxRetries = Integer.parseInt(cmdline.getOptionValue("max-retries"));
				maxRetries = Math.max(0, Math.min(10, maxRetries));
			} catch (NumberFormatException e) {
				logger.warn("Invalid max-retries value, using default: " + maxRetries);
			}
		}
		scanTask.setMaxRetries(maxRetries);

		long initialRetryDelay = prefs.getInitialRetryDelayMs();
		if (cmdline.hasOption("retry-delay")) {
			try {
				initialRetryDelay = Long.parseLong(cmdline.getOptionValue("retry-delay"));
				initialRetryDelay = Math.max(100, Math.min(10000, initialRetryDelay));
			} catch (NumberFormatException e) {
				logger.warn("Invalid retry-delay value, using default: " + initialRetryDelay);
			}
		}
		scanTask.setInitialRetryDelayMs(initialRetryDelay);

		long maxRetryDelay = prefs.getMaxRetryDelayMs();
		if (cmdline.hasOption("retry-max-delay")) {
			try {
				maxRetryDelay = Long.parseLong(cmdline.getOptionValue("retry-max-delay"));
				maxRetryDelay = Math.max(100, Math.min(30000, maxRetryDelay));
			} catch (NumberFormatException e) {
				logger.warn("Invalid retry-max-delay value, using default: " + maxRetryDelay);
			}
		}
		scanTask.setMaxRetryDelayMs(maxRetryDelay);

		long retryBudget = prefs.getRetryBudgetMs();
		if (cmdline.hasOption("retry-budget")) {
			try {
				retryBudget = Long.parseLong(cmdline.getOptionValue("retry-budget"));
				retryBudget = Math.max(1000, Math.min(120000, retryBudget));
			} catch (NumberFormatException e) {
				logger.warn("Invalid retry-budget value, using default: " + retryBudget);
			}
		}
		scanTask.setRetryBudgetMs(retryBudget);

		// Restore point — checkpoint every N hosts
		int restoreInterval = prefs.getRestorePointInterval();
		if (cmdline.hasOption("restore-point")) {
			try {
				restoreInterval = Integer.parseInt(cmdline.getOptionValue("restore-point"));
				restoreInterval = Math.max(5, Math.min(1000, restoreInterval));
			} catch (NumberFormatException e) {
				logger.warn("Invalid restore-point value, using default: " + restoreInterval);
			}
		}
		scanTask.setRestorePointInterval(restoreInterval);

		// Checkpoint file in scans directory
		File scansDir = new File(FontPreferences.getHomeDir(), "ui" + File.separator + "scans");
		scansDir.mkdirs();
		File checkpointFile = new File(scansDir, ".scan-checkpoint.dvscan");

		// Resume from checkpoint if requested
		if (cmdline.hasOption("resume") && checkpointFile.exists()) {
			try {
				ScanResult checkpoint = ReportExporter.loadScanFile(checkpointFile, null);
				scanTask.resumeFrom(checkpoint);
				System.out.println("Resuming from checkpoint: " + checkpoint.getResults().size()
						+ " hosts already scanned");
			} catch (IOException ex) {
				logger.warn("Failed to load checkpoint, starting fresh: {}", ex.getMessage());
			}
		}

		// Wire checkpoint callback — saves every N hosts
		scanTask.setCheckpointCallback(result -> {
			try {
				File tmpFile = new File(scansDir, ".scan-checkpoint.tmp");
				ReportExporter.saveScanFile(tmpFile, result);
				if (checkpointFile.exists()) checkpointFile.delete();
				tmpFile.renameTo(checkpointFile);
				logger.info("Checkpoint saved: {} hosts completed", result.getResults().size());
			} catch (Exception e) {
				logger.warn("Failed to save checkpoint: {}", e.getMessage());
			}
		});

		// Custom cipher map
		if (cmdline.hasOption("ciphermap")) {
			File cmFile = new File(cmdline.getOptionValue("ciphermap"));
			if (!cmFile.exists()) {
				logger.error("Cipher map file not found: " + cmFile.getAbsolutePath());
				System.exit(-1);
				return;
			}
			DeepVioletFactory.loadCipherMap(new java.io.FileInputStream(cmFile));
		} else if (prefs.isCustomCipherMapEnabled()) {
			String cmYaml = FontPreferences.loadCustomCipherMapYaml();
			if (cmYaml != null && !cmYaml.isBlank()) {
				DeepVioletFactory.loadCipherMap(new java.io.ByteArrayInputStream(
						cmYaml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
			}
		}

		// System risk rules overlay
		if (cmdline.hasOption("sysriskrules")) {
			File srrFile = new File(cmdline.getOptionValue("sysriskrules"));
			if (!srrFile.exists()) {
				logger.error("System risk rules file not found: " + srrFile.getAbsolutePath());
				System.exit(-1);
				return;
			}
			scanTask.setSystemRiskRulesYaml(java.nio.file.Files.readString(
					srrFile.toPath(), java.nio.charset.StandardCharsets.UTF_8));
		} else if (prefs.isSystemRiskRulesEnabled()) {
			String srrYaml = FontPreferences.loadSystemRiskRulesYaml();
			if (srrYaml != null && !srrYaml.isBlank()) {
				scanTask.setSystemRiskRulesYaml(srrYaml);
			}
		}

		// User risk rules
		if (cmdline.hasOption("riskrules")) {
			File rrFile = new File(cmdline.getOptionValue("riskrules"));
			if (!rrFile.exists()) {
				logger.error("Risk rules file not found: " + rrFile.getAbsolutePath());
				System.exit(-1);
				return;
			}
			scanTask.setUserRiskRulesYaml(java.nio.file.Files.readString(
					rrFile.toPath(), java.nio.charset.StandardCharsets.UTF_8));
		} else if (prefs.isUserRiskRulesEnabled()) {
			String rrYaml = FontPreferences.loadUserRiskRulesYaml();
			if (rrYaml != null && !rrYaml.isBlank()) {
				scanTask.setUserRiskRulesYaml(rrYaml);
			}
		}

		scanTask.setProgressCallback((index, target) ->
				logger.info("[" + (index + 1) + "/" + targetUrls.size() + "] Scanning " + target + "..."));

		long start = System.currentTimeMillis();

		// Start scan and block until completion
		Thread scanThread = scanTask.start();
		scanThread.join();

		ScanResult result = scanTask.getResult();
		long finish = System.currentTimeMillis();

		// Clean up checkpoint file — scan completed
		if (checkpointFile.exists()) {
			checkpointFile.delete();
		}

		// Summary
		System.out.println();
		System.out.println("Scan complete: " + result.getSuccessCount() + "/"
				+ result.getTotalTargets() + " hosts scanned ("
				+ result.getErrorCount() + " errors), " + (finish - start) + "ms");
		System.out.println();

		// Output heat maps to console
		int scale = scanScale;
		System.out.print(ReportExporter.heatMapToText(result.toRiskHeatMap(scale)));
		System.out.print(ReportExporter.heatMapToText(result.toCipherHeatMap(scale)));
		System.out.print(ReportExporter.heatMapToText(result.toConnectionHeatMap(scale)));
		System.out.print(ReportExporter.heatMapToText(result.toFingerprintHeatMap(scale)));

		// Error summary
		for (ScanResult.HostResult hr : result.getResults()) {
			if (!hr.isSuccess()) {
				System.out.println("  ERROR: " + hr.getTargetUrl() + " - " + hr.getErrorMessage());
			}
		}

		// Auto-save individual host reports
		String timestamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss").format(new java.util.Date());
		File scanDir = new File(FontPreferences.getHomeDir(),
				"cli" + File.separator + "scans" + File.separator + timestamp);
		if (scanDir.mkdirs() || scanDir.isDirectory()) {
			int saved = 0;
			for (ScanResult.HostResult hr : result.getResults()) {
				if (hr.isSuccess() && hr.getScanTree() != null && hr.getScanTree().hasChildren()) {
					String hostName = hr.getTargetUrl()
							.replaceAll("https?://", "")
							.replaceAll("[:/]", "-")
							.replaceAll("-+$", "");
					File hostFile = new File(scanDir, hostName + ".txt");
					try (PrintWriter pw = new PrintWriter(hostFile)) {
						pw.print(ReportExporter.toPlainText(hr.getScanTree()));
						saved++;
					} catch (IOException e) {
						logger.warn("Failed to save host report for {}: {}", hr.getTargetUrl(), e.getMessage());
					}
				}
			}
			if (saved > 0) {
				logger.info("Individual host reports saved to " + scanDir.getAbsolutePath()
						+ " (" + saved + " files)");
			}
		}

		// Export to file if -o specified
		String outputPath = cmdline.getOptionValue("o");
		if (outputPath != null) {
			String formatOpt = cmdline.getOptionValue("f");
			String format = resolveFormat(outputPath, formatOpt);
			File outFile = new File(outputPath);
			if (!outFile.getName().contains(".")) {
				outFile = new File(outputPath + "." + format);
			}

			switch (format) {
				case "html":
					ReportExporter.saveScanAsHtml(outFile, result, scale);
					break;
				case "pdf":
					ReportExporter.saveScanAsPdf(outFile, result, scale,
							prefs.getRiskPass(), prefs.getRiskFail(), prefs.getRiskInconclusive());
					break;
				case "json":
					ReportExporter.saveScanAsJson(outFile, result);
					break;
				default:
					ReportExporter.saveScanAsText(outFile, result, scale);
					break;
			}
			logger.info("Scan report written to " + outFile.getAbsolutePath() + " (" + format + ")");
		}

		logger.info("Scan processing complete, execution(ms)=" + (finish - start));
	}

	/**
	 * Run delta comparison mode. Parses comma-separated .dvscan paths from
	 * --delta, loads both scans, compares, and outputs the delta report.
	 */
	private void runDeltaMode(CommandLine cmdline) throws Exception {
		FontPreferences.ensureEncryptionSeed();

		String deltaArg = cmdline.getOptionValue("delta");
		String[] paths = deltaArg.split(",", 2);
		if (paths.length != 2) {
			logger.error("--delta requires two comma-separated .dvscan file paths");
			System.exit(-1);
			return;
		}

		File baseFile = new File(paths[0].trim());
		File targetFile = new File(paths[1].trim());

		if (!baseFile.exists()) {
			logger.error("Base scan file not found: " + baseFile.getAbsolutePath());
			System.exit(-1);
			return;
		}
		if (!targetFile.exists()) {
			logger.error("Target scan file not found: " + targetFile.getAbsolutePath());
			System.exit(-1);
			return;
		}

		logger.info("Delta scan: comparing " + baseFile.getName()
				+ " vs " + targetFile.getName());

		com.mps.deepviolet.persist.ScanFileIO.PasswordCallback pwCb = buildPasswordCallback(cmdline);
		ScanResult base = ReportExporter.loadScanFile(baseFile, pwCb);
		ScanResult target = ReportExporter.loadScanFile(targetFile, pwCb);

		DeltaScanResult result = DeltaScanner.compare(
				base, target, baseFile, targetFile);

		// Output
		String outputPath = cmdline.getOptionValue("o");
		if (outputPath != null) {
			String formatOpt = cmdline.getOptionValue("f");
			String format = resolveFormat(outputPath, formatOpt);
			File outFile = new File(outputPath);
			if (!outFile.getName().contains(".")) {
				outFile = new File(outputPath + "." + format);
			}

			switch (format) {
				case "html":
					ReportExporter.saveDeltaAsHtml(outFile, result);
					break;
				case "pdf":
					ReportExporter.saveDeltaAsPdf(outFile, result);
					break;
				case "json":
					ReportExporter.saveDeltaAsJson(outFile, result);
					break;
				default:
					ReportExporter.saveDeltaAsText(outFile, result);
					break;
			}
			logger.info("Delta report written to " + outFile.getAbsolutePath()
					+ " (" + format + ")");
		} else {
			System.out.print(ReportExporter.deltaToPlainText(result));
		}

		logger.info("Delta comparison complete: " + result.getChangedCount()
				+ " changed, " + result.getAddedCount() + " added, "
				+ result.getRemovedCount() + " removed, "
				+ result.getUnchangedCount() + " unchanged");
	}

	/**
	 * Run validation mode. Compares DV API results against openssl for a host.
	 */
	private void runValidateMode(CommandLine cmdline) {
		String host = cmdline.getOptionValue("validate");
		if (host == null || host.isBlank()) {
			logger.error("--validate requires a host argument");
			System.exit(-1);
			return;
		}

		// Strip protocol prefix if provided
		if (host.startsWith("https://")) {
			host = host.substring(8);
		} else if (host.startsWith("http://")) {
			host = host.substring(7);
		}
		// Strip trailing slash and path
		int slashIdx = host.indexOf('/');
		if (slashIdx > 0) {
			host = host.substring(0, slashIdx);
		}

		// Extract port if specified as host:port
		int port = 443;
		int colonIdx = host.lastIndexOf(':');
		if (colonIdx > 0) {
			try {
				port = Integer.parseInt(host.substring(colonIdx + 1));
				host = host.substring(0, colonIdx);
			} catch (NumberFormatException e) {
				// Not a port, leave host as-is
			}
		}

		ApiValidator validator = new ApiValidator();
		var result = validator.validate(host, port);

		String formatOpt = cmdline.getOptionValue("f");
		if ("json".equals(formatOpt)) {
			validator.printJson(result, System.out);
		} else {
			validator.printResult(result, System.out);
		}

		System.exit(result.isAllMatched() || !result.isDvSessionSucceeded() ? 0 : 1);
	}

	/**
	 * Update tick every 5 seconds
	 *
	 * @param task Background scan task
	 */
	private void updateLongRunningCMDStatus(final UIBackgroundScanTask task) {

		// Instance logger. Need to define working dir before we can create.
		final Logger logger = LoggerFactory.getLogger("com.mps.deepviolettools.bin.StartCMD");

		// Background update thread. Display scan results in progress
		final int delay = 500; // Update interval
		ActionListener taskPerformer = new ActionListener() {
			int ct = 0;

			public void actionPerformed(ActionEvent evt) {
				if (task.isWorking()) {
					ct += delay;
					if (ct % 15000 == 0) {
						logger.info("Still busy, " + ct / 1000 + " seconds elapsed.");
					}
				} else {
					// Scan done, stop timer.
					((Timer) evt.getSource()).stop();
				}
			}
		};
		new Timer(delay, taskPerformer).start();

	}

	/**
	 * Build a PasswordCallback from --password-env or --password-file CLI flags.
	 * Returns null if neither flag is specified.
	 */
	private com.mps.deepviolet.persist.ScanFileIO.PasswordCallback buildPasswordCallback(
			CommandLine cmdline) {
		if (cmdline.hasOption("password-env")) {
			String envVar = cmdline.getOptionValue("password-env");
			return () -> {
				String pw = System.getenv(envVar);
				if (pw == null) {
					throw new IOException("Environment variable not set: " + envVar);
				}
				return pw.toCharArray();
			};
		}
		if (cmdline.hasOption("password-file")) {
			String filePath = cmdline.getOptionValue("password-file");
			return () -> {
				String pw = java.nio.file.Files.readString(
						java.nio.file.Path.of(filePath)).trim();
				return pw.toCharArray();
			};
		}
		return null;
	}

}
