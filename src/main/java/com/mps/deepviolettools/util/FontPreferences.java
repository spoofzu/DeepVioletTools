package com.mps.deepviolettools.util;

import java.awt.Color;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Window;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.model.CardMetaElement;
import com.mps.deepviolettools.model.CardSize;
import com.mps.deepviolettools.model.CardSlotConfig;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages shared preferences (theme, colors, output format) persisted to
 * {@code ~/DeepVioletTools/deepviolet.properties} (or the directory specified by
 * the {@code deepviolet.home} system property).  Used by both the GUI and CLI.
 *
 * @author Milton Smith
 */
public class FontPreferences {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.util.FontPreferences");

	private static final String PROPS_FILE = "deepviolet.properties";

	public static File getHomeDir() {
		String override = System.getProperty("deepviolet.home");
		if (override != null && !override.isEmpty()) {
			return new File(override);
		}
		return new File(System.getProperty("user.home"), "DeepVioletTools");
	}

	// Migrate from old location on first access
	static {
		File oldFile = new File(System.getProperty("user.home"),
				"DeepVioletTools" + File.separator + "ui" + File.separator + "deepvioletui.properties");
		File newFile = new File(getHomeDir(), PROPS_FILE);
		if (oldFile.exists() && !newFile.exists()) {
			try {
				getHomeDir().mkdirs();
				java.nio.file.Files.copy(oldFile.toPath(), newFile.toPath());
				logger.info("Migrated preferences from {} to {}", oldFile, newFile);
			} catch (IOException e) {
				logger.warn("Could not migrate old preferences file", e);
			}
		}
	}

	/**
	 * Return the global config directory ({@code ~/.deepviolet/}).
	 * This is always relative to the real user home so that security
	 * material (encryption seed) survives home-dir wipes.  The location
	 * can be overridden with the {@code deepviolet.global} system property
	 * (used by tests).
	 */
	public static File getGlobalDir() {
		String override = System.getProperty("deepviolet.global");
		if (override != null && !override.isEmpty()) {
			return new File(override);
		}
		return new File(System.getProperty("user.home"), GLOBAL_DIR_NAME);
	}

	private static Properties loadGlobalProperties() {
		Properties props = new Properties();
		File file = new File(getGlobalDir(), GLOBAL_PROPS_FILE);
		if (file.exists()) {
			try (FileInputStream in = new FileInputStream(file)) {
				props.load(in);
			} catch (IOException e) {
				logger.error("Failed to load global properties file", e);
			}
		}
		return props;
	}

	private static void saveGlobalProperties(Properties props) {
		File dir = getGlobalDir();
		dir.mkdirs();
		File file = new File(dir, GLOBAL_PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet global settings — do not delete");
		} catch (IOException e) {
			logger.error("Failed to save global properties file", e);
		}
	}

	// System L&F defaults — captured from real Swing components after L&F is set.
	// Call captureSystemDefaults() from StartUI after UIManager.setLookAndFeel().
	private static Color sysLafPanelBg = new Color(0xEE, 0xEE, 0xEE);
	private static Color sysLafLabelFg = Color.BLACK;
	private static Color sysLafButtonBg = new Color(0xE0, 0xE0, 0xE0);
	private static Color sysLafButtonFg = Color.BLACK;
	private static Font sysLafFont = new Font("SansSerif", Font.PLAIN, 16);
	private static boolean systemDefaultsCaptured = false;

	/**
	 * Capture the actual system L&F colors and font by creating temporary
	 * Swing components. Must be called on the EDT after
	 * {@code UIManager.setLookAndFeel()} and before {@code FontPreferences.load()}.
	 */
	public static void captureSystemDefaults() {
		javax.swing.JPanel tempPanel = new javax.swing.JPanel();
		javax.swing.JLabel tempLabel = new javax.swing.JLabel("x");
		javax.swing.JButton tempButton = new javax.swing.JButton("x");

		sysLafPanelBg = tempPanel.getBackground();
		sysLafLabelFg = tempLabel.getForeground();
		sysLafButtonBg = tempButton.getBackground();
		sysLafButtonFg = tempButton.getForeground();
		sysLafFont = tempLabel.getFont().deriveFont((float) DEFAULT_FONT_SIZE);
		systemDefaultsCaptured = true;
		logger.debug("System L&F captured: bg={}, fg={}, btnBg={}, btnFg={}, font={}",
				sysLafPanelBg, sysLafLabelFg, sysLafButtonBg, sysLafButtonFg, sysLafFont);
	}

	/**
	 * Reset the application theme to system default by setting
	 * {@code app.theme.custom=false} in the properties file. All other
	 * settings (reporting colors, engine config, window bounds, URL history)
	 * are preserved. Intended as a CLI escape hatch when a custom theme
	 * renders the UI unreadable.
	 */
	public static void resetAppTheme() {
		Properties props = loadProperties();
		props.setProperty(KEY_APP_THEME_CUSTOM, "false");
		File dir = getHomeDir();
		dir.mkdirs();
		File file = new File(dir, PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
		} catch (IOException e) {
			logger.error("Failed to reset app theme", e);
		}
	}

	/**
	 * Load the accent color for use before FlatLaf is set up.  This reads
	 * saved preferences without requiring the L&amp;F to be installed yet.
	 *
	 * @param isDarkMode true if macOS dark mode is active
	 * @return the accent color to set as {@code @accentColor} before setup
	 */
	public static Color loadAccentForInit(boolean isDarkMode) {
		Properties props = loadProperties();
		boolean isCustom = "true".equalsIgnoreCase(
				props.getProperty(KEY_APP_THEME_CUSTOM, "false"));
		if (isCustom) {
			return deriveAccentFromButtonBg(props, isDarkMode);
		}
		// System mode: compute from approximate FlatLaf backgrounds
		if (isDarkMode) {
			return computeSubtleAccent(
					new Color(0x2B, 0x2B, 0x2B),
					new Color(0x3C, 0x3F, 0x41));
		} else {
			return computeSubtleAccent(
					new Color(0xF5, 0xF5, 0xF5),
					new Color(0xFF, 0xFF, 0xFF));
		}
	}

	/**
	 * Derive the accent color from the saved button background, with
	 * migration fallback to old control background key.
	 */
	private static Color deriveAccentFromButtonBg(Properties props, boolean isDarkMode) {
		Color windowBg = readColor(props, KEY_APP_COLOR_BG,
				isDarkMode ? new Color(0x2B, 0x2B, 0x2B) : new Color(0xFA, 0xFA, 0xFA));
		// Try new key first, fall back to old control key for migration
		Color buttonBg = readColor(props, KEY_APP_COLOR_BUTTON_BG, null);
		if (buttonBg == null) {
			buttonBg = readColor(props, "app.color.controlBackground",
					isDarkMode ? new Color(0x3C, 0x3F, 0x41) : new Color(0xE8, 0xE8, 0xE8));
		}
		return computeSubtleAccent(windowBg, buttonBg);
	}

	public static Color getSysPanelBg() { return sysLafPanelBg; }
	public static Color getSysLabelFg() { return sysLafLabelFg; }
	public static Color getSysButtonBg() { return sysLafButtonBg; }
	public static Color getSysButtonFg() { return sysLafButtonFg; }
	public static Font getSysFont() { return sysLafFont; }

	private static final String KEY_FONT_NAME = "font.name";
	private static final String KEY_FONT_SIZE = "font.size";
	private static final String KEY_COLOR_BG = "color.background";
	private static final String KEY_COLOR_DEFAULT = "color.default";
	private static final String KEY_COLOR_NOTICE = "color.notice";
	private static final String KEY_COLOR_HEADING = "color.heading";
	private static final String KEY_COLOR_CONTENT = "color.content";
	private static final String KEY_COLOR_KEY = "color.key";
	private static final String KEY_COLOR_VALUE = "color.value";
	private static final String KEY_COLOR_WARNING = "color.warning";
	private static final String KEY_COLOR_SUBSECTION = "color.subsection";
	private static final String KEY_COLOR_HIGHLIGHT = "color.highlight";
	private static final String KEY_COLOR_RISK_PASS = "color.riskPass";
	private static final String KEY_COLOR_RISK_INCONCLUSIVE = "color.riskInconclusive";
	private static final String KEY_COLOR_RISK_FAIL = "color.riskFail";
	private static final String KEY_COLOR_RISK_CRITICAL = "color.riskCritical";
	private static final String KEY_COLOR_RISK_HIGH = "color.riskHigh";
	private static final String KEY_COLOR_RISK_MEDIUM = "color.riskMedium";
	private static final String KEY_COLOR_RISK_LOW = "color.riskLow";
	private static final String KEY_COLOR_RISK_INFO = "color.riskInfo";
	private static final String KEY_WINDOW_X = "window.x";
	private static final String KEY_WINDOW_Y = "window.y";
	private static final String KEY_WINDOW_W = "window.width";
	private static final String KEY_WINDOW_H = "window.height";
	private static final String KEY_HARDWRAP_ENABLED = "hardwrap.enabled";
	private static final String KEY_HARDWRAP_WIDTH = "hardwrap.width";
	private static final String KEY_SAVE_LAST_FOLDER = "save.lastFolder";
	private static final String KEY_SAVE_LAST_FORMAT = "save.lastFormat";

	// Engine settings keys
	private static final String KEY_SECTION_RISK_ASSESSMENT = "engine.section.riskAssessment";
	private static final String KEY_SECTION_RUNTIME_ENV = "engine.section.runtimeEnvironment";
	private static final String KEY_SECTION_HOST = "engine.section.host";
	private static final String KEY_SECTION_HTTP_RESPONSE = "engine.section.httpResponse";
	private static final String KEY_SECTION_SECURITY_HEADERS = "engine.section.securityHeaders";
	private static final String KEY_SECTION_CONNECTION = "engine.section.connection";
	private static final String KEY_SECTION_CIPHER_SUITES = "engine.section.cipherSuites";
	private static final String KEY_SECTION_CERT_CHAIN = "engine.section.certChain";
	private static final String KEY_SECTION_REVOCATION = "engine.section.revocation";
	private static final String KEY_SECTION_TLS_FINGERPRINT = "engine.section.tlsFingerprint";
	private static final String KEY_CIPHER_CONVENTION = "engine.cipherConvention";
	private static final String KEY_PROTOCOL_SSLV3 = "engine.protocol.sslv3";
	private static final String KEY_PROTOCOL_TLS10 = "engine.protocol.tls10";
	private static final String KEY_PROTOCOL_TLS11 = "engine.protocol.tls11";
	private static final String KEY_PROTOCOL_TLS12 = "engine.protocol.tls12";
	private static final String KEY_PROTOCOL_TLS13 = "engine.protocol.tls13";
	private static final String KEY_RISK_SCALE = "engine.riskScale";
	private static final String KEY_BATCH_SCALE = "batch.scale";
	private static final String KEY_WORKER_THREADS = "engine.workerThreads";
	private static final String KEY_THROTTLE_DELAY_MS = "engine.throttleDelayMs";
	private static final String KEY_MAX_CIDR_EXPANSION = "engine.maxCidrExpansion";

	// Legacy batch keys — used only for migration fallback in load()
	private static final String KEY_BATCH_WORKER_THREADS = "batch.workerThreads";
	private static final String KEY_BATCH_THROTTLE_DELAY_MS = "batch.throttleDelayMs";
	private static final String KEY_BATCH_MAX_CIDR_EXPANSION = "batch.maxCidrExpansion";

	// Custom cipher map / user risk rules keys
	private static final String KEY_CUSTOM_CIPHER_MAP_ENABLED = "engine.customCipherMapEnabled";
	private static final String KEY_USER_RISK_RULES_ENABLED = "engine.userRiskRulesEnabled";
	private static final String CUSTOM_CIPHER_MAP_FILE = "custom-ciphermap.yaml";
	private static final String USER_RISK_RULES_FILE = "user-riskrules.yaml";
	private static final String RISK_RULES_DIR = "risk-rules";
	private static final String CIPHER_MAP_DIR = "ciphermap";

	// Migrate yaml files from old flat layout to ui/ subdirectories
	static {
		File uiDir = new File(getHomeDir(), "ui");

		// Migrate user-riskrules.yaml to ui/risk-rules/ subdirectory
		File oldRR = new File(getHomeDir(), USER_RISK_RULES_FILE);
		File newRR = new File(new File(uiDir, RISK_RULES_DIR), USER_RISK_RULES_FILE);
		if (oldRR.exists() && !newRR.exists()) {
			try {
				newRR.getParentFile().mkdirs();
				java.nio.file.Files.move(oldRR.toPath(), newRR.toPath());
				logger.info("Migrated risk rules from {} to {}", oldRR, newRR);
			} catch (IOException e) {
				logger.warn("Could not migrate risk rules file", e);
			}
		}

		// Migrate custom-ciphermap.yaml to ui/ciphermap/ subdirectory
		File oldCM = new File(getHomeDir(), CUSTOM_CIPHER_MAP_FILE);
		File newCM = new File(new File(uiDir, CIPHER_MAP_DIR), CUSTOM_CIPHER_MAP_FILE);
		if (oldCM.exists() && !newCM.exists()) {
			try {
				newCM.getParentFile().mkdirs();
				java.nio.file.Files.move(oldCM.toPath(), newCM.toPath());
				logger.info("Migrated cipher map from {} to {}", oldCM, newCM);
			} catch (IOException e) {
				logger.warn("Could not migrate cipher map file", e);
			}
		}
	}

	/** Default user risk rules shipped with the application. */
	public static final String DEFAULT_USER_RISK_RULES =
			"categories:\n"
			+ "  INFO:\n"
			+ "    display_name: \"Informational\"\n"
			+ "    rules:\n"
			+ "      cert_key_info:\n"
			+ "        id: USR-0000001\n"
			+ "        description: \"Certificate uses ${algorithm} ${key_size}-bit key\"\n"
			+ "        score: 0.0\n"
			+ "        when: \"true\"\n"
			+ "        meta:\n"
			+ "          algorithm: cert.key_algorithm\n"
			+ "          key_size: cert.key_size\n"
			+ "      negotiated_connection:\n"
			+ "        id: USR-0000002\n"
			+ "        description: \"Negotiated ${protocol} with ${cipher}\"\n"
			+ "        score: 0.0\n"
			+ "        when: \"true\"\n"
			+ "        meta:\n"
			+ "          protocol: session.negotiated_protocol\n"
			+ "          cipher: session.negotiated_cipher_suite\n";

	// Global properties — stored outside the home dir so they survive wipes
	private static final String GLOBAL_DIR_NAME = ".deepviolet";
	private static final String GLOBAL_PROPS_FILE = "global.properties";

	// Encryption seed — generated once, used to encrypt sensitive values
	private static final String KEY_ENCRYPTION_SEED = "security.encryptionSeed";
	private static final int GCM_IV_BYTES = 12;
	private static final int GCM_TAG_BITS = 128;

	// AI report configuration keys (existing — backward compatible)
	private static final String KEY_AI_ENABLED = "ai.enabled";
	private static final String KEY_AI_PROVIDER = "ai.provider";
	private static final String KEY_AI_API_KEY = "ai.apiKey";
	private static final String KEY_AI_MODEL = "ai.model";
	private static final String KEY_AI_MAX_TOKENS = "ai.maxTokens";
	private static final String KEY_AI_TEMPERATURE = "ai.temperature";
	private static final String KEY_AI_SYSTEM_PROMPT = "ai.systemPrompt";
	private static final String KEY_AI_CHAT_SYSTEM_PROMPT = "ai.chatSystemPrompt";
	private static final String KEY_AI_ENDPOINT_URL = "ai.endpointUrl";
	private static final String KEY_SECTION_AI_EVALUATION = "engine.section.aiEvaluation";

	// AI chat configuration keys
	private static final String KEY_AI_CHAT_ENABLED = "ai.chat.enabled";
	private static final String KEY_AI_CHAT_PROVIDER = "ai.chat.provider";
	private static final String KEY_AI_CHAT_API_KEY = "ai.chat.apiKey";
	private static final String KEY_AI_CHAT_MODEL = "ai.chat.model";
	private static final String KEY_AI_CHAT_MAX_TOKENS = "ai.chat.maxTokens";
	private static final String KEY_AI_CHAT_TEMPERATURE = "ai.chat.temperature";
	private static final String KEY_AI_CHAT_ENDPOINT_URL = "ai.chat.endpointUrl";

	// AI terminal color keys
	private static final String KEY_AI_TERMINAL_BG = "ai.terminal.background";
	private static final String KEY_AI_TERMINAL_USER_PREFIX = "ai.terminal.user.prefix";
	private static final String KEY_AI_TERMINAL_USER_TEXT = "ai.terminal.user.text";
	private static final String KEY_AI_TERMINAL_AI_PREFIX = "ai.terminal.ai.prefix";
	private static final String KEY_AI_TERMINAL_AI_TEXT = "ai.terminal.ai.text";
	private static final String KEY_AI_TERMINAL_ERROR = "ai.terminal.error";
	private static final String KEY_AI_TERMINAL_SYSTEM = "ai.terminal.system";
	private static final String KEY_AI_TERMINAL_SELECTION_BG = "ai.terminal.selection.background";
	private static final String KEY_AI_TERMINAL_SELECTION_FG = "ai.terminal.selection.foreground";

	// Application mode key
	private static final String KEY_APP_MODE = "app.mode";

	// Application theme keys
	private static final String KEY_APP_THEME_CUSTOM = "app.theme.custom";
	private static final String KEY_APP_FONT_NAME = "app.font.name";
	private static final String KEY_APP_FONT_SIZE = "app.font.size";
	private static final String KEY_APP_COLOR_BG = "app.color.background";
	private static final String KEY_APP_COLOR_FG = "app.color.foreground";
	private static final String KEY_APP_COLOR_BUTTON_BG = "app.color.buttonBackground";
	private static final String KEY_APP_COLOR_BUTTON_FG = "app.color.buttonForeground";

	// Card display keys
	private static final String KEY_CARD_FONT_NAME = "card.font.name";
	private static final String KEY_CARD_FONT_SIZE = "card.font.size";
	private static final String KEY_CARD_BADGE_SIZE = "card.badge.size";
	private static final String KEY_CARD_COLOR_BG = "card.color.background";
	private static final String KEY_CARD_COLOR_TEXT = "card.color.text";
	private static final String KEY_CARD_COLOR_DIM = "card.color.dim";
	private static final String KEY_CARD_COLOR_BORDER = "card.color.border";
	private static final String KEY_CARD_COLOR_SELECTED = "card.color.selected";
	private static final String KEY_CARD_COLOR_ERROR = "card.color.error";

	// Card layout property key prefix
	private static final String KEY_CARD_LAYOUT_PREFIX = "card.layout.";

	private static final String KEY_CARD_SIZE = "card.size";

	// Card grid keys
	private static final String KEY_CARD_GRID_VERSION = "card.grid.version";
	private static final String KEY_CARD_GRID_COLS = "card.grid.cols";
	private static final String KEY_CARD_GRID_ROWS = "card.grid.rows";
	private static final String KEY_CARD_GRID_COL_WEIGHTS = "card.grid.colWeights";
	private static final String KEY_CARD_GRID_ROW_WEIGHTS = "card.grid.rowWeights";

	// Dock position keys
	private static final String KEY_DOCK_CARD_PANEL = "dock.cardPanel";
	private static final String KEY_DOCK_TOOLBAR = "dock.toolbar";
	private static final String KEY_DOCK_TARGET_BUTTONS = "dock.targetButtons";
	private static final String KEY_DOCK_GRADE_BAR = "dock.gradeBar";

	// Splitter position keys
	private static final String KEY_SPLIT_BATCH = "split.batch";
	private static final String KEY_SPLIT_DETAIL = "split.detail";
	private static final String KEY_SPLIT_EXTERNAL_DETAIL = "split.externalDetail";

	public static final int DEFAULT_HARDWRAP_WIDTH = 120;

	// Dark theme defaults
	public static final String DEFAULT_FONT_NAME = "Courier New";
	public static final int DEFAULT_FONT_SIZE = 16;
	public static final Color DEFAULT_BG = new Color(0x0D, 0x11, 0x17);
	public static final Color DEFAULT_TEXT = new Color(0xC9, 0xD1, 0xD9);
	public static final Color DEFAULT_NOTICE = new Color(0x8B, 0x5C, 0xF6);
	public static final Color DEFAULT_HEADING = new Color(0x58, 0xA6, 0xFF);
	public static final Color DEFAULT_CONTENT = new Color(0x8B, 0x94, 0x9E);
	public static final Color DEFAULT_KEY = new Color(0x79, 0xC0, 0xFF);
	public static final Color DEFAULT_VALUE = new Color(0xA5, 0xD6, 0xA7);
	public static final Color DEFAULT_WARNING = new Color(0xF8, 0x54, 0x49);
	public static final Color DEFAULT_SUBSECTION = new Color(0x56, 0xD4, 0xDD);
	public static final Color DEFAULT_HIGHLIGHT = DEFAULT_TEXT;
	public static final Color DEFAULT_RISK_PASS = new Color(0xA5, 0xD6, 0xA7);
	public static final Color DEFAULT_RISK_INCONCLUSIVE = new Color(0xE3, 0xB3, 0x41);
	public static final Color DEFAULT_RISK_FAIL = new Color(0xF8, 0x54, 0x49);
	public static final Color DEFAULT_RISK_CRITICAL = new Color(0xF8, 0x54, 0x49);
	public static final Color DEFAULT_RISK_HIGH = new Color(0xFF, 0x8C, 0x00);
	public static final Color DEFAULT_RISK_MEDIUM = new Color(0xE3, 0x8D, 0x20);
	public static final Color DEFAULT_RISK_LOW = new Color(0xCC, 0xCC, 0x44);
	public static final Color DEFAULT_RISK_INFO = new Color(0x58, 0xA6, 0xFF);

	// AI terminal color defaults
	public static final Color DEFAULT_AI_TERMINAL_BG = new Color(0x0D, 0x11, 0x17);
	public static final Color DEFAULT_AI_TERMINAL_USER_PREFIX = new Color(0xB6, 0xDA, 0xFB); // light blue
	public static final Color DEFAULT_AI_TERMINAL_USER_TEXT = new Color(0x60, 0xA5, 0xFA);   // blue
	public static final Color DEFAULT_AI_TERMINAL_AI_PREFIX = new Color(0xF5, 0xDF, 0x9F);   // warm gold
	public static final Color DEFAULT_AI_TERMINAL_AI_TEXT = new Color(0xE3, 0xB3, 0x41);     // gold
	public static final Color DEFAULT_AI_TERMINAL_ERROR = new Color(0xF8, 0x54, 0x49);
	public static final Color DEFAULT_AI_TERMINAL_SYSTEM = new Color(0xCC, 0xCC, 0xCC);
	public static final Color DEFAULT_AI_TERMINAL_SELECTION_BG = new Color(0x3D, 0x5A, 0x80);
	public static final Color DEFAULT_AI_TERMINAL_SELECTION_FG = new Color(0xFF, 0xFF, 0xFF);

	// Card display defaults (dark)
	public static final String DEFAULT_CARD_FONT_NAME = "SansSerif";
	public static final int DEFAULT_CARD_FONT_SIZE = 13;
	public static final int DEFAULT_CARD_BADGE_SIZE = 24;
	public static final Color DEFAULT_CARD_BG = new Color(0x1E, 0x1E, 0x1E);
	public static final Color DEFAULT_CARD_TEXT = new Color(0xE0, 0xE0, 0xE0);
	public static final Color DEFAULT_CARD_DIM = new Color(0x90, 0x90, 0x90);
	public static final Color DEFAULT_CARD_BORDER = new Color(0x44, 0x44, 0x44);
	public static final Color DEFAULT_CARD_SELECTED = new Color(0x21, 0x96, 0xF3);
	public static final Color DEFAULT_CARD_ERROR = new Color(0xF4, 0x43, 0x36);

	private Font font;
	private Color background;
	private Color defaultText;
	private Color notice;
	private Color heading;
	private Color content;
	private Color key;
	private Color value;
	private Color warning;
	private Color subsection;
	private Color highlight;
	private Color riskPass;
	private Color riskInconclusive;
	private Color riskFail;
	private Color riskCritical;
	private Color riskHigh;
	private Color riskMedium;
	private Color riskLow;
	private Color riskInfo;
	private boolean hardwrapEnabled;
	private int hardwrapWidth;

	// Engine settings fields
	private boolean sectionRiskAssessment = true;
	private boolean sectionRuntimeEnvironment = true;
	private boolean sectionHost = true;
	private boolean sectionHttpResponse = true;
	private boolean sectionSecurityHeaders = true;
	private boolean sectionConnection = true;
	private boolean sectionCipherSuites = true;
	private boolean sectionCertChain = true;
	private boolean sectionRevocation = true;
	private boolean sectionTlsFingerprint = true;
	private String cipherConvention = "IANA";
	private boolean protocolSslv3 = false;
	private boolean protocolTls10 = false;
	private boolean protocolTls11 = false;
	private boolean protocolTls12 = true;
	private boolean protocolTls13 = true;
	private int riskScale = 20;

	/** Fixed heat map block count. */
	public static final int SCAN_SCALE = 20;

	// Unified scanning settings
	private int workerThreads = 3;
	private long throttleDelayMs = 150;
	private int maxCidrExpansion = TargetParser.DEFAULT_MAX_CIDR_EXPANSION;

	// AI report configuration fields
	private boolean aiReportEnabled = false;
	private String aiProvider = "Anthropic";
	private String aiApiKey = "";
	private String aiModel = "claude-sonnet-4-5-20250929";
	private int aiMaxTokens = 4096;
	private double aiTemperature = AiAnalysisService.DEFAULT_TEMPERATURE;
	private String aiSystemPrompt = AiAnalysisService.DEFAULT_SYSTEM_PROMPT;
	private String aiChatSystemPrompt = AiAnalysisService.DEFAULT_CHAT_SYSTEM_PROMPT;
	private String aiEndpointUrl = AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT;
	private boolean sectionAiEvaluation = false;

	// AI chat configuration fields
	private boolean aiChatEnabled = false;
	private String aiChatProvider = "Anthropic";
	private String aiChatApiKey = "";
	private String aiChatModel = "claude-sonnet-4-5-20250929";
	private int aiChatMaxTokens = 4096;
	private double aiChatTemperature = AiAnalysisService.DEFAULT_TEMPERATURE;
	private String aiChatEndpointUrl = AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT;

	// AI terminal color fields
	private Color aiTerminalBg = DEFAULT_AI_TERMINAL_BG;
	private Color aiTerminalUserPrefix = DEFAULT_AI_TERMINAL_USER_PREFIX;
	private Color aiTerminalUserText = DEFAULT_AI_TERMINAL_USER_TEXT;
	private Color aiTerminalAiPrefix = DEFAULT_AI_TERMINAL_AI_PREFIX;
	private Color aiTerminalAiText = DEFAULT_AI_TERMINAL_AI_TEXT;
	private Color aiTerminalError = DEFAULT_AI_TERMINAL_ERROR;
	private Color aiTerminalSystem = DEFAULT_AI_TERMINAL_SYSTEM;
	private Color aiTerminalSelectionBg = DEFAULT_AI_TERMINAL_SELECTION_BG;
	private Color aiTerminalSelectionFg = DEFAULT_AI_TERMINAL_SELECTION_FG;

	// Custom cipher map / user risk rules fields
	private boolean customCipherMapEnabled = false;
	private boolean userRiskRulesEnabled = true;

	// Application theme fields
	private boolean appThemeCustom = false;
	private Font appFont;
	private Color appBackground;
	private Color appForeground;
	private Color appButtonBg;
	private Color appButtonFg;

	// Card display fields
	private Font cardFont = new Font(DEFAULT_CARD_FONT_NAME, Font.PLAIN, DEFAULT_CARD_FONT_SIZE);
	private int cardBadgeSize = DEFAULT_CARD_BADGE_SIZE;
	private Color cardBg = DEFAULT_CARD_BG;
	private Color cardText = DEFAULT_CARD_TEXT;
	private Color cardDim = DEFAULT_CARD_DIM;
	private Color cardBorder = DEFAULT_CARD_BORDER;
	private Color cardSelected = DEFAULT_CARD_SELECTED;
	private Color cardError = DEFAULT_CARD_ERROR;
	private CardLayout cardLayout = CardLayout.defaultLayout();
	private CardSize cardSize = CardSize.SMALL;

	// Dock position fields
	private String dockCardPanel = "LEFT";
	private String dockToolbar = "NORTH";
	private String dockTargetButtons = "RIGHT";
	private String dockGradeBar = "TOP";

	// Splitter position fields (-1 means use default resizeWeight)
	private int splitScan = -1;
	private int splitDetail = -1;
	private int splitExternalDetail = -1;

	// Application mode (normal vs workbench)
	private boolean workbenchMode = false;

	private FontPreferences() {
	}

	/**
	 * Load all theme preferences from disk.
	 *
	 * @return A populated FontPreferences instance
	 */
	public static FontPreferences load() {
		Properties props = loadProperties();
		FontPreferences fp = new FontPreferences();

		String name = props.getProperty(KEY_FONT_NAME, DEFAULT_FONT_NAME);
		int size = DEFAULT_FONT_SIZE;
		try {
			size = Integer.parseInt(props.getProperty(KEY_FONT_SIZE,
					String.valueOf(DEFAULT_FONT_SIZE)));
		} catch (NumberFormatException e) {
			logger.warn("Invalid font size in properties, using default");
		}
		fp.font = new Font(name, Font.PLAIN, size);

		fp.background = readColor(props, KEY_COLOR_BG, DEFAULT_BG);
		fp.defaultText = readColor(props, KEY_COLOR_DEFAULT, DEFAULT_TEXT);
		fp.notice = readColor(props, KEY_COLOR_NOTICE, DEFAULT_NOTICE);
		fp.heading = readColor(props, KEY_COLOR_HEADING, DEFAULT_HEADING);
		fp.content = readColor(props, KEY_COLOR_CONTENT, DEFAULT_CONTENT);
		fp.key = readColor(props, KEY_COLOR_KEY, DEFAULT_KEY);
		fp.value = readColor(props, KEY_COLOR_VALUE, DEFAULT_VALUE);
		fp.warning = readColor(props, KEY_COLOR_WARNING, DEFAULT_WARNING);
		fp.subsection = readColor(props, KEY_COLOR_SUBSECTION, DEFAULT_SUBSECTION);
		fp.highlight = readColor(props, KEY_COLOR_HIGHLIGHT, DEFAULT_HIGHLIGHT);
		fp.riskPass = readColor(props, KEY_COLOR_RISK_PASS, DEFAULT_RISK_PASS);
		fp.riskInconclusive = readColor(props, KEY_COLOR_RISK_INCONCLUSIVE, DEFAULT_RISK_INCONCLUSIVE);
		fp.riskFail = readColor(props, KEY_COLOR_RISK_FAIL, DEFAULT_RISK_FAIL);
		fp.riskCritical = readColor(props, KEY_COLOR_RISK_CRITICAL, DEFAULT_RISK_CRITICAL);
		fp.riskHigh = readColor(props, KEY_COLOR_RISK_HIGH, DEFAULT_RISK_HIGH);
		fp.riskMedium = readColor(props, KEY_COLOR_RISK_MEDIUM, DEFAULT_RISK_MEDIUM);
		fp.riskLow = readColor(props, KEY_COLOR_RISK_LOW, DEFAULT_RISK_LOW);
		fp.riskInfo = readColor(props, KEY_COLOR_RISK_INFO, DEFAULT_RISK_INFO);

		fp.hardwrapEnabled = "true".equalsIgnoreCase(
				props.getProperty(KEY_HARDWRAP_ENABLED, "false"));
		try {
			fp.hardwrapWidth = Integer.parseInt(props.getProperty(
					KEY_HARDWRAP_WIDTH, String.valueOf(DEFAULT_HARDWRAP_WIDTH)));
		} catch (NumberFormatException e) {
			fp.hardwrapWidth = DEFAULT_HARDWRAP_WIDTH;
		}

		// Engine settings (default: all sections enabled)
		fp.sectionRiskAssessment = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_RISK_ASSESSMENT));
		fp.sectionRuntimeEnvironment = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_RUNTIME_ENV));
		fp.sectionHost = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_HOST));
		fp.sectionHttpResponse = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_HTTP_RESPONSE));
		fp.sectionSecurityHeaders = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_SECURITY_HEADERS));
		fp.sectionConnection = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_CONNECTION));
		fp.sectionCipherSuites = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_CIPHER_SUITES));
		fp.sectionCertChain = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_CERT_CHAIN));
		fp.sectionRevocation = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_REVOCATION));
		fp.sectionTlsFingerprint = !"false".equalsIgnoreCase(props.getProperty(KEY_SECTION_TLS_FINGERPRINT));
		fp.cipherConvention = props.getProperty(KEY_CIPHER_CONVENTION, "IANA");
		fp.protocolSslv3 = "true".equalsIgnoreCase(props.getProperty(KEY_PROTOCOL_SSLV3, "false"));
		fp.protocolTls10 = "true".equalsIgnoreCase(props.getProperty(KEY_PROTOCOL_TLS10, "false"));
		fp.protocolTls11 = "true".equalsIgnoreCase(props.getProperty(KEY_PROTOCOL_TLS11, "false"));
		fp.protocolTls12 = !"false".equalsIgnoreCase(props.getProperty(KEY_PROTOCOL_TLS12));
		fp.protocolTls13 = !"false".equalsIgnoreCase(props.getProperty(KEY_PROTOCOL_TLS13));
		try {
			fp.riskScale = Integer.parseInt(props.getProperty(KEY_RISK_SCALE, "20"));
			fp.riskScale = Math.max(10, Math.min(50, fp.riskScale));
		} catch (NumberFormatException e) {
			fp.riskScale = 20;
		}
		// Unified scanning settings (with migration fallback from old batch keys)
		try {
			String wt = props.getProperty(KEY_WORKER_THREADS,
					props.getProperty(KEY_BATCH_WORKER_THREADS, "3"));
			fp.workerThreads = Math.max(1, Math.min(10, Integer.parseInt(wt)));
		} catch (NumberFormatException e) {
			fp.workerThreads = 3;
		}
		try {
			String td = props.getProperty(KEY_THROTTLE_DELAY_MS,
					props.getProperty(KEY_BATCH_THROTTLE_DELAY_MS, "150"));
			fp.throttleDelayMs = Math.max(0, Math.min(10000, Long.parseLong(td)));
		} catch (NumberFormatException e) {
			fp.throttleDelayMs = 150;
		}
		try {
			String mc = props.getProperty(KEY_MAX_CIDR_EXPANSION,
					props.getProperty(KEY_BATCH_MAX_CIDR_EXPANSION,
							String.valueOf(TargetParser.DEFAULT_MAX_CIDR_EXPANSION)));
			fp.maxCidrExpansion = Math.max(1, Math.min(1_000_000, Integer.parseInt(mc)));
		} catch (NumberFormatException e) {
			fp.maxCidrExpansion = TargetParser.DEFAULT_MAX_CIDR_EXPANSION;
		}

		// AI report configuration
		fp.aiReportEnabled = "true".equalsIgnoreCase(props.getProperty(KEY_AI_ENABLED, "false"));
		fp.aiProvider = props.getProperty(KEY_AI_PROVIDER, "Anthropic");
		fp.aiApiKey = decryptApiKey(props, KEY_AI_API_KEY);
		fp.aiModel = props.getProperty(KEY_AI_MODEL, "claude-sonnet-4-5-20250929");
		try {
			fp.aiMaxTokens = Integer.parseInt(props.getProperty(KEY_AI_MAX_TOKENS, "4096"));
		} catch (NumberFormatException e) {
			fp.aiMaxTokens = 4096;
		}
		try {
			fp.aiTemperature = Double.parseDouble(props.getProperty(KEY_AI_TEMPERATURE,
					String.valueOf(AiAnalysisService.DEFAULT_TEMPERATURE)));
		} catch (NumberFormatException e) {
			fp.aiTemperature = AiAnalysisService.DEFAULT_TEMPERATURE;
		}
		String savedPrompt = props.getProperty(KEY_AI_SYSTEM_PROMPT, AiAnalysisService.DEFAULT_SYSTEM_PROMPT);
		// Migrate older prompt versions to current structured format
		if ((savedPrompt.contains("1. **Executive Summary**") && savedPrompt.contains("Be concise but thorough."))
				|| (savedPrompt.contains("[Critical Issues]") && savedPrompt.contains("CRITICAL: "))) {
			savedPrompt = AiAnalysisService.DEFAULT_SYSTEM_PROMPT;
		}
		fp.aiSystemPrompt = savedPrompt;
		fp.aiChatSystemPrompt = props.getProperty(KEY_AI_CHAT_SYSTEM_PROMPT,
				AiAnalysisService.DEFAULT_CHAT_SYSTEM_PROMPT);
		fp.aiEndpointUrl = props.getProperty(KEY_AI_ENDPOINT_URL,
				AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT);
		fp.sectionAiEvaluation = "true".equalsIgnoreCase(
				props.getProperty(KEY_SECTION_AI_EVALUATION, "false"));

		// AI chat configuration
		fp.aiChatProvider = props.getProperty(KEY_AI_CHAT_PROVIDER, "Anthropic");
		fp.aiChatApiKey = decryptApiKey(props, KEY_AI_CHAT_API_KEY);
		fp.aiChatModel = props.getProperty(KEY_AI_CHAT_MODEL, "claude-sonnet-4-5-20250929");
		try {
			fp.aiChatMaxTokens = Integer.parseInt(props.getProperty(KEY_AI_CHAT_MAX_TOKENS, "4096"));
		} catch (NumberFormatException e) {
			fp.aiChatMaxTokens = 4096;
		}
		try {
			fp.aiChatTemperature = Double.parseDouble(props.getProperty(KEY_AI_CHAT_TEMPERATURE,
					String.valueOf(AiAnalysisService.DEFAULT_TEMPERATURE)));
		} catch (NumberFormatException e) {
			fp.aiChatTemperature = AiAnalysisService.DEFAULT_TEMPERATURE;
		}
		fp.aiChatEndpointUrl = props.getProperty(KEY_AI_CHAT_ENDPOINT_URL,
				AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT);
		// Migration: if chat keys absent but report AI was enabled, enable chat too
		if (props.getProperty(KEY_AI_CHAT_ENABLED) == null) {
			fp.aiChatEnabled = fp.aiReportEnabled;
			// Copy report config as initial chat config for existing users
			if (fp.aiChatEnabled) {
				fp.aiChatProvider = fp.aiProvider;
				fp.aiChatApiKey = fp.aiApiKey;
				fp.aiChatModel = fp.aiModel;
				fp.aiChatMaxTokens = fp.aiMaxTokens;
				fp.aiChatTemperature = fp.aiTemperature;
				fp.aiChatEndpointUrl = fp.aiEndpointUrl;
			}
		} else {
			fp.aiChatEnabled = "true".equalsIgnoreCase(props.getProperty(KEY_AI_CHAT_ENABLED, "false"));
		}

		// AI terminal colors
		fp.aiTerminalBg = readColor(props, KEY_AI_TERMINAL_BG, DEFAULT_AI_TERMINAL_BG);
		fp.aiTerminalUserPrefix = readColor(props, KEY_AI_TERMINAL_USER_PREFIX, DEFAULT_AI_TERMINAL_USER_PREFIX);
		fp.aiTerminalUserText = readColor(props, KEY_AI_TERMINAL_USER_TEXT, DEFAULT_AI_TERMINAL_USER_TEXT);
		fp.aiTerminalAiPrefix = readColor(props, KEY_AI_TERMINAL_AI_PREFIX, DEFAULT_AI_TERMINAL_AI_PREFIX);
		fp.aiTerminalAiText = readColor(props, KEY_AI_TERMINAL_AI_TEXT, DEFAULT_AI_TERMINAL_AI_TEXT);
		fp.aiTerminalError = readColor(props, KEY_AI_TERMINAL_ERROR, DEFAULT_AI_TERMINAL_ERROR);
		fp.aiTerminalSystem = readColor(props, KEY_AI_TERMINAL_SYSTEM, DEFAULT_AI_TERMINAL_SYSTEM);
		fp.aiTerminalSelectionBg = readColor(props, KEY_AI_TERMINAL_SELECTION_BG, DEFAULT_AI_TERMINAL_SELECTION_BG);
		fp.aiTerminalSelectionFg = readColor(props, KEY_AI_TERMINAL_SELECTION_FG, DEFAULT_AI_TERMINAL_SELECTION_FG);

		// Custom cipher map / user risk rules
		fp.customCipherMapEnabled = "true".equalsIgnoreCase(
				props.getProperty(KEY_CUSTOM_CIPHER_MAP_ENABLED, "false"));
		fp.userRiskRulesEnabled = "true".equalsIgnoreCase(
				props.getProperty(KEY_USER_RISK_RULES_ENABLED, "true"));

		// Application theme
		fp.appThemeCustom = "true".equalsIgnoreCase(
				props.getProperty(KEY_APP_THEME_CUSTOM, "false"));
		if (fp.appThemeCustom) {
			// Custom mode: read user's saved color choices
			String appFontName = props.getProperty(KEY_APP_FONT_NAME, sysLafFont.getFamily());
			int appFontSize = sysLafFont.getSize();
			try {
				appFontSize = Integer.parseInt(props.getProperty(KEY_APP_FONT_SIZE,
						String.valueOf(sysLafFont.getSize())));
			} catch (NumberFormatException e) {
				logger.warn("Invalid app font size in properties, using default");
			}
			fp.appFont = new Font(appFontName, Font.PLAIN, appFontSize);
			fp.appBackground = readColor(props, KEY_APP_COLOR_BG, sysLafPanelBg);
			fp.appForeground = readColor(props, KEY_APP_COLOR_FG, sysLafLabelFg);
			// New button keys with migration fallback to old control keys
			Color btnBg = readColor(props, KEY_APP_COLOR_BUTTON_BG, null);
			if (btnBg == null) {
				btnBg = readColor(props, "app.color.controlBackground", sysLafButtonBg);
			}
			fp.appButtonBg = btnBg;
			Color btnFg = readColor(props, KEY_APP_COLOR_BUTTON_FG, null);
			if (btnFg == null) {
				btnFg = readColor(props, "app.color.controlForeground", sysLafButtonFg);
			}
			fp.appButtonFg = btnFg;
		} else {
			// System mode: always use captured startup values so the
			// Settings dialog matches the actual displayed colors
			fp.appFont = sysLafFont;
			fp.appBackground = sysLafPanelBg;
			fp.appForeground = sysLafLabelFg;
			fp.appButtonBg = sysLafButtonBg;
			fp.appButtonFg = sysLafButtonFg;
		}

		// Card display
		String cardFontName = props.getProperty(KEY_CARD_FONT_NAME, DEFAULT_CARD_FONT_NAME);
		int cardFontSize = DEFAULT_CARD_FONT_SIZE;
		try {
			cardFontSize = Integer.parseInt(props.getProperty(KEY_CARD_FONT_SIZE,
					String.valueOf(DEFAULT_CARD_FONT_SIZE)));
		} catch (NumberFormatException e) {
			// use default
		}
		fp.cardFont = new Font(cardFontName, Font.PLAIN, cardFontSize);
		try {
			fp.cardBadgeSize = Integer.parseInt(props.getProperty(KEY_CARD_BADGE_SIZE,
					String.valueOf(DEFAULT_CARD_BADGE_SIZE)));
		} catch (NumberFormatException e) {
			// use default
		}
		fp.cardBg = readColor(props, KEY_CARD_COLOR_BG, DEFAULT_CARD_BG);
		fp.cardText = readColor(props, KEY_CARD_COLOR_TEXT, DEFAULT_CARD_TEXT);
		fp.cardDim = readColor(props, KEY_CARD_COLOR_DIM, DEFAULT_CARD_DIM);
		fp.cardBorder = readColor(props, KEY_CARD_COLOR_BORDER, DEFAULT_CARD_BORDER);
		fp.cardSelected = readColor(props, KEY_CARD_COLOR_SELECTED, DEFAULT_CARD_SELECTED);
		fp.cardError = readColor(props, KEY_CARD_COLOR_ERROR, DEFAULT_CARD_ERROR);

		// Card layout
		fp.cardLayout = loadCardLayout(props);
		fp.cardSize = CardSize.fromString(props.getProperty(KEY_CARD_SIZE, "SMALL"));

		// Dock positions
		fp.dockCardPanel = props.getProperty(KEY_DOCK_CARD_PANEL, "LEFT");
		fp.dockToolbar = props.getProperty(KEY_DOCK_TOOLBAR, "NORTH");
		fp.dockTargetButtons = props.getProperty(KEY_DOCK_TARGET_BUTTONS, "RIGHT");
		fp.dockGradeBar = props.getProperty(KEY_DOCK_GRADE_BAR, "TOP");

		// Splitter positions
		fp.splitScan = parseIntProp(props, KEY_SPLIT_BATCH, -1);
		fp.splitDetail = parseIntProp(props, KEY_SPLIT_DETAIL, -1);
		fp.splitExternalDetail = parseIntProp(props, KEY_SPLIT_EXTERNAL_DETAIL, -1);

		// Application mode
		fp.workbenchMode = "true".equalsIgnoreCase(props.getProperty(KEY_APP_MODE, "false"));

		// Seed the local custom cipher map from the API default on first launch
		ensureDefaultCipherMap();

		return fp;
	}

	/**
	 * Persist all theme preferences to disk.
	 *
	 * @param fp The preferences to save
	 */
	public static void save(FontPreferences fp) {
		Properties props = loadProperties();

		props.setProperty(KEY_FONT_NAME, fp.font.getFamily());
		props.setProperty(KEY_FONT_SIZE, String.valueOf(fp.font.getSize()));
		props.setProperty(KEY_COLOR_BG, encodeColor(fp.background));
		props.setProperty(KEY_COLOR_DEFAULT, encodeColor(fp.defaultText));
		props.setProperty(KEY_COLOR_NOTICE, encodeColor(fp.notice));
		props.setProperty(KEY_COLOR_HEADING, encodeColor(fp.heading));
		props.setProperty(KEY_COLOR_CONTENT, encodeColor(fp.content));
		props.setProperty(KEY_COLOR_KEY, encodeColor(fp.key));
		props.setProperty(KEY_COLOR_VALUE, encodeColor(fp.value));
		props.setProperty(KEY_COLOR_WARNING, encodeColor(fp.warning));
		props.setProperty(KEY_COLOR_SUBSECTION, encodeColor(fp.subsection));
		props.setProperty(KEY_COLOR_HIGHLIGHT, encodeColor(fp.highlight));
		props.setProperty(KEY_COLOR_RISK_PASS, encodeColor(fp.riskPass));
		props.setProperty(KEY_COLOR_RISK_INCONCLUSIVE, encodeColor(fp.riskInconclusive));
		props.setProperty(KEY_COLOR_RISK_FAIL, encodeColor(fp.riskFail));
		props.setProperty(KEY_COLOR_RISK_CRITICAL, encodeColor(fp.riskCritical));
		props.setProperty(KEY_COLOR_RISK_HIGH, encodeColor(fp.riskHigh));
		props.setProperty(KEY_COLOR_RISK_MEDIUM, encodeColor(fp.riskMedium));
		props.setProperty(KEY_COLOR_RISK_LOW, encodeColor(fp.riskLow));
		props.setProperty(KEY_COLOR_RISK_INFO, encodeColor(fp.riskInfo));
		props.setProperty(KEY_HARDWRAP_ENABLED, String.valueOf(fp.hardwrapEnabled));
		props.setProperty(KEY_HARDWRAP_WIDTH, String.valueOf(fp.hardwrapWidth));

		// Engine settings
		props.setProperty(KEY_SECTION_RISK_ASSESSMENT, String.valueOf(fp.sectionRiskAssessment));
		props.setProperty(KEY_SECTION_RUNTIME_ENV, String.valueOf(fp.sectionRuntimeEnvironment));
		props.remove("engine.section.header"); // deprecated: header always included
		props.setProperty(KEY_SECTION_HOST, String.valueOf(fp.sectionHost));
		props.setProperty(KEY_SECTION_HTTP_RESPONSE, String.valueOf(fp.sectionHttpResponse));
		props.setProperty(KEY_SECTION_SECURITY_HEADERS, String.valueOf(fp.sectionSecurityHeaders));
		props.setProperty(KEY_SECTION_CONNECTION, String.valueOf(fp.sectionConnection));
		props.setProperty(KEY_SECTION_CIPHER_SUITES, String.valueOf(fp.sectionCipherSuites));
		props.setProperty(KEY_SECTION_CERT_CHAIN, String.valueOf(fp.sectionCertChain));
		props.setProperty(KEY_SECTION_REVOCATION, String.valueOf(fp.sectionRevocation));
		props.setProperty(KEY_SECTION_TLS_FINGERPRINT, String.valueOf(fp.sectionTlsFingerprint));
		props.setProperty(KEY_CIPHER_CONVENTION, fp.cipherConvention);
		props.setProperty(KEY_PROTOCOL_SSLV3, String.valueOf(fp.protocolSslv3));
		props.setProperty(KEY_PROTOCOL_TLS10, String.valueOf(fp.protocolTls10));
		props.setProperty(KEY_PROTOCOL_TLS11, String.valueOf(fp.protocolTls11));
		props.setProperty(KEY_PROTOCOL_TLS12, String.valueOf(fp.protocolTls12));
		props.setProperty(KEY_PROTOCOL_TLS13, String.valueOf(fp.protocolTls13));
		props.setProperty(KEY_RISK_SCALE, String.valueOf(fp.riskScale));
		props.setProperty(KEY_WORKER_THREADS, String.valueOf(fp.workerThreads));
		props.setProperty(KEY_THROTTLE_DELAY_MS, String.valueOf(fp.throttleDelayMs));
		props.setProperty(KEY_MAX_CIDR_EXPANSION, String.valueOf(fp.maxCidrExpansion));

		// AI report configuration
		props.setProperty(KEY_AI_ENABLED, String.valueOf(fp.aiReportEnabled));
		props.setProperty(KEY_AI_PROVIDER, fp.aiProvider);
		encryptApiKey(props, KEY_AI_API_KEY, fp.aiApiKey);
		props.setProperty(KEY_AI_MODEL, fp.aiModel);
		props.setProperty(KEY_AI_MAX_TOKENS, String.valueOf(fp.aiMaxTokens));
		props.setProperty(KEY_AI_TEMPERATURE, String.valueOf(fp.aiTemperature));
		props.setProperty(KEY_AI_SYSTEM_PROMPT, fp.aiSystemPrompt);
		props.setProperty(KEY_AI_CHAT_SYSTEM_PROMPT, fp.aiChatSystemPrompt);
		props.setProperty(KEY_AI_ENDPOINT_URL, fp.aiEndpointUrl);
		props.setProperty(KEY_SECTION_AI_EVALUATION, String.valueOf(fp.sectionAiEvaluation));

		// AI chat configuration
		props.setProperty(KEY_AI_CHAT_ENABLED, String.valueOf(fp.aiChatEnabled));
		props.setProperty(KEY_AI_CHAT_PROVIDER, fp.aiChatProvider);
		encryptApiKey(props, KEY_AI_CHAT_API_KEY, fp.aiChatApiKey);
		props.setProperty(KEY_AI_CHAT_MODEL, fp.aiChatModel);
		props.setProperty(KEY_AI_CHAT_MAX_TOKENS, String.valueOf(fp.aiChatMaxTokens));
		props.setProperty(KEY_AI_CHAT_TEMPERATURE, String.valueOf(fp.aiChatTemperature));
		props.setProperty(KEY_AI_CHAT_ENDPOINT_URL, fp.aiChatEndpointUrl);

		// AI terminal colors
		props.setProperty(KEY_AI_TERMINAL_BG, encodeColor(fp.aiTerminalBg));
		props.setProperty(KEY_AI_TERMINAL_USER_PREFIX, encodeColor(fp.aiTerminalUserPrefix));
		props.setProperty(KEY_AI_TERMINAL_USER_TEXT, encodeColor(fp.aiTerminalUserText));
		props.setProperty(KEY_AI_TERMINAL_AI_PREFIX, encodeColor(fp.aiTerminalAiPrefix));
		props.setProperty(KEY_AI_TERMINAL_AI_TEXT, encodeColor(fp.aiTerminalAiText));
		props.setProperty(KEY_AI_TERMINAL_ERROR, encodeColor(fp.aiTerminalError));
		props.setProperty(KEY_AI_TERMINAL_SYSTEM, encodeColor(fp.aiTerminalSystem));
		props.setProperty(KEY_AI_TERMINAL_SELECTION_BG, encodeColor(fp.aiTerminalSelectionBg));
		props.setProperty(KEY_AI_TERMINAL_SELECTION_FG, encodeColor(fp.aiTerminalSelectionFg));

		// Custom cipher map / user risk rules
		props.setProperty(KEY_CUSTOM_CIPHER_MAP_ENABLED, String.valueOf(fp.customCipherMapEnabled));
		props.setProperty(KEY_USER_RISK_RULES_ENABLED, String.valueOf(fp.userRiskRulesEnabled));

		// Application theme
		props.setProperty(KEY_APP_THEME_CUSTOM, String.valueOf(fp.appThemeCustom));
		props.setProperty(KEY_APP_FONT_NAME, fp.appFont.getFamily());
		props.setProperty(KEY_APP_FONT_SIZE, String.valueOf(fp.appFont.getSize()));
		props.setProperty(KEY_APP_COLOR_BG, encodeColor(fp.appBackground));
		props.setProperty(KEY_APP_COLOR_FG, encodeColor(fp.appForeground));
		props.setProperty(KEY_APP_COLOR_BUTTON_BG, encodeColor(fp.appButtonBg));
		props.setProperty(KEY_APP_COLOR_BUTTON_FG, encodeColor(fp.appButtonFg));
		// Remove deprecated old keys
		props.remove("app.color.controlBackground");
		props.remove("app.color.controlForeground");
		props.remove("app.color.accent");

		// Card display
		props.setProperty(KEY_CARD_FONT_NAME, fp.cardFont.getFamily());
		props.setProperty(KEY_CARD_FONT_SIZE, String.valueOf(fp.cardFont.getSize()));
		props.setProperty(KEY_CARD_BADGE_SIZE, String.valueOf(fp.cardBadgeSize));
		props.setProperty(KEY_CARD_COLOR_BG, encodeColor(fp.cardBg));
		props.setProperty(KEY_CARD_COLOR_TEXT, encodeColor(fp.cardText));
		props.setProperty(KEY_CARD_COLOR_DIM, encodeColor(fp.cardDim));
		props.setProperty(KEY_CARD_COLOR_BORDER, encodeColor(fp.cardBorder));
		props.setProperty(KEY_CARD_COLOR_SELECTED, encodeColor(fp.cardSelected));
		props.setProperty(KEY_CARD_COLOR_ERROR, encodeColor(fp.cardError));

		// Card layout and size
		saveCardLayout(props, fp.cardLayout);
		props.setProperty(KEY_CARD_SIZE, fp.cardSize.name());

		// Dock positions
		props.setProperty(KEY_DOCK_CARD_PANEL, fp.dockCardPanel);
		props.setProperty(KEY_DOCK_TOOLBAR, fp.dockToolbar);
		props.setProperty(KEY_DOCK_TARGET_BUTTONS, fp.dockTargetButtons);
		props.setProperty(KEY_DOCK_GRADE_BAR, fp.dockGradeBar);

		// Splitter positions
		if (fp.splitScan >= 0) props.setProperty(KEY_SPLIT_BATCH, String.valueOf(fp.splitScan));
		if (fp.splitDetail >= 0) props.setProperty(KEY_SPLIT_DETAIL, String.valueOf(fp.splitDetail));
		if (fp.splitExternalDetail >= 0) props.setProperty(KEY_SPLIT_EXTERNAL_DETAIL, String.valueOf(fp.splitExternalDetail));

		// Application mode
		props.setProperty(KEY_APP_MODE, String.valueOf(fp.workbenchMode));

		File dir = getHomeDir();
		dir.mkdirs();
		File file = new File(dir, PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
			logger.info("Theme preferences saved");
		} catch (IOException e) {
			logger.error("Failed to save theme preferences", e);
		}
	}

	/**
	 * Create a FontPreferences with dark theme defaults.
	 *
	 * @return dark theme defaults
	 */
	public static FontPreferences defaults() {
		return darkDefaults();
	}

	/**
	 * Dark theme preset - rich dark background with high-contrast colors.
	 *
	 * @return dark theme
	 */
	public static FontPreferences darkDefaults() {
		FontPreferences fp = new FontPreferences();
		fp.font = new Font(DEFAULT_FONT_NAME, Font.PLAIN, DEFAULT_FONT_SIZE);
		fp.background = DEFAULT_BG;
		fp.defaultText = DEFAULT_TEXT;
		fp.notice = DEFAULT_NOTICE;
		fp.heading = DEFAULT_HEADING;
		fp.content = DEFAULT_CONTENT;
		fp.key = DEFAULT_KEY;
		fp.value = DEFAULT_VALUE;
		fp.warning = DEFAULT_WARNING;
		fp.subsection = DEFAULT_SUBSECTION;
		fp.highlight = DEFAULT_HIGHLIGHT;
		fp.riskPass = DEFAULT_RISK_PASS;
		fp.riskInconclusive = DEFAULT_RISK_INCONCLUSIVE;
		fp.riskFail = DEFAULT_RISK_FAIL;
		fp.riskCritical = DEFAULT_RISK_CRITICAL;
		fp.riskHigh = DEFAULT_RISK_HIGH;
		fp.riskMedium = DEFAULT_RISK_MEDIUM;
		fp.riskLow = DEFAULT_RISK_LOW;
		fp.riskInfo = DEFAULT_RISK_INFO;
		fp.hardwrapEnabled = false;
		fp.hardwrapWidth = DEFAULT_HARDWRAP_WIDTH;
		fp.cardFont = new Font(DEFAULT_CARD_FONT_NAME, Font.PLAIN, DEFAULT_CARD_FONT_SIZE);
		fp.cardBadgeSize = DEFAULT_CARD_BADGE_SIZE;
		fp.cardBg = DEFAULT_CARD_BG;
		fp.cardText = DEFAULT_CARD_TEXT;
		fp.cardDim = DEFAULT_CARD_DIM;
		fp.cardBorder = DEFAULT_CARD_BORDER;
		fp.cardSelected = DEFAULT_CARD_SELECTED;
		fp.cardError = DEFAULT_CARD_ERROR;
		fp.cardLayout = CardLayout.defaultLayout();
		return fp;
	}

	/**
	 * Light theme preset - white background with rich accent colors.
	 *
	 * @return light theme
	 */
	public static FontPreferences lightDefaults() {
		FontPreferences fp = new FontPreferences();
		fp.font = new Font(DEFAULT_FONT_NAME, Font.PLAIN, DEFAULT_FONT_SIZE);
		fp.background = new Color(0xCC, 0xCC, 0xCC);
		fp.defaultText = new Color(0x24, 0x29, 0x2F);
		fp.notice = new Color(0x6D, 0x28, 0xD9);
		fp.heading = new Color(0x05, 0x50, 0xAE);
		fp.content = new Color(0x00, 0x00, 0x00);
		fp.key = new Color(0x33, 0x33, 0x33);
		fp.value = new Color(0x00, 0x66, 0x99);
		fp.warning = new Color(0xCC, 0x66, 0x00);
		fp.subsection = new Color(0x00, 0x33, 0x66);
		fp.highlight = fp.defaultText;
		fp.riskPass = new Color(0x1A, 0x7F, 0x37);
		fp.riskInconclusive = new Color(0x9A, 0x67, 0x00);
		fp.riskFail = new Color(0xCF, 0x22, 0x2E);
		fp.riskCritical = new Color(0xCC, 0x00, 0x00);
		fp.riskHigh = new Color(0xCC, 0x66, 0x00);
		fp.riskMedium = new Color(0x99, 0x66, 0x00);
		fp.riskLow = new Color(0x88, 0x88, 0x00);
		fp.riskInfo = new Color(0x05, 0x50, 0xAE);
		fp.hardwrapEnabled = true;
		fp.hardwrapWidth = 90;
		fp.cardFont = new Font(DEFAULT_CARD_FONT_NAME, Font.PLAIN, DEFAULT_CARD_FONT_SIZE);
		fp.cardBadgeSize = DEFAULT_CARD_BADGE_SIZE;
		fp.cardBg = new Color(0xE8, 0xE8, 0xE8);
		fp.cardText = new Color(0x1A, 0x1A, 0x1A);
		fp.cardDim = new Color(0x66, 0x66, 0x66);
		fp.cardBorder = new Color(0xBB, 0xBB, 0xBB);
		fp.cardSelected = new Color(0x19, 0x76, 0xD2);
		fp.cardError = new Color(0xC6, 0x28, 0x28);
		fp.cardLayout = CardLayout.defaultLayout();
		return fp;
	}

	/**
	 * System theme preset - neutral colors suitable for any system look
	 * and feel.
	 *
	 * @return system theme
	 */
	public static FontPreferences systemDefaults() {
		FontPreferences fp = new FontPreferences();
		fp.font = new Font(DEFAULT_FONT_NAME, Font.PLAIN, DEFAULT_FONT_SIZE);
		fp.background = new Color(0xF6, 0xF8, 0xFA);
		fp.defaultText = new Color(0x1F, 0x23, 0x28);
		fp.notice = new Color(0x7D, 0x4E, 0x00);
		fp.heading = new Color(0x03, 0x49, 0xB4);
		fp.content = new Color(0x65, 0x6D, 0x76);
		fp.key = new Color(0x1F, 0x6F, 0xEB);
		fp.value = new Color(0x11, 0x63, 0x29);
		fp.warning = new Color(0xCF, 0x22, 0x2E);
		fp.subsection = new Color(0x0A, 0x63, 0x76);
		fp.highlight = fp.defaultText;
		fp.riskPass = new Color(0x11, 0x63, 0x29);
		fp.riskInconclusive = new Color(0x7D, 0x4E, 0x00);
		fp.riskFail = new Color(0xCF, 0x22, 0x2E);
		fp.riskCritical = new Color(0xCF, 0x22, 0x2E);
		fp.riskHigh = new Color(0xBC, 0x5C, 0x00);
		fp.riskMedium = new Color(0x7D, 0x4E, 0x00);
		fp.riskLow = new Color(0x63, 0x63, 0x00);
		fp.riskInfo = new Color(0x03, 0x49, 0xB4);
		fp.hardwrapEnabled = false;
		fp.hardwrapWidth = DEFAULT_HARDWRAP_WIDTH;
		fp.cardFont = new Font(DEFAULT_CARD_FONT_NAME, Font.PLAIN, DEFAULT_CARD_FONT_SIZE);
		fp.cardBadgeSize = DEFAULT_CARD_BADGE_SIZE;
		fp.cardBg = new Color(0xF0, 0xF0, 0xF0);
		fp.cardText = new Color(0x1F, 0x23, 0x28);
		fp.cardDim = new Color(0x6E, 0x76, 0x81);
		fp.cardBorder = new Color(0xCC, 0xCC, 0xCC);
		fp.cardSelected = new Color(0x21, 0x96, 0xF3);
		fp.cardError = new Color(0xCF, 0x22, 0x2E);
		fp.cardLayout = CardLayout.defaultLayout();
		return fp;
	}

	/**
	 * Application theme preset: System Default - restores system L&F values.
	 *
	 * @return preset with system L&F app theme values
	 */
	public static FontPreferences appSystemDefaults() {
		FontPreferences fp = new FontPreferences();
		fp.appThemeCustom = false;
		fp.appFont = sysLafFont;
		fp.appBackground = sysLafPanelBg;
		fp.appForeground = sysLafLabelFg;
		fp.appButtonBg = sysLafButtonBg;
		fp.appButtonFg = sysLafButtonFg;
		return fp;
	}

	/**
	 * Application theme preset: Light Default.
	 *
	 * @return preset with light app theme values
	 */
	public static FontPreferences appLightDefaults() {
		FontPreferences fp = new FontPreferences();
		fp.appThemeCustom = true;
		fp.appFont = new Font("SansSerif", Font.PLAIN, DEFAULT_FONT_SIZE);
		fp.appBackground = new Color(0xFA, 0xFA, 0xFA);
		fp.appForeground = new Color(0x1A, 0x1A, 0x1A);
		fp.appButtonBg = new Color(0xE8, 0xE8, 0xE8);
		fp.appButtonFg = new Color(0x1A, 0x1A, 0x1A);
		return fp;
	}

	/**
	 * Application theme preset: Dark Default.
	 *
	 * @return preset with dark app theme values
	 */
	public static FontPreferences appDarkDefaults() {
		FontPreferences fp = new FontPreferences();
		fp.appThemeCustom = true;
		fp.appFont = new Font("SansSerif", Font.PLAIN, DEFAULT_FONT_SIZE);
		fp.appBackground = new Color(0x2B, 0x2B, 0x2B);
		fp.appForeground = new Color(0xBB, 0xBB, 0xBB);
		fp.appButtonBg = new Color(0x3C, 0x3F, 0x41);
		fp.appButtonFg = new Color(0xBB, 0xBB, 0xBB);
		return fp;
	}

	/**
	 * Apply the application theme to all standard Swing UI defaults and
	 * refresh all open windows. When the app theme is set to system default
	 * (appThemeCustom == false), the native L&amp;F is re-installed so the
	 * platform renders everything naturally.
	 *
	 * @param prefs Preferences containing app theme settings
	 */
	public static void applyAppTheme(FontPreferences prefs) {
		String[] fontKeys = {
			"Label.font", "Button.font", "CheckBox.font", "RadioButton.font",
			"ComboBox.font", "TextField.font", "TextArea.font",
			"TabbedPane.font", "TitledBorder.font", "Menu.font",
			"MenuItem.font", "MenuBar.font", "OptionPane.font",
			"Table.font", "TableHeader.font", "List.font", "Spinner.font",
			"ToolTip.font"
		};

		Font font = prefs.appFont;
		for (String k : fontKeys) UIManager.put(k, font);

		Color accent;
		Color bg;

		if (prefs.appThemeCustom) {
			bg = prefs.appBackground;
			Color fg = prefs.appForeground;
			Color btnBg = prefs.appButtonBg;
			Color btnFg = prefs.appButtonFg;
			accent = computeSubtleAccent(bg, btnBg);

			// Window Bg — panels, text fields, combo boxes, lists, tables
			UIManager.put("Panel.background", bg);
			UIManager.put("TextField.background", bg);
			UIManager.put("TextArea.background", bg);
			UIManager.put("ComboBox.background", bg);
			UIManager.put("List.background", bg);
			UIManager.put("Table.background", bg);
			UIManager.put("TableHeader.background", bg);

			// Window Fg — labels, input text, menus, tabs
			UIManager.put("Label.foreground", fg);
			UIManager.put("TextField.foreground", fg);
			UIManager.put("TextArea.foreground", fg);
			UIManager.put("ComboBox.foreground", fg);
			UIManager.put("List.foreground", fg);
			UIManager.put("Table.foreground", fg);
			UIManager.put("Menu.foreground", fg);
			UIManager.put("MenuItem.foreground", fg);
			UIManager.put("MenuBar.foreground", fg);
			UIManager.put("TabbedPane.foreground", fg);

			// Button Bg / Fg
			UIManager.put("Button.background", btnBg);
			UIManager.put("Button.foreground", btnFg);
		} else {
			// Remove chrome overrides so FlatLaf handles them natively
			String[] chromeKeys = {
				"Panel.background", "Label.foreground",
				"TextField.background", "TextField.foreground",
				"TextArea.background", "TextArea.foreground",
				"ComboBox.background", "ComboBox.foreground",
				"List.background", "List.foreground",
				"Table.background", "Table.foreground", "TableHeader.background",
				"Button.background", "Button.foreground",
				"Menu.foreground", "MenuItem.foreground",
				"MenuBar.foreground", "TabbedPane.foreground"
			};
			for (String k : chromeKeys) UIManager.put(k, null);

			// Use computed accent from system defaults
			bg = UIManager.getColor("Panel.background");
			if (bg == null) bg = sysLafPanelBg;
			accent = computeSubtleAccent(bg, sysLafButtonBg);
		}

		// Set @accentColor and reinstall L&F so FlatLaf re-derives all
		// accent-dependent colors (focus borders, selection, etc.)
		UIManager.put("@accentColor", accent);
		try {
			UIManager.setLookAndFeel(UIManager.getLookAndFeel());
		} catch (Exception e) {
			logger.warn("Failed to reinstall L&F for accent update", e);
		}

		// Re-apply font keys after L&F reinstall
		for (String k : fontKeys) UIManager.put(k, font);

		// Apply explicit accent overrides on top of FlatLaf's derived values
		applyAccentKeys(accent, bg);

		for (Window w : Window.getWindows()) {
			// Skip dialogs — they manage their own refresh via
			// FontChooserDialog.refreshSwatches().  Calling
			// updateComponentTreeUI on an open dialog with a focused
			// JComboBox causes a NPE in BasicComboBoxUI$Handler.focusLost
			// because the old UI delegate's comboBox field is nulled
			// during uninstall while a stale focusLost event still fires.
			if (w instanceof java.awt.Dialog) continue;
			SwingUtilities.updateComponentTreeUI(w);
		}
	}

	/**
	 * Apply accent-derived UIManager keys for default buttons, tabs, and
	 * focus indicators.  Values are written to both the developer defaults
	 * table ({@code UIManager.put}) and the L&amp;F defaults table so that
	 * FlatLaf picks them up even for colors it resolved at install time.
	 */
	private static void applyAccentKeys(Color accent, Color bg) {
		boolean isDark = luminance(bg) < 128;
		Color accentFg = isDark ? new Color(0xDD, 0xDD, 0xDD)
				: new Color(0x33, 0x33, 0x33);
		Color hover = isDark ? lighten(accent, 18) : darken(accent, 18);
		Color pressed = isDark ? lighten(accent, 30) : darken(accent, 30);
		Color focusRing = new Color(
				accent.getRed(), accent.getGreen(), accent.getBlue(), 60);
		// Muted variant for inactive/unfocused states
		Color inactive = isDark ? darken(accent, 12) : lighten(accent, 12);

		// Collect all key/value pairs to write into both defaults tables
		Object[][] entries = {
			// Default button (Scan, Send, OK, etc.)
			{ "Button.default.background", accent },
			{ "Button.default.foreground", accentFg },
			{ "Button.default.hoverBackground", hover },
			{ "Button.default.pressedBackground", pressed },
			{ "Button.default.focusedBackground", accent },
			{ "Button.default.borderColor", accent },
			{ "Button.default.hoverBorderColor", hover },
			{ "Button.default.focusedBorderColor", hover },

			// Tabs — both focused and unfocused selected states
			{ "TabbedPane.underlineColor", accent },
			{ "TabbedPane.inactiveUnderlineColor", inactive },
			{ "TabbedPane.selectedBackground", bg },
			{ "TabbedPane.focusColor", focusRing },
			{ "TabbedPane.hoverColor",
				new Color(accent.getRed(), accent.getGreen(), accent.getBlue(), 30) },

			// Global focus/accent — affects all focusable components
			{ "Component.accentColor", accent },
			{ "Component.focusColor", focusRing },
			{ "Component.focusedBorderColor", accent },

			// CheckBox / RadioButton focus indicators
			{ "CheckBox.icon.focusedBorderColor", accent },
			{ "CheckBox.icon.selectedFocusedBorderColor", accent },
			{ "RadioButton.icon.focusedBorderColor", accent },
			{ "RadioButton.icon.selectedFocusedBorderColor", accent },
		};

		// Write to both the developer defaults table and the L&F defaults
		// table. FlatLaf resolves @accentColor references at install time
		// and caches results in its L&F table; some component UIs read
		// directly from there, bypassing the developer defaults.
		javax.swing.UIDefaults lafDefaults = UIManager.getLookAndFeelDefaults();
		for (Object[] entry : entries) {
			String key = (String) entry[0];
			Object value = entry[1];
			UIManager.put(key, value);
			if (lafDefaults != null) {
				lafDefaults.put(key, value);
			}
		}
	}

	/**
	 * Compute a subtle accent color derived from the background.
	 * In dark themes the accent is lighter than the control background
	 * with a faint blue tint; in light themes it is darker.
	 */
	private static Color computeSubtleAccent(Color bg, Color controlBg) {
		if (luminance(bg) < 128) {
			// Dark: lighten and shift slightly toward blue
			return new Color(
					Math.min(255, controlBg.getRed() + 22),
					Math.min(255, controlBg.getGreen() + 28),
					Math.min(255, controlBg.getBlue() + 38));
		} else {
			// Light: darken and shift slightly toward blue
			return new Color(
					Math.max(0, controlBg.getRed() - 35),
					Math.max(0, controlBg.getGreen() - 30),
					Math.max(0, controlBg.getBlue() - 20));
		}
	}

	private static double luminance(Color c) {
		return 0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue();
	}

	private static Color lighten(Color c, int amount) {
		return new Color(
				Math.min(255, c.getRed() + amount),
				Math.min(255, c.getGreen() + amount),
				Math.min(255, c.getBlue() + amount));
	}

	private static Color darken(Color c, int amount) {
		return new Color(
				Math.max(0, c.getRed() - amount),
				Math.max(0, c.getGreen() - amount),
				Math.max(0, c.getBlue() - amount));
	}

	/**
	 * Load saved window bounds, or null if none saved.
	 *
	 * @return Rectangle with saved x, y, width, height or null
	 */
	public static Rectangle loadWindowBounds() {
		Properties props = loadProperties();
		String sx = props.getProperty(KEY_WINDOW_X);
		String sy = props.getProperty(KEY_WINDOW_Y);
		String sw = props.getProperty(KEY_WINDOW_W);
		String sh = props.getProperty(KEY_WINDOW_H);
		if (sx == null || sy == null || sw == null || sh == null) {
			return null;
		}
		try {
			return new Rectangle(Integer.parseInt(sx),
					Integer.parseInt(sy), Integer.parseInt(sw),
					Integer.parseInt(sh));
		} catch (NumberFormatException e) {
			logger.warn("Invalid window bounds in properties");
			return null;
		}
	}

	/**
	 * Save window bounds to the properties file.
	 *
	 * @param bounds Window position and size
	 */
	public static void saveWindowBounds(Rectangle bounds) {
		Properties props = loadProperties();
		props.setProperty(KEY_WINDOW_X, String.valueOf(bounds.x));
		props.setProperty(KEY_WINDOW_Y, String.valueOf(bounds.y));
		props.setProperty(KEY_WINDOW_W, String.valueOf(bounds.width));
		props.setProperty(KEY_WINDOW_H, String.valueOf(bounds.height));
		File file = new File(getHomeDir(), PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
		} catch (IOException e) {
			logger.error("Failed to save window bounds", e);
		}
	}

	/**
	 * Load URL history from the properties file.
	 *
	 * @return List of URLs, most recent first (up to 5)
	 */
	public static List<String> loadUrlHistory() {
		Properties props = loadProperties();
		List<String> history = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			String url = props.getProperty("history.url." + i);
			if (url != null && !url.isEmpty()) {
				history.add(url);
			}
		}
		return history;
	}

	/**
	 * Save URL history to the properties file.
	 *
	 * @param history List of URLs, most recent first (max 5 saved)
	 */
	public static void saveUrlHistory(List<String> history) {
		Properties props = loadProperties();
		// Clear old entries
		for (int i = 0; i < 5; i++) {
			props.remove("history.url." + i);
		}
		int limit = Math.min(history.size(), 5);
		for (int i = 0; i < limit; i++) {
			props.setProperty("history.url." + i, history.get(i));
		}
		File file = new File(getHomeDir(), PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
		} catch (IOException e) {
			logger.error("Failed to save URL history", e);
		}
	}

	/**
	 * Load scan target history from the properties file.
	 *
	 * @return List of {label, targetText} pairs, most recent first (max 5)
	 */
	public static List<String[]> loadScanTargetHistory() {
		Properties props = loadProperties();
		List<String[]> history = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			String label = props.getProperty("batch.history.label." + i);
			String targets = props.getProperty("batch.history.targets." + i);
			if (label != null && !label.isEmpty() && targets != null) {
				history.add(new String[] { label, targets.replace("|", "\n") });
			}
		}
		return history;
	}

	/**
	 * Save scan target history to the properties file.
	 *
	 * @param history List of {label, targetText} pairs, most recent first (max 5 saved)
	 */
	public static void saveScanTargetHistory(List<String[]> history) {
		Properties props = loadProperties();
		// Clear old entries
		for (int i = 0; i < 5; i++) {
			props.remove("batch.history.label." + i);
			props.remove("batch.history.targets." + i);
		}
		int limit = Math.min(history.size(), 5);
		for (int i = 0; i < limit; i++) {
			props.setProperty("batch.history.label." + i, history.get(i)[0]);
			props.setProperty("batch.history.targets." + i,
					history.get(i)[1].replace("\n", "|"));
		}
		File file = new File(getHomeDir(), PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
		} catch (IOException e) {
			logger.error("Failed to save scan target history", e);
		}
	}

	/**
	 * Load the last folder used in the Save dialog.
	 *
	 * @return Last save folder path, or null if none saved
	 */
	public static String loadLastSaveFolder() {
		Properties props = loadProperties();
		return props.getProperty(KEY_SAVE_LAST_FOLDER);
	}

	/**
	 * Save the last folder used in the Save dialog.
	 *
	 * @param folderPath Folder path to persist
	 */
	public static void saveLastSaveFolder(String folderPath) {
		Properties props = loadProperties();
		props.setProperty(KEY_SAVE_LAST_FOLDER, folderPath);
		File file = new File(getHomeDir(), PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
		} catch (IOException e) {
			logger.error("Failed to save last save folder", e);
		}
	}

	/**
	 * Load the last file format used in the Save dialog.
	 *
	 * @return Last format ("txt", "rtf", or "html"), or "txt" if none saved
	 */
	public static String loadLastSaveFormat() {
		Properties props = loadProperties();
		return props.getProperty(KEY_SAVE_LAST_FORMAT, "txt");
	}

	/**
	 * Save the last file format used in the Save dialog.
	 *
	 * @param format Format string ("txt", "rtf", or "html")
	 */
	public static void saveLastSaveFormat(String format) {
		Properties props = loadProperties();
		props.setProperty(KEY_SAVE_LAST_FORMAT, format);
		File file = new File(getHomeDir(), PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet user preferences");
		} catch (IOException e) {
			logger.error("Failed to save last save format", e);
		}
	}

	// ---- accessors ----

	/** @return the display font */
	public Font getFont() {
		return font;
	}

	/** @param font the display font */
	public void setFont(Font font) {
		this.font = font;
	}

	/** @return the background color */
	public Color getBackground() {
		return background;
	}

	/** @param background the background color */
	public void setBackground(Color background) {
		this.background = background;
	}

	/** @return the default text color */
	public Color getDefaultText() {
		return defaultText;
	}

	/** @param defaultText the default text color */
	public void setDefaultText(Color defaultText) {
		this.defaultText = defaultText;
	}

	/** @return the notice/banner color */
	public Color getNotice() {
		return notice;
	}

	/** @param notice the notice/banner color */
	public void setNotice(Color notice) {
		this.notice = notice;
	}

	/** @return the section heading color */
	public Color getHeading() {
		return heading;
	}

	/** @param heading the section heading color */
	public void setHeading(Color heading) {
		this.heading = heading;
	}

	/** @return the section content color */
	public Color getContent() {
		return content;
	}

	/** @param content the section content color */
	public void setContent(Color content) {
		this.content = content;
	}

	/** @return the key color for key=value lines */
	public Color getKey() {
		return key;
	}

	/** @param key the key color for key=value lines */
	public void setKey(Color key) {
		this.key = key;
	}

	/** @return the value color for key=value lines */
	public Color getValue() {
		return value;
	}

	/** @param value the value color for key=value lines */
	public void setValue(Color value) {
		this.value = value;
	}

	/** @return the warning text color */
	public Color getWarning() {
		return warning;
	}

	/** @param warning the warning text color */
	public void setWarning(Color warning) {
		this.warning = warning;
	}

	/** @return the subsection label color */
	public Color getSubsection() {
		return subsection;
	}

	/** @param subsection the subsection label color */
	public void setSubsection(Color subsection) {
		this.subsection = subsection;
	}

	/** @return the highlight color (used for Server Target URL in header) */
	public Color getHighlight() {
		return highlight;
	}

	/** @param highlight the highlight color */
	public void setHighlight(Color highlight) {
		this.highlight = highlight;
	}

	/** @return the risk assessment pass color */
	public Color getRiskPass() {
		return riskPass;
	}

	/** @param riskPass the risk assessment pass color */
	public void setRiskPass(Color riskPass) {
		this.riskPass = riskPass;
	}

	/** @return the risk assessment inconclusive color */
	public Color getRiskInconclusive() {
		return riskInconclusive;
	}

	/** @param riskInconclusive the risk assessment inconclusive color */
	public void setRiskInconclusive(Color riskInconclusive) {
		this.riskInconclusive = riskInconclusive;
	}

	/** @return the risk assessment fail color */
	public Color getRiskFail() {
		return riskFail;
	}

	/** @param riskFail the risk assessment fail color */
	public void setRiskFail(Color riskFail) {
		this.riskFail = riskFail;
	}

	/** @return the risk priority critical color */
	public Color getRiskCritical() {
		return riskCritical;
	}

	/** @param riskCritical the risk priority critical color */
	public void setRiskCritical(Color riskCritical) {
		this.riskCritical = riskCritical;
	}

	/** @return the risk priority high color */
	public Color getRiskHigh() {
		return riskHigh;
	}

	/** @param riskHigh the risk priority high color */
	public void setRiskHigh(Color riskHigh) {
		this.riskHigh = riskHigh;
	}

	/** @return the risk priority medium color */
	public Color getRiskMedium() {
		return riskMedium;
	}

	/** @param riskMedium the risk priority medium color */
	public void setRiskMedium(Color riskMedium) {
		this.riskMedium = riskMedium;
	}

	/** @return the risk priority low color */
	public Color getRiskLow() {
		return riskLow;
	}

	/** @param riskLow the risk priority low color */
	public void setRiskLow(Color riskLow) {
		this.riskLow = riskLow;
	}

	/** @return the risk priority info color */
	public Color getRiskInfo() {
		return riskInfo;
	}

	/** @param riskInfo the risk priority info color */
	public void setRiskInfo(Color riskInfo) {
		this.riskInfo = riskInfo;
	}

	/**
	 * Return the color for a given risk severity level.
	 *
	 * @param severity severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO), or null
	 * @return the corresponding color, or warning color for null/unknown
	 */
	public Color getColorForSeverity(String severity) {
		if (severity == null) return warning;
		return switch (severity) {
			case "CRITICAL" -> riskCritical;
			case "HIGH" -> riskHigh;
			case "MEDIUM" -> riskMedium;
			case "LOW" -> riskLow;
			case "INFO" -> riskInfo;
			default -> warning;
		};
	}

	/** @return true if hard wrapping is enabled */
	public boolean isHardwrapEnabled() {
		return hardwrapEnabled;
	}

	/** @param hardwrapEnabled true to enable hard wrapping */
	public void setHardwrapEnabled(boolean hardwrapEnabled) {
		this.hardwrapEnabled = hardwrapEnabled;
	}

	/** @return the hard wrap width in characters */
	public int getHardwrapWidth() {
		return hardwrapWidth;
	}

	/** @param hardwrapWidth the hard wrap width in characters */
	public void setHardwrapWidth(int hardwrapWidth) {
		this.hardwrapWidth = hardwrapWidth;
	}

	// ---- engine settings accessors ----

	public boolean isSectionRiskAssessment() { return sectionRiskAssessment; }
	public void setSectionRiskAssessment(boolean v) { this.sectionRiskAssessment = v; }

	public boolean isSectionRuntimeEnvironment() { return sectionRuntimeEnvironment; }
	public void setSectionRuntimeEnvironment(boolean v) { this.sectionRuntimeEnvironment = v; }

	/** Header is always included when any report section is printed. */
	public boolean isSectionHeader() { return true; }
	/** No-op: header is always included. Kept for backward compatibility. */
	public void setSectionHeader(boolean v) { /* always true */ }

	public boolean isSectionHost() { return sectionHost; }
	public void setSectionHost(boolean v) { this.sectionHost = v; }

	public boolean isSectionHttpResponse() { return sectionHttpResponse; }
	public void setSectionHttpResponse(boolean v) { this.sectionHttpResponse = v; }

	public boolean isSectionSecurityHeaders() { return sectionSecurityHeaders; }
	public void setSectionSecurityHeaders(boolean v) { this.sectionSecurityHeaders = v; }

	public boolean isSectionConnection() { return sectionConnection; }
	public void setSectionConnection(boolean v) { this.sectionConnection = v; }

	public boolean isSectionCipherSuites() { return sectionCipherSuites; }
	public void setSectionCipherSuites(boolean v) { this.sectionCipherSuites = v; }

	public boolean isSectionCertChain() { return sectionCertChain; }
	public void setSectionCertChain(boolean v) { this.sectionCertChain = v; }

	public boolean isSectionRevocation() { return sectionRevocation; }
	public void setSectionRevocation(boolean v) { this.sectionRevocation = v; }

	public boolean isSectionTlsFingerprint() { return sectionTlsFingerprint; }
	public void setSectionTlsFingerprint(boolean v) { this.sectionTlsFingerprint = v; }

	public String getCipherConvention() { return cipherConvention; }
	public void setCipherConvention(String v) { this.cipherConvention = v; }

	public boolean isProtocolSslv3() { return protocolSslv3; }
	public void setProtocolSslv3(boolean v) { this.protocolSslv3 = v; }

	public boolean isProtocolTls10() { return protocolTls10; }
	public void setProtocolTls10(boolean v) { this.protocolTls10 = v; }

	public boolean isProtocolTls11() { return protocolTls11; }
	public void setProtocolTls11(boolean v) { this.protocolTls11 = v; }

	public boolean isProtocolTls12() { return protocolTls12; }
	public void setProtocolTls12(boolean v) { this.protocolTls12 = v; }

	public boolean isProtocolTls13() { return protocolTls13; }
	public void setProtocolTls13(boolean v) { this.protocolTls13 = v; }

	public int getRiskScale() { return riskScale; }
	public void setRiskScale(int v) { this.riskScale = Math.max(10, Math.min(50, v)); }

	public int getScanScale() { return SCAN_SCALE; }
	public void setScanScale(int v) { /* fixed at SCAN_SCALE */ }

	// ---- unified scanning settings accessors ----

	public int getWorkerThreads() { return workerThreads; }
	public void setWorkerThreads(int v) { this.workerThreads = Math.max(1, Math.min(10, v)); }

	public long getThrottleDelayMs() { return throttleDelayMs; }
	public void setThrottleDelayMs(long v) { this.throttleDelayMs = Math.max(0, Math.min(10000, v)); }

	public int getMaxCidrExpansion() { return maxCidrExpansion; }
	public void setMaxCidrExpansion(int v) { this.maxCidrExpansion = Math.max(1, Math.min(1_000_000, v)); }

	// ---- scan accessors (delegate to individual for backwards compatibility) ----

	public boolean isScanSectionRiskAssessment() { return sectionRiskAssessment; }
	public void setScanSectionRiskAssessment(boolean v) { this.sectionRiskAssessment = v; }

	public boolean isScanSectionHttpResponse() { return sectionHttpResponse; }
	public void setScanSectionHttpResponse(boolean v) { this.sectionHttpResponse = v; }

	public boolean isScanSectionSecurityHeaders() { return sectionSecurityHeaders; }
	public void setScanSectionSecurityHeaders(boolean v) { this.sectionSecurityHeaders = v; }

	public boolean isScanSectionConnection() { return sectionConnection; }
	public void setScanSectionConnection(boolean v) { this.sectionConnection = v; }

	public boolean isScanSectionCipherSuites() { return sectionCipherSuites; }
	public void setScanSectionCipherSuites(boolean v) { this.sectionCipherSuites = v; }

	public boolean isScanSectionRevocation() { return sectionRevocation; }
	public void setScanSectionRevocation(boolean v) { this.sectionRevocation = v; }

	public boolean isScanSectionTlsFingerprint() { return sectionTlsFingerprint; }
	public void setScanSectionTlsFingerprint(boolean v) { this.sectionTlsFingerprint = v; }

	public String getScanCipherConvention() { return cipherConvention; }
	public void setScanCipherConvention(String v) { this.cipherConvention = v; }

	public boolean isScanProtocolSslv3() { return protocolSslv3; }
	public void setScanProtocolSslv3(boolean v) { this.protocolSslv3 = v; }

	public boolean isScanProtocolTls10() { return protocolTls10; }
	public void setScanProtocolTls10(boolean v) { this.protocolTls10 = v; }

	public boolean isScanProtocolTls11() { return protocolTls11; }
	public void setScanProtocolTls11(boolean v) { this.protocolTls11 = v; }

	public boolean isScanProtocolTls12() { return protocolTls12; }
	public void setScanProtocolTls12(boolean v) { this.protocolTls12 = v; }

	public boolean isScanProtocolTls13() { return protocolTls13; }
	public void setScanProtocolTls13(boolean v) { this.protocolTls13 = v; }

	public int getScanWorkerThreads() { return workerThreads; }
	public void setScanWorkerThreads(int v) { this.workerThreads = Math.max(1, Math.min(10, v)); }

	public long getScanThrottleDelayMs() { return throttleDelayMs; }
	public void setScanThrottleDelayMs(long v) { this.throttleDelayMs = Math.max(0, Math.min(10000, v)); }

	public Font getScanFont() { return font; }
	public void setScanFont(Font v) { this.font = v; }

	public Color getScanBackground() { return background; }
	public void setScanBackground(Color v) { this.background = v; }

	public Color getScanDefaultText() { return defaultText; }
	public void setScanDefaultText(Color v) { this.defaultText = v; }

	public Color getScanNotice() { return notice; }
	public void setScanNotice(Color v) { this.notice = v; }

	public Color getScanHeading() { return heading; }
	public void setScanHeading(Color v) { this.heading = v; }

	public Color getScanContent() { return content; }
	public void setScanContent(Color v) { this.content = v; }

	public Color getScanKey() { return key; }
	public void setScanKey(Color v) { this.key = v; }

	public Color getScanValue() { return value; }
	public void setScanValue(Color v) { this.value = v; }

	public Color getScanWarning() { return warning; }
	public void setScanWarning(Color v) { this.warning = v; }

	public Color getScanSubsection() { return subsection; }
	public void setScanSubsection(Color v) { this.subsection = v; }

	public Color getScanHighlight() { return highlight; }
	public void setScanHighlight(Color v) { this.highlight = v; }

	public Color getScanRiskPass() { return riskPass; }
	public void setScanRiskPass(Color v) { this.riskPass = v; }

	public Color getScanRiskInconclusive() { return riskInconclusive; }
	public void setScanRiskInconclusive(Color v) { this.riskInconclusive = v; }

	public Color getScanRiskFail() { return riskFail; }
	public void setScanRiskFail(Color v) { this.riskFail = v; }

	public boolean isScanHardwrapEnabled() { return hardwrapEnabled; }
	public void setScanHardwrapEnabled(boolean v) { this.hardwrapEnabled = v; }

	public int getScanHardwrapWidth() { return hardwrapWidth; }
	public void setScanHardwrapWidth(int v) { this.hardwrapWidth = v; }

	// ---- AI report configuration accessors ----

	public boolean isAiReportEnabled() { return aiReportEnabled; }
	public void setAiReportEnabled(boolean v) { this.aiReportEnabled = v; }

	/**
	 * Returns true if AI reports are enabled AND an API key is configured
	 * (or the provider is Ollama, which doesn't require a key).
	 */
	public boolean isReportReady() {
		if (!aiReportEnabled) return false;
		if ("Ollama".equalsIgnoreCase(aiProvider)) return true;
		return aiApiKey != null && !aiApiKey.isBlank();
	}

	public String getAiProvider() { return aiProvider; }
	public void setAiProvider(String v) { this.aiProvider = v; }

	public String getAiApiKey() { return aiApiKey; }
	public void setAiApiKey(String v) { this.aiApiKey = v; }

	public String getAiModel() { return aiModel; }
	public void setAiModel(String v) { this.aiModel = v; }

	public int getAiMaxTokens() { return aiMaxTokens; }
	public void setAiMaxTokens(int v) { this.aiMaxTokens = v; }

	public double getAiTemperature() { return aiTemperature; }
	public void setAiTemperature(double v) { this.aiTemperature = v; }

	public String getAiSystemPrompt() { return aiSystemPrompt; }
	public void setAiSystemPrompt(String v) { this.aiSystemPrompt = v; }

	public String getAiChatSystemPrompt() { return aiChatSystemPrompt; }
	public void setAiChatSystemPrompt(String v) { this.aiChatSystemPrompt = v; }

	public String getAiEndpointUrl() { return aiEndpointUrl; }
	public void setAiEndpointUrl(String v) { this.aiEndpointUrl = v; }

	public boolean isSectionAiEvaluation() { return sectionAiEvaluation; }
	public void setSectionAiEvaluation(boolean v) { this.sectionAiEvaluation = v; }

	// ---- AI chat configuration accessors ----

	public boolean isAiChatEnabled() { return aiChatEnabled; }
	public void setAiChatEnabled(boolean v) { this.aiChatEnabled = v; }

	/**
	 * Returns true if AI chat is enabled AND an API key is configured
	 * (or the provider is Ollama, which doesn't require a key).
	 */
	public boolean isChatReady() {
		if (!aiChatEnabled) return false;
		if ("Ollama".equalsIgnoreCase(aiChatProvider)) return true;
		return aiChatApiKey != null && !aiChatApiKey.isBlank();
	}

	public String getAiChatProvider() { return aiChatProvider; }
	public void setAiChatProvider(String v) { this.aiChatProvider = v; }

	public String getAiChatApiKey() { return aiChatApiKey; }
	public void setAiChatApiKey(String v) { this.aiChatApiKey = v; }

	public String getAiChatModel() { return aiChatModel; }
	public void setAiChatModel(String v) { this.aiChatModel = v; }

	public int getAiChatMaxTokens() { return aiChatMaxTokens; }
	public void setAiChatMaxTokens(int v) { this.aiChatMaxTokens = v; }

	public double getAiChatTemperature() { return aiChatTemperature; }
	public void setAiChatTemperature(double v) { this.aiChatTemperature = v; }

	public String getAiChatEndpointUrl() { return aiChatEndpointUrl; }
	public void setAiChatEndpointUrl(String v) { this.aiChatEndpointUrl = v; }

	// ---- AI terminal color accessors ----

	public Color getAiTerminalBg() { return aiTerminalBg; }
	public void setAiTerminalBg(Color v) { this.aiTerminalBg = v; }

	public Color getAiTerminalUserPrefix() { return aiTerminalUserPrefix; }
	public void setAiTerminalUserPrefix(Color v) { this.aiTerminalUserPrefix = v; }

	public Color getAiTerminalUserText() { return aiTerminalUserText; }
	public void setAiTerminalUserText(Color v) { this.aiTerminalUserText = v; }

	public Color getAiTerminalAiPrefix() { return aiTerminalAiPrefix; }
	public void setAiTerminalAiPrefix(Color v) { this.aiTerminalAiPrefix = v; }

	public Color getAiTerminalAiText() { return aiTerminalAiText; }
	public void setAiTerminalAiText(Color v) { this.aiTerminalAiText = v; }

	public Color getAiTerminalError() { return aiTerminalError; }
	public void setAiTerminalError(Color v) { this.aiTerminalError = v; }

	public Color getAiTerminalSystem() { return aiTerminalSystem; }
	public void setAiTerminalSystem(Color v) { this.aiTerminalSystem = v; }

	public Color getAiTerminalSelectionBg() { return aiTerminalSelectionBg; }
	public void setAiTerminalSelectionBg(Color v) { this.aiTerminalSelectionBg = v; }

	public Color getAiTerminalSelectionFg() { return aiTerminalSelectionFg; }
	public void setAiTerminalSelectionFg(Color v) { this.aiTerminalSelectionFg = v; }

	// ---- custom cipher map / user risk rules accessors ----

	public boolean isCustomCipherMapEnabled() { return customCipherMapEnabled; }
	public void setCustomCipherMapEnabled(boolean v) { this.customCipherMapEnabled = v; }

	public boolean isUserRiskRulesEnabled() { return userRiskRulesEnabled; }
	public void setUserRiskRulesEnabled(boolean v) { this.userRiskRulesEnabled = v; }

	/** @return the file where the custom cipher map YAML is stored */
	public static File getCustomCipherMapFile() {
		return new File(new File(new File(getHomeDir(), "ui"), CIPHER_MAP_DIR), CUSTOM_CIPHER_MAP_FILE);
	}

	/** Load the custom cipher map YAML from disk, or null if not present. */
	public static String loadCustomCipherMapYaml() {
		File f = getCustomCipherMapFile();
		if (!f.exists()) return null;
		try {
			return Files.readString(f.toPath(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to load custom cipher map YAML", e);
			return null;
		}
	}

	/** Save custom cipher map YAML to disk. */
	public static void saveCustomCipherMapYaml(String yaml) {
		File dir = new File(new File(getHomeDir(), "ui"), CIPHER_MAP_DIR);
		dir.mkdirs();
		try {
			Files.writeString(getCustomCipherMapFile().toPath(), yaml, StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to save custom cipher map YAML", e);
		}
	}

	/**
	 * Load the DeepViolet API's built-in {@code ciphermap.yaml} from the classpath.
	 * @return the YAML content, or {@code null} if the resource is not found
	 */
	public static String loadApiDefaultCipherMapYaml() {
		try (InputStream in = FontPreferences.class.getClassLoader()
				.getResourceAsStream("ciphermap.yaml")) {
			if (in == null) return null;
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to load API default cipher map", e);
			return null;
		}
	}

	/**
	 * Copy the API's built-in cipher map to the local custom file if it does
	 * not already exist.  Called once during {@link #load()} so first-launch
	 * users see the full cipher map pre-populated.
	 */
	public static void ensureDefaultCipherMap() {
		File f = getCustomCipherMapFile();
		if (f.exists()) return;
		String apiDefault = loadApiDefaultCipherMapYaml();
		if (apiDefault != null) {
			saveCustomCipherMapYaml(apiDefault);
		}
	}

	/** Delete the custom cipher map YAML file. */
	public static void deleteCustomCipherMapYaml() {
		File f = getCustomCipherMapFile();
		if (f.exists()) {
			f.delete();
		}
	}

	/** @return the file where the user risk rules YAML is stored */
	public static File getUserRiskRulesFile() {
		return new File(new File(new File(getHomeDir(), "ui"), RISK_RULES_DIR), USER_RISK_RULES_FILE);
	}

	/**
	 * Load the user risk rules YAML from disk.
	 * Returns the built-in defaults when no user file exists yet,
	 * or null if the file was explicitly cleared.
	 */
	public static String loadUserRiskRulesYaml() {
		File f = getUserRiskRulesFile();
		if (!f.exists()) return DEFAULT_USER_RISK_RULES;
		try {
			return Files.readString(f.toPath(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to load user risk rules YAML", e);
			return null;
		}
	}

	/** Save user risk rules YAML to disk. */
	public static void saveUserRiskRulesYaml(String yaml) {
		File dir = new File(new File(getHomeDir(), "ui"), RISK_RULES_DIR);
		dir.mkdirs();
		try {
			Files.writeString(getUserRiskRulesFile().toPath(), yaml, StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to save user risk rules YAML", e);
		}
	}

	/** Clear the user risk rules by writing an empty sentinel file. */
	public static void deleteUserRiskRulesYaml() {
		File dir = new File(new File(getHomeDir(), "ui"), RISK_RULES_DIR);
		dir.mkdirs();
		try {
			Files.writeString(getUserRiskRulesFile().toPath(), "", StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to clear user risk rules YAML", e);
		}
	}

	// ---- application theme accessors ----

	public boolean isAppThemeCustom() { return appThemeCustom; }
	public void setAppThemeCustom(boolean v) { this.appThemeCustom = v; }

	public Font getAppFont() { return appFont; }
	public void setAppFont(Font v) { this.appFont = v; }

	public Color getAppBackground() { return appBackground; }
	public void setAppBackground(Color v) { this.appBackground = v; }

	public Color getAppForeground() { return appForeground; }
	public void setAppForeground(Color v) { this.appForeground = v; }

	public Color getAppButtonBg() { return appButtonBg; }
	public void setAppButtonBg(Color v) { this.appButtonBg = v; }

	public Color getAppButtonFg() { return appButtonFg; }
	public void setAppButtonFg(Color v) { this.appButtonFg = v; }

	// Card display getters/setters
	public Font getCardFont() { return cardFont; }
	public void setCardFont(Font v) { this.cardFont = v; }
	public int getCardBadgeSize() { return cardBadgeSize; }
	public void setCardBadgeSize(int v) { this.cardBadgeSize = v; }
	public Color getCardBg() { return cardBg; }
	public void setCardBg(Color v) { this.cardBg = v; }
	public Color getCardText() { return cardText; }
	public void setCardText(Color v) { this.cardText = v; }
	public Color getCardDim() { return cardDim; }
	public void setCardDim(Color v) { this.cardDim = v; }
	public Color getCardBorder() { return cardBorder; }
	public void setCardBorder(Color v) { this.cardBorder = v; }
	public Color getCardSelected() { return cardSelected; }
	public void setCardSelected(Color v) { this.cardSelected = v; }
	public Color getCardError() { return cardError; }
	public void setCardError(Color v) { this.cardError = v; }
	public CardLayout getCardLayout() { return cardLayout; }
	public void setCardLayout(CardLayout v) { this.cardLayout = v; }
	public CardSize getCardSize() { return cardSize; }
	public void setCardSize(CardSize v) { this.cardSize = v; }

	public boolean isWorkbenchMode() { return workbenchMode; }
	public void setWorkbenchMode(boolean v) { this.workbenchMode = v; }

	// ---- dock position accessors ----

	public String getDockCardPanel() { return dockCardPanel; }
	public void setDockCardPanel(String v) { this.dockCardPanel = v; }

	public String getDockToolbar() { return dockToolbar; }
	public void setDockToolbar(String v) { this.dockToolbar = v; }

	public String getDockTargetButtons() { return dockTargetButtons; }
	public void setDockTargetButtons(String v) { this.dockTargetButtons = v; }

	public String getDockGradeBar() { return dockGradeBar; }
	public void setDockGradeBar(String v) { this.dockGradeBar = v; }

	// ---- splitter position accessors ----

	public int getSplitScan() { return splitScan; }
	public void setSplitScan(int v) { this.splitScan = v; }

	public int getSplitDetail() { return splitDetail; }
	public void setSplitDetail(int v) { this.splitDetail = v; }

	public int getSplitExternalDetail() { return splitExternalDetail; }
	public void setSplitExternalDetail(int v) { this.splitExternalDetail = v; }

	// ---- card layout helpers ----

	private static CardLayout loadCardLayout(Properties props) {
		CardLayout def = CardLayout.defaultLayout();

		// Load grid dimensions (default 3x5)
		int cols = CardLayout.DEFAULT_COLS;
		int rows = CardLayout.DEFAULT_ROWS;
		try {
			cols = Integer.parseInt(props.getProperty(KEY_CARD_GRID_COLS,
					String.valueOf(CardLayout.DEFAULT_COLS)));
		} catch (NumberFormatException e) { /* use default */ }
		try {
			rows = Integer.parseInt(props.getProperty(KEY_CARD_GRID_ROWS,
					String.valueOf(CardLayout.DEFAULT_ROWS)));
		} catch (NumberFormatException e) { /* use default */ }

		// Load weights
		double[] colWeights = parseWeights(
				props.getProperty(KEY_CARD_GRID_COL_WEIGHTS), cols);
		double[] rowWeights = parseWeights(
				props.getProperty(KEY_CARD_GRID_ROW_WEIGHTS), rows);

		// Load element configs (auto-detects legacy 4-field vs new 5-field)
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		for (CardMetaElement elem : CardMetaElement.values()) {
			String val = props.getProperty(KEY_CARD_LAYOUT_PREFIX + elem.getPropertyKey());
			CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(elem, val);
			if (parsed != null) {
				slots.add(parsed);
			} else {
				// Fall back to default for this element
				CardSlotConfig defSlot = def.getConfig(elem);
				if (defSlot != null) {
					slots.add(defSlot);
				}
			}
		}
		return new CardLayout(slots, cols, rows, colWeights, rowWeights);
	}

	private static void saveCardLayout(Properties props, CardLayout layout) {
		// Always write version=2 (grid format)
		props.setProperty(KEY_CARD_GRID_VERSION, "2");
		props.setProperty(KEY_CARD_GRID_COLS, String.valueOf(layout.getCols()));
		props.setProperty(KEY_CARD_GRID_ROWS, String.valueOf(layout.getRows()));
		props.setProperty(KEY_CARD_GRID_COL_WEIGHTS, encodeWeights(layout.getColWeights()));
		props.setProperty(KEY_CARD_GRID_ROW_WEIGHTS, encodeWeights(layout.getRowWeights()));

		for (CardSlotConfig slot : layout.getSlots()) {
			props.setProperty(KEY_CARD_LAYOUT_PREFIX + slot.getElement().getPropertyKey(),
					slot.toPropertyValue());
		}
	}

	private static double[] parseWeights(String value, int expectedSize) {
		if (value == null || value.isEmpty()) {
			return CardLayout.uniformWeights(expectedSize);
		}
		String[] parts = value.split(",");
		double[] weights = new double[parts.length];
		try {
			for (int i = 0; i < parts.length; i++) {
				weights[i] = Double.parseDouble(parts[i].trim());
			}
		} catch (NumberFormatException e) {
			return CardLayout.uniformWeights(expectedSize);
		}
		return weights;
	}

	private static String encodeWeights(double[] weights) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < weights.length; i++) {
			if (i > 0) sb.append(',');
			sb.append(String.format("%.4f", weights[i]));
		}
		return sb.toString();
	}

	// ---- helpers ----

	private static String encodeColor(Color c) {
		return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(),
				c.getBlue());
	}

	private static Color readColor(Properties props, String key,
			Color fallback) {
		String val = props.getProperty(key);
		if (val != null && val.startsWith("#") && val.length() == 7) {
			try {
				return Color.decode(val);
			} catch (NumberFormatException e) {
				logger.warn("Invalid color for " + key + ", using default");
			}
		}
		return fallback;
	}

	private static int parseIntProp(Properties props, String key, int fallback) {
		String val = props.getProperty(key);
		if (val == null) return fallback;
		try {
			return Integer.parseInt(val.trim());
		} catch (NumberFormatException e) {
			return fallback;
		}
	}

	private static Properties loadProperties() {
		Properties props = new Properties();
		File file = new File(getHomeDir(), PROPS_FILE);
		if (file.exists()) {
			try (FileInputStream in = new FileInputStream(file)) {
				props.load(in);
			} catch (IOException e) {
				logger.error("Failed to load properties file", e);
			}
		}
		return props;
	}

	// ---- encryption helpers ----

	/**
	 * Ensure an encryption seed exists in {@code ~/.deepviolet/global.properties}.
	 * Call this once during application startup (both GUI and CLI).
	 * If no seed is present, a random AES-256 key is generated and persisted.
	 * Seeds in the old location ({@code deepviolet.properties}) are migrated
	 * automatically.
	 */
	public static void ensureEncryptionSeed() {
		Properties globalProps = loadGlobalProperties();
		if (globalProps.getProperty(KEY_ENCRYPTION_SEED) != null) {
			return;
		}

		// Migrate seed from old location if present
		Properties localProps = loadProperties();
		String existingSeed = localProps.getProperty(KEY_ENCRYPTION_SEED);
		if (existingSeed != null) {
			globalProps.setProperty(KEY_ENCRYPTION_SEED, existingSeed);
			saveGlobalProperties(globalProps);
			// Remove from local properties
			localProps.remove(KEY_ENCRYPTION_SEED);
			File dir = getHomeDir();
			dir.mkdirs();
			File file = new File(dir, PROPS_FILE);
			try (FileOutputStream out = new FileOutputStream(file)) {
				localProps.store(out, "DeepViolet user preferences");
			} catch (IOException e) {
				logger.error("Failed to remove seed from local properties", e);
			}
			logger.info("Encryption seed migrated to global properties");
			return;
		}

		// Generate a new seed
		byte[] seed = new byte[32]; // AES-256
		new SecureRandom().nextBytes(seed);
		globalProps.setProperty(KEY_ENCRYPTION_SEED, Base64.getEncoder().encodeToString(seed));
		saveGlobalProperties(globalProps);
		logger.info("Encryption seed generated");
	}

	/**
	 * Decrypt the API key from the properties.  Handles three cases:
	 * <ol>
	 *   <li>Empty/missing — returns empty string</li>
	 *   <li>Encrypted (valid base64 with IV+ciphertext) — decrypts and returns plaintext</li>
	 *   <li>Legacy plaintext — returns as-is (will be encrypted on next save)</li>
	 * </ol>
	 */
	private static String decryptApiKey(Properties props, String propKey) {
		String stored = props.getProperty(propKey, "");
		if (stored.isEmpty()) {
			return "";
		}
		String seedB64 = loadGlobalProperties().getProperty(KEY_ENCRYPTION_SEED);
		if (seedB64 == null) {
			// No seed yet — value is plaintext (legacy)
			return stored;
		}
		try {
			byte[] cipherBytes = Base64.getDecoder().decode(stored);
			// Encrypted values are at minimum IV (12) + tag (16) = 28 bytes
			if (cipherBytes.length < GCM_IV_BYTES + 16) {
				// Too short to be encrypted — treat as legacy plaintext
				return stored;
			}
			byte[] seed = Base64.getDecoder().decode(seedB64);
			return decrypt(cipherBytes, seed);
		} catch (IllegalArgumentException e) {
			// Not valid base64 — legacy plaintext key
			return stored;
		} catch (Exception e) {
			logger.warn("Failed to decrypt API key, treating as plaintext", e);
			return stored;
		}
	}

	/**
	 * Encrypt the API key and store it in the properties under the given key.
	 */
	private static void encryptApiKey(Properties props, String propKey, String apiKey) {
		if (apiKey == null || apiKey.isEmpty()) {
			props.setProperty(propKey, "");
			return;
		}
		String seedB64 = loadGlobalProperties().getProperty(KEY_ENCRYPTION_SEED);
		if (seedB64 == null) {
			// No seed — store plaintext (will be encrypted after seed is created)
			props.setProperty(propKey, apiKey);
			return;
		}
		try {
			byte[] seed = Base64.getDecoder().decode(seedB64);
			byte[] encrypted = encrypt(apiKey, seed);
			props.setProperty(propKey, Base64.getEncoder().encodeToString(encrypted));
		} catch (Exception e) {
			logger.error("Failed to encrypt API key", e);
			props.setProperty(propKey, apiKey);
		}
	}

	/**
	 * AES-256-GCM encrypt.  Returns IV (12 bytes) || ciphertext+tag.
	 */
	private static byte[] encrypt(String plaintext, byte[] key) throws Exception {
		SecureRandom sr = new SecureRandom();
		byte[] iv = new byte[GCM_IV_BYTES];
		sr.nextBytes(iv);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE,
				new SecretKeySpec(key, "AES"),
				new GCMParameterSpec(GCM_TAG_BITS, iv));
		byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

		byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * AES-256-GCM decrypt.  Expects IV (12 bytes) || ciphertext+tag.
	 */
	private static String decrypt(byte[] data, byte[] key) throws Exception {
		byte[] iv = new byte[GCM_IV_BYTES];
		System.arraycopy(data, 0, iv, 0, GCM_IV_BYTES);
		byte[] ciphertext = new byte[data.length - GCM_IV_BYTES];
		System.arraycopy(data, GCM_IV_BYTES, ciphertext, 0, ciphertext.length);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE,
				new SecretKeySpec(key, "AES"),
				new GCMParameterSpec(GCM_TAG_BITS, iv));
		byte[] plaintext = cipher.doFinal(ciphertext);
		return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
	}

	/**
	 * Return the 32-byte AES-256 encryption key from properties, or null
	 * if no seed has been generated yet.
	 */
	static byte[] getEncryptionSeed() {
		String seedB64 = loadGlobalProperties().getProperty(KEY_ENCRYPTION_SEED);
		if (seedB64 == null) {
			return null;
		}
		return Base64.getDecoder().decode(seedB64);
	}

	/**
	 * AES-256-GCM encrypt arbitrary bytes.
	 * Returns IV (12 bytes) || ciphertext || auth tag (16 bytes).
	 */
	static byte[] encryptBytes(byte[] plaintext, byte[] key) throws Exception {
		SecureRandom sr = new SecureRandom();
		byte[] iv = new byte[GCM_IV_BYTES];
		sr.nextBytes(iv);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE,
				new SecretKeySpec(key, "AES"),
				new GCMParameterSpec(GCM_TAG_BITS, iv));
		byte[] ciphertext = cipher.doFinal(plaintext);

		byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * AES-256-GCM decrypt arbitrary bytes.
	 * Expects IV (12 bytes) || ciphertext || auth tag (16 bytes).
	 * Throws if the auth tag validation fails (tampered data).
	 */
	static byte[] decryptBytes(byte[] data, byte[] key) throws Exception {
		byte[] iv = new byte[GCM_IV_BYTES];
		System.arraycopy(data, 0, iv, 0, GCM_IV_BYTES);
		byte[] ciphertext = new byte[data.length - GCM_IV_BYTES];
		System.arraycopy(data, GCM_IV_BYTES, ciphertext, 0, ciphertext.length);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE,
				new SecretKeySpec(key, "AES"),
				new GCMParameterSpec(GCM_TAG_BITS, iv));
		return cipher.doFinal(ciphertext);
	}

	/**
	 * Compute the SHA-256 hash of the given data and return it as a
	 * lowercase 64-character hex string.
	 *
	 * @return hex digest, or {@code null} on failure
	 */
	public static String sha256Hex(byte[] data) {
		try {
			java.security.MessageDigest md =
					java.security.MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(data);
			StringBuilder sb = new StringBuilder(64);
			for (byte b : hash) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		} catch (java.security.NoSuchAlgorithmException e) {
			logger.error("SHA-256 not available", e);
			return null;
		}
	}
}
