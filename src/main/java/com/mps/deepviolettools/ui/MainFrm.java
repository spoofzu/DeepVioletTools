package com.mps.deepviolettools.ui;

import java.awt.Desktop;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GridBagConstraints;
import java.awt.Graphics;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Taskbar;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Rectangle;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.imageio.ImageIO;
import javax.swing.Box;
import javax.swing.BorderFactory;
import javax.swing.JEditorPane;
import javax.swing.JSplitPane;
import javax.swing.event.HyperlinkEvent;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JPopupMenu;
import javax.swing.ListSelectionModel;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToolBar;
import javax.swing.Timer;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.rtf.RTFEditorKit;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;
import com.mps.deepviolettools.job.ScanTask;
import com.mps.deepviolettools.job.UIBackgroundScanTask;
import com.mps.deepviolettools.ui.DockablePanel.DockPosition;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.SourceProvenance;
import com.mps.deepviolettools.model.CipherDelta;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.model.FingerprintDelta;
import com.mps.deepviolettools.model.HeatMapData;
import com.mps.deepviolettools.model.HostDelta;
import com.mps.deepviolettools.model.MapDelta;
import com.mps.deepviolettools.model.RiskDelta;
import com.mps.deepviolettools.model.ScanNode;
import com.mps.deepviolettools.util.AiAnalysisService;
import com.mps.deepviolettools.util.DeltaScanner;
import com.mps.deepviolettools.util.FontPreferences;
import com.mps.deepviolettools.util.ReportExporter;
import com.mps.deepviolettools.util.TargetParser;

import org.ms.terminal.gui.TerminalPanel;
import org.ms.terminal.gui.TerminalView;

/**
 * Build main application UI used by StartUI. Creates the JFrame and deploys
 * user interface control elements.
 *
 * @author Milton Smith
 *
 */
public class MainFrm extends JFrame {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.ui.MainFrm");
	private static final Logger chatLog = LoggerFactory.getLogger("aichat");

	private static final long serialVersionUID = -7591324908851824818L;
	private StyledDocument doc;

	private static final String STATUS_HDR = "Status: ";

	private static JFileChooser fc;

	private FontPreferences themePrefs;

	private JTabbedPane mainTabs;
	private TerminalView aiTerminalView;
	private TerminalPanel aiTerminal;
	private JTextField txtAiInput;
	private JButton btnAiSend;
	private java.util.List<AiAnalysisService.ChatMessage> chatHistory = new java.util.ArrayList<>();
	private Timer aiDotTimer;
	private int aiDotCount;

	private ScanResult.HostResult aiActiveHost;

	private JButton btnScanSelector;
	private String selectedScanLabel;
	private String selectedScanText;
	private File scansDir;
	private File reportsDir;
	private List<File> cachedScanFiles = new ArrayList<>();

	// ---- Scan tab fields ----
	private ScanResultsPanel scanResultsPanel;
	private JButton btnScanClear;
	private JButton btnSaveTargets;
	private File targetsDir;
	private static final String SCAN_PLACEHOLDER_TEXT =
			"# Add comments like this\n" +
			"192.168.1.1\n" +
			"10.0.1.5:8443\n" +
			"10.0.2.1-50\n" +
			"[2001:db8::1]\n" +
			"[::1]:8443\n" +
			"example.com\n" +
			"example.com:8443\n" +
			"https://www.example.com/\n" +
			"172.16.0.0/16\n" +
			"10.0.0.0/24\n" +
			"2001:db8::/120";
	private boolean targetsPlaceholder = true;
	private javax.swing.JTextArea txtTargets;
	private JButton btnLoadFile;
	private JButton btnScan;
	private JButton btnSave;
	private JButton btnSaveScan;
	private JButton btnLoadScan;
	private JButton btnClearScan;
	private JButton btnDelta;
	private JToolBar scanToolbar;
	private JTextField txtActiveScan;
	private JTextField txtScanStatus;
	private JTextField txtScanProgress;
	private Timer scanStatusTimer;
	private Timer statusResetTimer;
	private JTextPane tpScanResults;
	private StyledDocument scanResultsDoc;
	private ScanTask currentScanTask;
	private long scanStartTime;
	private ScanResult currentScanResult;
	private DeltaScanResult currentDeltaResult;
	private JButton btnTestServers;
	private DockablePanel dockableResultsPanel;
	private DeltaResultsPanel deltaResultsPanel;
	private DockablePanel dockableDeltaPanel;
	private JPanel cardLayoutContainer;
	private java.awt.CardLayout cardLayoutSwitcher;
	private JPanel scanTabPanel;
	private JPanel pnlTopTargets;
	private JPanel pnlTargetRow;
	private JScrollPane spTargets;
	private String targetButtonsDock = "RIGHT";
	private JPopupMenu targetDockMenu;
	private JPanel pnlSelector;
	private java.awt.event.MouseAdapter targetDragAdapter;
	private boolean targetDragging;
	private String targetDropZone;
	private JPanel targetDropOverlay;

	// Scan toolbar dock state
	private String toolbarDock = "NORTH";
	private boolean toolbarDragging;
	private String toolbarDropZone;
	private JPanel toolbarDropOverlay;
	private JPopupMenu toolbarDockMenu;
	private JPanel scanStatusPanel;
	private JSplitPane externalDetailSplit;
	private JSplitPane splitScan;
	private List<String[]> scanTargetHistory;
	private SourceProvenance scanTargetProvenance;
	private JMenuItem modeMenuItem;

	/**
	 * CTOR
	 */
	public MainFrm() {

		super();

		// Set application icon for window (Windows/Linux) and dock (macOS)
		try {
			Image logo = ImageIO.read(getClass().getResourceAsStream("/deepviolet-logo.png"));
			setIconImage(logo);
			if (Taskbar.isTaskbarSupported()) {
				Taskbar taskbar = Taskbar.getTaskbar();
				if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
					taskbar.setIconImage(logo);
				}
			}
		} catch (Exception e) {
			// Non-fatal — continue without custom icon
		}

		setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				saveSplitterPositions();
				FontPreferences.saveWindowBounds(getBounds());
				System.exit(0);
			}
		});
		// Save window bounds on Ctrl-C / SIGINT
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			if (isDisplayable()) {
				FontPreferences.saveWindowBounds(getBounds());
			}
		}));
		themePrefs = FontPreferences.load();
		scanTargetHistory = FontPreferences.loadScanTargetHistory();
		File homeDir = FontPreferences.getHomeDir();
		scansDir = new File(homeDir, "ui" + File.separator + "scans");
		scansDir.mkdirs();
		reportsDir = new File(homeDir, "ui" + File.separator + "reports");
		reportsDir.mkdirs();
		targetsDir = new File(homeDir, "ui" + File.separator + "targets");
		targetsDir.mkdirs();
		migrateScanFolders();
		FontPreferences.applyAppTheme(themePrefs);

	}

	/**
	 * One-time migration: move .txt scan files from old subdirectory layouts
	 * (scans/single/, scans/batch/, batchscans/) into the unified scans/ directory.
	 */
	private void migrateScanFolders() {
		// Migrate from scans/single/ -> scans/
		File oldSingleDir = new File(scansDir, "single");
		if (oldSingleDir.isDirectory()) {
			File[] oldFiles = oldSingleDir.listFiles((dir, name) -> name.endsWith(".txt"));
			if (oldFiles != null) {
				for (File f : oldFiles) {
					File dest = new File(scansDir, f.getName());
					if (!dest.exists()) {
						f.renameTo(dest);
					}
				}
			}
		}

		// Migrate from scans/batch/ -> scans/
		File oldBatchSubDir = new File(scansDir, "batch");
		if (oldBatchSubDir.isDirectory()) {
			File[] oldFiles = oldBatchSubDir.listFiles((dir, name) -> name.endsWith(".txt"));
			if (oldFiles != null) {
				for (File f : oldFiles) {
					File dest = new File(scansDir, f.getName());
					if (!dest.exists()) {
						f.renameTo(dest);
					}
				}
			}
		}

		// Migrate from targets/batch/ -> targets/
		File oldTargetBatchDir = new File(targetsDir, "batch");
		if (oldTargetBatchDir.isDirectory()) {
			File[] oldFiles = oldTargetBatchDir.listFiles();
			if (oldFiles != null) {
				for (File f : oldFiles) {
					File dest = new File(targetsDir, f.getName());
					if (!dest.exists()) {
						f.renameTo(dest);
					}
				}
			}
		}

		// Migrate from old batchscans/ -> scans/
		File oldBatchDir = new File(FontPreferences.getHomeDir(),
				"ui" + File.separator + "batchscans");
		if (oldBatchDir.isDirectory()) {
			File[] oldFiles = oldBatchDir.listFiles((dir, name) -> name.endsWith(".txt"));
			if (oldFiles != null) {
				for (File f : oldFiles) {
					File dest = new File(scansDir, f.getName());
					if (!dest.exists()) {
						f.renameTo(dest);
					}
				}
			}
		}
	}

	/**
	 * Build the UI.
	 */
	public void initComponents() {

		// Menu bar
		JMenuBar menuBar = new JMenuBar();

		JMenu fileMenu = new JMenu("System");
		JMenuItem settingsItem = new JMenuItem("Settings");
		settingsItem.addActionListener(e -> selectionBtnThemePressed());
		fileMenu.add(settingsItem);
		fileMenu.addSeparator();
		JMenuItem exitItem = new JMenuItem("Exit");
		exitItem.addActionListener(e -> {
			FontPreferences.saveWindowBounds(getBounds());
			System.exit(0);
		});
		fileMenu.add(exitItem);
		menuBar.add(fileMenu);

		JMenu devMenu = new JMenu("Developer");
		modeMenuItem = new JMenuItem(
				themePrefs.isWorkbenchMode() ? "Mode: advanced" : "Mode: normal");
		modeMenuItem.addActionListener(e -> toggleMode());
		devMenu.add(modeMenuItem);
		menuBar.add(devMenu);

		JMenu helpMenu = new JMenu("Help");
		JMenuItem interfaceItem = new JMenuItem("Interface");
		interfaceItem.addActionListener(e -> showInterfaceHelp());
		helpMenu.add(interfaceItem);
		helpMenu.addSeparator();
		JMenuItem aboutItem = new JMenuItem("About");
		aboutItem.addActionListener(e -> showAboutDialog());
		helpMenu.add(aboutItem);
		menuBar.add(helpMenu);

		// Right-justified application title (non-interactive)
		menuBar.add(Box.createHorizontalGlue());
		JMenu brandLabel = new JMenu("DeepViolet TLS Workbench");
		brandLabel.setEnabled(false);
		menuBar.add(brandLabel);

		setJMenuBar(menuBar);

		// ---- AI tab ----
		JPanel pnlAi = buildAiChatPanel();

		// ---- Scan tab ----
		JPanel pnlScan = buildScanTab();

		// ---- Main tabbed pane (top-level, like Settings dialog) ----
		mainTabs = new JTabbedPane();
		mainTabs.addTab("Scan", pnlScan);
		mainTabs.addTab("AI Assistant", pnlAi);

		// Enable/disable AI tab based on config + API key + scan data
		updateAiTabState();

		// Switch default button and focus when changing tabs
		mainTabs.addChangeListener(e -> {
			if (mainTabs.getSelectedIndex() == 1) {
				getRootPane().setDefaultButton(btnAiSend);
				// Re-sync aiActiveHost with the card currently selected on the Scan tab
				if (scanResultsPanel.isDetailShowing()) {
					ScanResult.HostResult cardHost = scanResultsPanel.getSelectedHostResult();
					if (cardHost != null && cardHost != aiActiveHost) {
						aiActiveHost = cardHost;
						chatHistory.clear();
					}
				}
				if (aiActiveHost != null) {
					updateAiWelcomeMessage();
				} else {
					syncScanSelector();
				}
				javax.swing.SwingUtilities.invokeLater(() -> txtAiInput.requestFocusInWindow());
			} else if (mainTabs.getSelectedIndex() == 0) {
				getRootPane().setDefaultButton(btnScan);
				javax.swing.SwingUtilities.invokeLater(() -> btnScan.requestFocusInWindow());
			}
		});

		// Frame layout: wrap tabbed pane in a panel with top padding so
		// tabs don't sit flush against the menu bar (JTabbedPane.setBorder
		// is ignored by the macOS Aqua L&F).
		getContentPane().setLayout(new java.awt.BorderLayout());
		JPanel tabWrapper = new JPanel(new java.awt.BorderLayout());
		tabWrapper.setBorder(BorderFactory.createCompoundBorder(
				BorderFactory.createMatteBorder(2, 0, 0, 0, new Color(90, 90, 90)),
				BorderFactory.createEmptyBorder(8, 0, 0, 0)));
		tabWrapper.add(mainTabs, java.awt.BorderLayout.CENTER);
		getContentPane().add(tabWrapper, java.awt.BorderLayout.CENTER);

		setResizable(true);

		// Restore saved window bounds or use defaults
		Rectangle savedBounds = FontPreferences.loadWindowBounds();
		if (savedBounds != null) {
			setBounds(savedBounds);
		} else {
			Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
			setSize(screen.width / 2, screen.height * 2 / 3);
			centerOnScreen();
		}

		// Listener for Window resize
		this.addComponentListener(new ComponentAdapter() {
			public void componentResized(ComponentEvent e) {
				refresh();
			}
		});

	}

	/**
	 * Apply the current theme preferences to the scan results pane and
	 * graphical scan results panel. Re-renders from the scan result if available.
	 */
	private void applyTheme() {
		// Restore targets placeholder foreground (updateComponentTreeUI may reset it)
		if (txtTargets != null && targetsPlaceholder) {
			txtTargets.setForeground(Color.GRAY);
		}

		if (tpScanResults == null) return;
		tpScanResults.setBackground(themePrefs.getScanBackground());
		tpScanResults.setFont(themePrefs.getScanFont());
		tpScanResults.setCaretColor(themePrefs.getScanDefaultText());

		if (scanResultsPanel != null) {
			scanResultsPanel.applyTheme(themePrefs);
		}
		if (deltaResultsPanel != null) {
			deltaResultsPanel.applyTheme(themePrefs);
		}

		applyScanToolbarIcons();
		applyTargetIcons();

		// Re-render from scan result if available
		if (currentScanResult != null) {
			renderScanResults(currentScanResult);
		}
	}

	/**
	 * Load toolbar icons matching the current dark/light theme.
	 * Detects the theme by checking the Panel.background luminance.
	 */
	private void applyScanToolbarIcons() {
		if (scanToolbar == null) return;
		Color bg = javax.swing.UIManager.getColor("Panel.background");
		if (bg == null) bg = getBackground();
		boolean isDark = (0.299 * bg.getRed() + 0.587 * bg.getGreen()
				+ 0.114 * bg.getBlue()) < 128;
		String suffix = isDark ? "dark" : "light";
		int iconSize = 28;

		setToolbarIcon(btnScan, "/icons/scan-" + suffix + ".png", iconSize);
		setToolbarIcon(btnSaveScan, "/icons/save-scan-" + suffix + ".png", iconSize);
		setToolbarIcon(btnLoadScan, "/icons/load-scan-" + suffix + ".png", iconSize);
		setToolbarIcon(btnClearScan, "/icons/clear-scan-" + suffix + ".png", iconSize);
		setToolbarIcon(btnDelta, "/icons/delta-scan-" + suffix + ".png", iconSize);
		setToolbarIcon(btnSave, "/icons/save-detail-" + suffix + ".png", iconSize);
	}

	/**
	 * Load target-button icons matching the current dark/light theme.
	 */
	private void applyTargetIcons() {
		if (btnLoadFile == null) return;
		Color bg = javax.swing.UIManager.getColor("Panel.background");
		if (bg == null) bg = getBackground();
		boolean isDark = (0.299 * bg.getRed() + 0.587 * bg.getGreen()
				+ 0.114 * bg.getBlue()) < 128;
		String suffix = isDark ? "dark" : "light";
		int iconSize = 24;

		setToolbarIcon(btnLoadFile, "/icons/load-targets-" + suffix + ".png", iconSize);
		setToolbarIcon(btnScanClear, "/icons/clear-targets-" + suffix + ".png", iconSize);
		setToolbarIcon(btnSaveTargets, "/icons/save-targets-" + suffix + ".png", iconSize);
	}

	private void setToolbarIcon(JButton btn, String resourcePath, int size) {
		try {
			java.io.InputStream is = getClass().getResourceAsStream(resourcePath);
			if (is != null) {
				Image img = ImageIO.read(is);
				Image scaled = img.getScaledInstance(size, size, Image.SCALE_SMOOTH);
				btn.setIcon(new ImageIcon(scaled));
			}
		} catch (IOException e) {
			logger.debug("Could not load toolbar icon: {}", resourcePath);
		}
	}

	/**
	 * Append a key=value line with hard wrapping. The key= prefix is rendered
	 * on the first line; if the value overflows, continuation lines are
	 * indented and rendered in value color.
	 */
	private void appendWrappedKeyValue(String prefix, String value,
			String contIndent, int wrapWidth, Font font) {

		String fullLine = prefix + value;
		if (fullLine.length() <= wrapWidth) {
			// Fits on one line
			appendStyled(prefix.substring(0, prefix.length() - 1), font, themePrefs.getKey(), false);
			appendStyled("=", font, themePrefs.getContent(), false);
			appendStyled(value + "\n", font, themePrefs.getValue(), false);
			return;
		}

		// First segment: key=<part of value>
		int firstValueLen = wrapWidth - prefix.length();
		if (firstValueLen <= 0) {
			// Key itself is longer than wrap width; just render key= then wrap value
			appendStyled(prefix.substring(0, prefix.length() - 1), font, themePrefs.getKey(), false);
			appendStyled("=", font, themePrefs.getContent(), false);
			appendStyled("\n", font, themePrefs.getValue(), false);
			wrapValueContinuation(value, contIndent, wrapWidth, font);
			return;
		}

		int end = findBreakPoint(value, firstValueLen);
		appendStyled(prefix.substring(0, prefix.length() - 1), font, themePrefs.getKey(), false);
		appendStyled("=", font, themePrefs.getContent(), false);
		appendStyled(value.substring(0, end) + "\n", font, themePrefs.getValue(), false);

		// Remaining continuation lines
		if (end < value.length()) {
			wrapValueContinuation(value.substring(end).trim(), contIndent, wrapWidth, font);
		}
	}

	/**
	 * Render continuation lines for a wrapped value.
	 */
	private void wrapValueContinuation(String text, String contIndent,
			int wrapWidth, Font font) {
		int pos = 0;
		int lineLen = wrapWidth - contIndent.length();
		if (lineLen <= 0) lineLen = 20;

		while (pos < text.length()) {
			int remaining = text.length() - pos;
			int end;
			if (remaining <= lineLen) {
				end = text.length();
			} else {
				end = pos + findBreakPoint(text.substring(pos), lineLen);
			}
			String segment = text.substring(pos, end).trim();
			if (!segment.isEmpty()) {
				appendStyled(contIndent + segment + "\n", font, themePrefs.getValue(), false);
			}
			pos = end;
		}
	}

	/**
	 * Append a single-color line with optional hard wrapping.
	 */
	private void appendWrappedSingle(String text, String contIndent,
			boolean wrap, int wrapWidth, Font font, Color fg, boolean bold) {
		if (!wrap || text.length() <= wrapWidth) {
			appendStyled(text + "\n", font, fg, bold);
			return;
		}

		int pos = 0;
		boolean first = true;
		while (pos < text.length()) {
			int available = first ? wrapWidth : wrapWidth - contIndent.length();
			if (available <= 0) available = 20;
			int remaining = text.length() - pos;
			int end;
			if (remaining <= available) {
				end = text.length();
			} else {
				end = pos + findBreakPoint(text.substring(pos), available);
			}
			String segment = text.substring(pos, end);
			if (!first) {
				segment = contIndent + segment.trim();
			}
			appendStyled(segment + "\n", font, fg, bold);
			pos = end;
			first = false;
		}
	}

	/**
	 * Find a suitable break point within maxLen characters of text.
	 * Prefers breaking at comma or space boundaries. For colon-delimited
	 * hex strings (e.g. "AA:BB:CC:DD"), breaks after a complete octet
	 * boundary to avoid splitting "AA:B" across lines.
	 */
	private int findBreakPoint(String text, int maxLen) {
		if (text.length() <= maxLen) {
			return text.length();
		}
		// Prefer comma or space break points
		int lastComma = text.lastIndexOf(',', maxLen);
		int lastSpace = text.lastIndexOf(' ', maxLen);
		int breakAt = Math.max(lastComma, lastSpace);
		if (breakAt > 20) {
			return breakAt + 1;
		}
		// No comma/space found — check for colon-delimited hex octets.
		// Find the last colon within range and break after it, but only
		// if the colon sits at an octet boundary (every 3rd character in
		// "XX:XX:XX" patterns).
		int lastColon = text.lastIndexOf(':', maxLen);
		if (lastColon > 0) {
			// Verify this looks like hex octets around the colon
			// by checking that the character before the colon is a hex digit
			char before = text.charAt(lastColon - 1);
			boolean isHexBoundary = isHexDigit(before);
			if (isHexBoundary) {
				return lastColon + 1;
			}
		}
		// No good break point; hard-break at maxLen
		return maxLen;
	}

	private static boolean isHexDigit(char c) {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	}

	/**
	 * Append styled text to the document.
	 */
	private void appendStyled(String text, Font font, Color fg, boolean bold) {
		SimpleAttributeSet attrs = new SimpleAttributeSet();
		StyleConstants.setFontFamily(attrs, font.getFamily());
		StyleConstants.setFontSize(attrs, font.getSize());
		StyleConstants.setForeground(attrs, fg);
		StyleConstants.setBold(attrs, bold);
		try {
			doc.insertString(doc.getLength(), text, attrs);
		} catch (BadLocationException e) {
			logger.error(e.getMessage(), e);
		}
	}

	/**
	 * Check if text contains risk bar characters (pass/inconclusive/fail blocks).
	 */
	private boolean containsBarChars(String text) {
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c == '\u2588' || c == '\u2590' || c == '\u2591') return true;
		}
		return false;
	}

	/**
	 * Render a bar line character-by-character with per-character coloring:
	 * █ (pass) → value color, ▐ (inconclusive) → notice color, ░ (fail) → warning color.
	 */
	private void appendBarLine(String text, Font font) {
		int i = 0;
		while (i < text.length()) {
			char c = text.charAt(i);
			if (c == '\u2588' || c == '\u2590' || c == '\u2591') {
				// Collect consecutive same-type bar chars
				int start = i;
				while (i < text.length() && text.charAt(i) == c) i++;
				Color color;
				if (c == '\u2588') {
					color = themePrefs.getRiskPass();         // pass (green)
				} else if (c == '\u2590') {
					color = themePrefs.getRiskInconclusive(); // inconclusive (amber)
				} else {
					color = themePrefs.getRiskFail();         // fail (red)
				}
				// Render as solid blocks so color isn't diluted by
				// semi-transparent glyphs (▐ and ░) on dark backgrounds
				String solid = "\u2588".repeat(i - start);
				appendStyled(solid, font, color, false);
			} else {
				// Collect consecutive non-bar chars
				int start = i;
				while (i < text.length() && text.charAt(i) != '\u2588'
						&& text.charAt(i) != '\u2590' && text.charAt(i) != '\u2591') {
					i++;
				}
				appendStyled(text.substring(start, i), font, themePrefs.getContent(), false);
			}
		}
		appendStyled("\n", font, themePrefs.getContent(), false);
	}

	/**
	 * Show a modal dialog with a semi-transparent overlay on the parent frame
	 * and movement tracking so the dialog follows the parent when dragged.
	 *
	 * @param dialog The modal dialog to display
	 */
	private void showModalWithOverlay(JDialog dialog) {
		// Semi-transparent overlay to visually indicate the parent is locked
		JPanel overlay = new JPanel() {
			@Override
			protected void paintComponent(Graphics g) {
				g.setColor(new Color(0, 0, 0, 80));
				g.fillRect(0, 0, getWidth(), getHeight());
			}
		};
		overlay.setOpaque(false);

		Component oldGlassPane = getGlassPane();
		setGlassPane(overlay);
		overlay.setVisible(true);

		// Track parent movement so the dialog follows the main window
		final int[] lastPos = { getX(), getY() };
		ComponentAdapter moveTracker = new ComponentAdapter() {
			@Override
			public void componentMoved(ComponentEvent e) {
				int dx = getX() - lastPos[0];
				int dy = getY() - lastPos[1];
				lastPos[0] = getX();
				lastPos[1] = getY();
				dialog.setLocation(dialog.getX() + dx, dialog.getY() + dy);
			}
		};
		addComponentListener(moveTracker);

		// Show the modal dialog (blocks until dismissed)
		dialog.setVisible(true);

		// Cleanup
		removeComponentListener(moveTracker);
		overlay.setVisible(false);
		setGlassPane(oldGlassPane);
	}

	/**
	 * Toggle between normal and workbench mode.
	 * Switching to normal mode resets section preferences to defaults
	 * (header + TLS risk assessment only).
	 */
	private void toggleMode() {
		boolean newMode = !themePrefs.isWorkbenchMode();
		themePrefs.setWorkbenchMode(newMode);
		if (!newMode) {
			// Returning to normal mode: reset sections to header + risk only
			themePrefs.setSectionRiskAssessment(true);
			themePrefs.setSectionAiEvaluation(false);
			themePrefs.setSectionRuntimeEnvironment(false);
			themePrefs.setSectionHost(false);
			themePrefs.setSectionHttpResponse(false);
			themePrefs.setSectionSecurityHeaders(false);
			themePrefs.setSectionConnection(false);
			themePrefs.setSectionCipherSuites(false);
			themePrefs.setSectionCertChain(false);
			themePrefs.setSectionRevocation(false);
			themePrefs.setSectionTlsFingerprint(false);
		}
		FontPreferences.save(themePrefs);
		modeMenuItem.setText(newMode ? "Mode: advanced" : "Mode: normal");
		if (currentDeltaResult != null) {
			deltaResultsPanel.refreshDetail();
		}
	}

	/**
	 * Action when theme button pressed. Open theme settings dialog.
	 */
	private void selectionBtnThemePressed() {
		FontChooserDialog dlg = new FontChooserDialog(this, themePrefs);
		showModalWithOverlay(dlg);
		if (dlg.isApproved()) {
			themePrefs = dlg.getPreferences();
			FontPreferences.save(themePrefs);
			FontPreferences.applyAppTheme(themePrefs);
		}
		// Update AI tab state
		updateAiTabState();
		applyAiTerminalColors();
		// Refresh AI terminal status message after settings change
		if (aiTerminal != null && themePrefs.isAiChatEnabled()) {
			aiTerminal.clear();
			aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
			if (!themePrefs.isChatReady()) {
				aiTerminal.write(fmtSystem("API key not configured. Go to System > Settings > AI to enter your API key.\n"));
			} else {
				updateAiReadyMessage();
			}
		}
		// Explicitly set the app font on all components in this window.
		// updateComponentTreeUI alone does not propagate font changes
		// on macOS Aqua L&F.
		setFontRecursively(this, themePrefs.getAppFont());
		// Restore the reporting font/colors on the results pane
		// (overrides the app font that was just set on it above).
		applyTheme();
	}

	private static void setFontRecursively(Component c, Font font) {
		c.setFont(font);
		if (c instanceof Container) {
			for (Component child : ((Container) c).getComponents()) {
				setFontRecursively(child, font);
			}
		}
	}

	/**
	 * Show the About dialog with project information.
	 */
	private void showAboutDialog() {
		Font defaultFont = javax.swing.UIManager.getFont("Label.font");
		String family = defaultFont != null ? defaultFont.getFamily() : "SansSerif";
		int size = defaultFont != null ? defaultFont.getSize() : 12;
		String html = "<html><body style='font-family:" + family + ";font-size:" + size + "pt;'>"
				+ "<b>DeepViolet</b><br>"
				+ "TLS/SSL scanning tool<br><br>"
				+ "Version: 1.0.0-SNAPSHOT<br>"
				+ "License: Apache 2.0<br>"
				+ "Author: Milton Smith<br><br>"
				+ "DeepViolet API<br>"
				+ "<a href='https://github.com/spoofzu/DeepViolet'>"
				+ "<font color='#2563EB'>https://github.com/spoofzu/DeepViolet</font></a><br><br>"
				+ "DeepVioletTools<br>"
				+ "<a href='https://github.com/spoofzu/DeepVioletTools'>"
				+ "<font color='#2563EB'>https://github.com/spoofzu/DeepVioletTools</font></a>"
				+ "</body></html>";
		JEditorPane ep = new JEditorPane("text/html", html);
		ep.setEditable(false);
		ep.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
		ep.addHyperlinkListener(e -> {
			if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
				try {
					Desktop.getDesktop().browse(e.getURL().toURI());
				} catch (Exception ex) {
					logger.warn("Unable to open browser: {}", ex.getMessage());
				}
			}
		});

		JDialog aboutDlg = new JDialog(this, "About DeepViolet", true);
		JPanel contentPanel = new JPanel(new java.awt.BorderLayout(10, 10));
		contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

		// Logo
		try {
			Image logo = ImageIO.read(getClass().getResourceAsStream("/deepviolet-logo.png"));
			Image scaled = logo.getScaledInstance(64, 64, Image.SCALE_SMOOTH);
			JLabel lblLogo = new JLabel(new javax.swing.ImageIcon(scaled));
			lblLogo.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
			contentPanel.add(lblLogo, java.awt.BorderLayout.WEST);
		} catch (Exception ex) {
			// Non-fatal — continue without logo
		}

		contentPanel.add(ep, java.awt.BorderLayout.CENTER);

		JButton btnClose = new JButton("OK");
		btnClose.addActionListener(e -> aboutDlg.dispose());
		JPanel btnPanel = new JPanel();
		btnPanel.add(btnClose);
		contentPanel.add(btnPanel, java.awt.BorderLayout.SOUTH);

		aboutDlg.setContentPane(contentPanel);
		aboutDlg.getRootPane().setDefaultButton(btnClose);
		aboutDlg.setResizable(true);
		aboutDlg.pack();
		aboutDlg.setLocationRelativeTo(this);

		showModalWithOverlay(aboutDlg);
	}

	/**
	 * Show the Interface help dialog with report documentation.
	 */
	private void showInterfaceHelp() {
		InterfaceHelpDialog dlg = new InterfaceHelpDialog(this);
		dlg.setVisible(true);
	}

	/**
	 * Center the UI on the screen.
	 */
	private void centerOnScreen() {

		Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
		this.setLocation(dim.width / 2 - this.getSize().width / 2, dim.height
				/ 2 - this.getSize().height / 2);
	}

	/**
	 * Refresh or update the UI.
	 */
	public void refresh() {

		invalidate();
		revalidate();
		repaint();

	}

	// ---- Scan Tab ----

	/**
	 * Build the Scan tab content: target input, scan/save buttons,
	 * styled text results pane, and status bar.
	 */
	private JPanel buildScanTab() {
		JPanel panel = new JPanel(new java.awt.BorderLayout(0, 6));
		panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 4, 6));

		// ---- Top: target input area + selector panel (80/20 split) ----
		JPanel pnlTop = new JPanel(new java.awt.BorderLayout(4, 4));

		txtTargets = new javax.swing.JTextArea(5, 40);
		txtTargets.setFont(themePrefs.getAppFont());
		txtTargets.setToolTipText("Enter targets: hostnames, IPv4/IPv6 addresses, CIDR blocks, or dash ranges");

		// Placeholder sample text shown in gray until the user clicks in;
		// restored whenever the field is empty and loses focus.
		txtTargets.setText(SCAN_PLACEHOLDER_TEXT);
		txtTargets.setForeground(Color.GRAY);
		targetsPlaceholder = true;

		txtTargets.addFocusListener(new java.awt.event.FocusListener() {
			@Override
			public void focusGained(java.awt.event.FocusEvent e) {
				if (targetsPlaceholder) {
					txtTargets.setText("");
					txtTargets.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
					targetsPlaceholder = false;
				}
			}
			@Override
			public void focusLost(java.awt.event.FocusEvent e) {
				if (txtTargets.getText().trim().isEmpty()) {
					txtTargets.setText(SCAN_PLACEHOLDER_TEXT);
					txtTargets.setForeground(Color.GRAY);
					targetsPlaceholder = true;
				}
			}
		});

		spTargets = new JScrollPane(txtTargets);

		// Column header for the targets area
		JLabel lblTargetHeader = new JLabel("Target");
		lblTargetHeader.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
		spTargets.setColumnHeaderView(lblTargetHeader);

		// Line number gutter showing target numbers
		javax.swing.JTextArea lineNumbers = new javax.swing.JTextArea("1");
		lineNumbers.setEditable(false);
		lineNumbers.setFocusable(false);
		lineNumbers.setBackground(txtTargets.getBackground());
		lineNumbers.setForeground(Color.GRAY);
		lineNumbers.setFont(txtTargets.getFont());
		lineNumbers.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 6));
		Runnable updateLineNumbers = () -> {
			int lines = txtTargets.getLineCount();
			StringBuilder nums = new StringBuilder();
			for (int i = 1; i <= lines; i++) {
				if (i > 1) nums.append("\n");
				nums.append(i);
			}
			String current = lineNumbers.getText();
			String next = nums.toString();
			if (!next.equals(current)) {
				lineNumbers.setText(next);
			}
		};
		txtTargets.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
			@Override public void insertUpdate(javax.swing.event.DocumentEvent e) { updateLineNumbers.run(); }
			@Override public void removeUpdate(javax.swing.event.DocumentEvent e) { updateLineNumbers.run(); }
			@Override public void changedUpdate(javax.swing.event.DocumentEvent e) { updateLineNumbers.run(); }
		});
		updateLineNumbers.run(); // sync gutter with initial placeholder text
		spTargets.setRowHeaderView(lineNumbers);

		// Create target buttons (sized uniformly, icons applied)
		btnLoadFile = new JButton("Load Targets");
		btnScanClear = new JButton("Clear Targets");
		btnSaveTargets = new JButton("Save Targets");
		for (JButton btn : new JButton[] { btnLoadFile, btnScanClear, btnSaveTargets }) {
			btn.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
			btn.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
			btn.setMargin(new Insets(6, 8, 4, 8));
			btn.setFocusable(false);
		}
		applyTargetIcons();
		int targetBtnWidth = 0;
		int targetBtnHeight = 0;
		for (JButton btn : new JButton[] { btnLoadFile, btnScanClear, btnSaveTargets }) {
			Dimension pref = btn.getPreferredSize();
			if (pref.width > targetBtnWidth) targetBtnWidth = pref.width;
			if (pref.height > targetBtnHeight) targetBtnHeight = pref.height;
		}
		for (JButton btn : new JButton[] { btnLoadFile, btnScanClear, btnSaveTargets }) {
			Dimension d = new Dimension(targetBtnWidth, targetBtnHeight);
			btn.setPreferredSize(d);
			btn.setMinimumSize(d);
			btn.setMaximumSize(d);
		}

		// ▼ test servers button — square, matching Load Targets button height
		btnTestServers = new JButton("\u25BC");
		btnTestServers.setToolTipText("Select Scan Target");
		btnTestServers.setMargin(new Insets(0, 2, 0, 2));
		btnTestServers.setFont(btnTestServers.getFont().deriveFont(
				btnTestServers.getFont().getSize2D() * 0.5f));
		{
			int side = btnLoadFile.getPreferredSize().height;
			Dimension d = new Dimension(side, side);
			btnTestServers.setPreferredSize(d);
			btnTestServers.setMinimumSize(d);
		}

		// Right-click context menu to dock target buttons
		targetDockMenu = new JPopupMenu();
		for (String pos : new String[] { "Left", "Right", "Top", "Bottom" }) {
			JMenuItem mi = new JMenuItem("Dock " + pos);
			mi.addActionListener(e -> dockTargetButtons(pos.toUpperCase()));
			targetDockMenu.add(mi);
		}
		java.awt.event.MouseAdapter targetDockMouseAdapter = new java.awt.event.MouseAdapter() {
			@Override public void mousePressed(java.awt.event.MouseEvent e) { showIfPopup(e); }
			@Override public void mouseReleased(java.awt.event.MouseEvent e) { showIfPopup(e); }
			private void showIfPopup(java.awt.event.MouseEvent e) {
				if (e.isPopupTrigger()) {
					targetDockMenu.show(e.getComponent(), e.getX(), e.getY());
				}
			}
		};
		for (JButton btn : new JButton[] { btnTestServers, btnLoadFile,
				btnScanClear, btnSaveTargets }) {
			btn.setComponentPopupMenu(targetDockMenu);
			btn.addMouseListener(targetDockMouseAdapter);
		}

		// Drag-to-dock adapter for the target buttons panel
		targetDragAdapter = new java.awt.event.MouseAdapter() {
			@Override
			public void mousePressed(java.awt.event.MouseEvent e) {
				if (javax.swing.SwingUtilities.isLeftMouseButton(e)) {
					targetDragging = true;
					targetDropZone = null;
					showTargetDropOverlay();
				}
			}

			@Override
			public void mouseDragged(java.awt.event.MouseEvent e) {
				if (!targetDragging) return;
				updateTargetDropZone(e.getLocationOnScreen());
			}

			@Override
			public void mouseReleased(java.awt.event.MouseEvent e) {
				if (!targetDragging) return;
				targetDragging = false;
				hideTargetDropOverlay();
				if (targetDropZone != null && !targetDropZone.equals(targetButtonsDock)) {
					dockTargetButtons(targetDropZone);
				}
				targetDropZone = null;
			}
		};

		// Build target row with buttons in saved dock position
		targetButtonsDock = themePrefs.getDockTargetButtons();
		pnlTargetRow = new JPanel();
		buildTargetButtonLayout();
		pnlTop.add(pnlTargetRow, java.awt.BorderLayout.CENTER);

		// ---- Toolbar: icon buttons above the input area ----
		scanToolbar = new JToolBar();
		scanToolbar.setFloatable(false);
		scanToolbar.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));

		btnScan = new JButton("Scan");
		btnDelta = new JButton("Delta Scan");
		btnSaveScan = new JButton("Save Scan");
		btnSaveScan.setVisible(false);
		btnSave = new JButton("Save Detail");
		btnSave.setVisible(false);
		btnLoadScan = new JButton("Load Scan");
		btnClearScan = new JButton("Clear Scan");
		btnClearScan.setVisible(false);

		JButton[] toolbarButtons = { btnScan, btnDelta,
				btnSaveScan, btnSave, btnLoadScan, btnClearScan };
		for (JButton btn : toolbarButtons) {
			btn.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
			btn.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
			btn.setMargin(new Insets(6, 8, 4, 8));
			btn.setFocusable(false);
			scanToolbar.add(btn);
		}
		applyScanToolbarIcons();

		// Make all toolbar buttons the same size (largest preferred size).
		// btnSave cycles through multiple labels so measure them all.
		String savedText = btnSave.getText();
		int maxW = 0, maxH = 0;
		for (JButton btn : toolbarButtons) {
			Dimension pref = btn.getPreferredSize();
			if (pref.width > maxW) maxW = pref.width;
			if (pref.height > maxH) maxH = pref.height;
		}
		for (String label : new String[] {"Save Detail", "Save Cards", "Save Report"}) {
			btnSave.setText(label);
			Dimension pref = btnSave.getPreferredSize();
			if (pref.width > maxW) maxW = pref.width;
		}
		btnSave.setText(savedText);
		int padX = 16, padY = 10;
		Dimension uniform = new Dimension(maxW + padX, maxH + padY);
		for (JButton btn : toolbarButtons) {
			btn.setPreferredSize(uniform);
			btn.setMinimumSize(uniform);
			btn.setMaximumSize(uniform);
		}

		// Restore toolbar dock position and add grip handle
		toolbarDock = themePrefs.getDockToolbar();
		boolean vertical = "EAST".equals(toolbarDock) || "WEST".equals(toolbarDock);
		if (vertical) {
			scanToolbar.setOrientation(JToolBar.VERTICAL);
		}

		// Grip panel — drag handle for the toolbar
		JPanel toolbarGrip = new JPanel() {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				paintToolbarGrip(g, this);
			}
		};
		toolbarGrip.setOpaque(false);
		toolbarGrip.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.MOVE_CURSOR));
		toolbarGrip.setPreferredSize(vertical ? new Dimension(0, 16) : new Dimension(16, 0));

		// Drag-to-dock adapter for toolbar grip
		java.awt.event.MouseAdapter toolbarDragAdapter = new java.awt.event.MouseAdapter() {
			@Override
			public void mousePressed(java.awt.event.MouseEvent e) {
				if (javax.swing.SwingUtilities.isLeftMouseButton(e)) {
					toolbarDragging = true;
					toolbarDropZone = null;
					showToolbarDropOverlay();
				}
			}

			@Override
			public void mouseDragged(java.awt.event.MouseEvent e) {
				if (!toolbarDragging) return;
				updateToolbarDropZone(e.getLocationOnScreen());
			}

			@Override
			public void mouseReleased(java.awt.event.MouseEvent e) {
				if (!toolbarDragging) return;
				toolbarDragging = false;
				hideToolbarDropOverlay();
				if (toolbarDropZone != null && !toolbarDropZone.equals(toolbarDock)) {
					dockToolbar(toolbarDropZone);
				}
				toolbarDropZone = null;
			}
		};
		toolbarGrip.addMouseListener(toolbarDragAdapter);
		toolbarGrip.addMouseMotionListener(toolbarDragAdapter);
		scanToolbar.add(toolbarGrip, 0);

		// Right-click context menu to dock toolbar
		toolbarDockMenu = new JPopupMenu();
		for (String pos : new String[] { "Top", "Bottom", "Left", "Right" }) {
			JMenuItem mi = new JMenuItem("Dock " + pos);
			mi.addActionListener(e -> dockToolbar(pos.toUpperCase().replace("TOP", "NORTH")
					.replace("BOTTOM", "SOUTH").replace("LEFT", "WEST").replace("RIGHT", "EAST")));
			toolbarDockMenu.add(mi);
		}
		scanToolbar.setComponentPopupMenu(toolbarDockMenu);

		// ---- Center: split pane — targets (top) + results (bottom) ----
		// Off-screen text pane for text export and AI assistant context
		tpScanResults = new JTextPane();
		tpScanResults.setEditable(false);
		scanResultsDoc = tpScanResults.getStyledDocument();

		// Graphical scan results panel wrapped in dockable container
		scanResultsPanel = new ScanResultsPanel(themePrefs, this::renderHostDetail);
		scanResultsPanel.addPropertyChangeListener("viewState", e -> {
			updateSaveButtons();
			updateExternalDetail();
			// Track host selection for AI
			ScanResult.HostResult previousHost = aiActiveHost;
			if (scanResultsPanel.isDetailShowing()) {
				aiActiveHost = scanResultsPanel.getSelectedHostResult();
			} else {
				aiActiveHost = null;
			}
			updateAiTabState();
			// Clear chat when host changes
			if (previousHost != aiActiveHost) {
				chatHistory.clear();
				if (aiTerminal != null) {
					aiTerminal.clearSelection();
					aiTerminal.clear();
					aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
					if (aiActiveHost != null) {
						aiTerminal.write(fmtSystem("Ready for questions about: "
								+ aiActiveHost.getTargetUrl() + "\n"));
					}
				}
				updateScanSelectorButton();
			}
		});

		dockableResultsPanel = new DockablePanel(scanResultsPanel, "Scan Results");
		dockableResultsPanel.addPropertyChangeListener("dockPosition", e -> {
			String newPos = (String) e.getNewValue();
			themePrefs.setDockCardPanel(newPos);
			FontPreferences.save(themePrefs);
			rebuildScanLayout(DockPosition.valueOf(newPos));
		});

		// Delta results panel wrapped in its own dockable container
		deltaResultsPanel = new DeltaResultsPanel(themePrefs);
		deltaResultsPanel.addPropertyChangeListener("viewState", e -> {
			updateSaveButtons();
			updateExternalDetail();
		});
		dockableDeltaPanel = new DockablePanel(deltaResultsPanel, "Delta Results");

		// CardLayout container to switch between scan and delta views
		cardLayoutSwitcher = new java.awt.CardLayout();
		cardLayoutContainer = new JPanel(cardLayoutSwitcher);
		cardLayoutContainer.add(dockableResultsPanel, "SCAN");
		cardLayoutContainer.add(dockableDeltaPanel, "DELTA");

		// Store references for layout rebuilding
		this.scanTabPanel = panel;
		this.pnlTopTargets = pnlTop;

		// ---- Status bar at bottom (auto-compacting) ----
		txtActiveScan = new JTextField("Active Scan: none");
		txtActiveScan.setEditable(false);
		txtActiveScan.setEnabled(false);
		txtActiveScan.setBorder(BorderFactory.createEmptyBorder(4, 6, 1, 6));
		txtActiveScan.setAlignmentX(Component.LEFT_ALIGNMENT);

		txtScanStatus = new JTextField();
		txtScanStatus.setEditable(false);
		txtScanStatus.setEnabled(false);
		txtScanStatus.setBorder(BorderFactory.createEmptyBorder(1, 6, 1, 6));
		txtScanStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
		txtScanStatus.setVisible(false);

		txtScanProgress = new JTextField(STATUS_HDR + "Ready");
		txtScanProgress.setEditable(false);
		txtScanProgress.setEnabled(false);
		txtScanProgress.setBorder(BorderFactory.createEmptyBorder(1, 6, 4, 6));
		txtScanProgress.setAlignmentX(Component.LEFT_ALIGNMENT);

		// Auto-hide status lines when their text is empty
		addAutoHideListener(txtScanStatus);
		addAutoHideListener(txtScanProgress);

		scanStatusPanel = new JPanel();
		scanStatusPanel.setLayout(new BoxLayout(scanStatusPanel, BoxLayout.Y_AXIS));
		scanStatusPanel.setBorder(BorderFactory.createMatteBorder(2, 0, 0, 0, new Color(90, 90, 90)));
		scanStatusPanel.add(txtActiveScan);
		scanStatusPanel.add(txtScanStatus);
		scanStatusPanel.add(txtScanProgress);
		addToolbarToPanel(panel);
		addStatusPanelToScanTab(panel);

		// Build initial layout based on saved card panel dock position
		String savedCardPos = themePrefs.getDockCardPanel();
		DockPosition initialDock = DockPosition.LEFT;
		try {
			initialDock = DockPosition.valueOf(savedCardPos);
		} catch (IllegalArgumentException ignored) { }
		dockableResultsPanel.setDockPosition(initialDock);
		buildScanSplitPane(initialDock);

		// Apply theme colors to scan results pane
		applyTheme();

		// ---- Button listeners ----
		btnLoadFile.addActionListener(e -> onLoadFile());
		btnScanClear.addActionListener(e -> onClearTargets());
		btnSaveTargets.addActionListener(e -> onSaveTargets());
		btnScan.addActionListener(e -> onScanButtonClicked());
		btnSaveScan.addActionListener(e -> onSaveScan());
		btnLoadScan.addActionListener(e -> onLoadScan());
		btnDelta.addActionListener(e -> onDeltaScan());
		btnClearScan.addActionListener(e -> onClearScan());
		btnSave.addActionListener(e -> onSavePressed());
		btnTestServers.addActionListener(e -> onTestServersPressed());

		return panel;
	}

	/**
	 * Build the split pane for the given dock position and add it to the
	 * scan tab panel's CENTER. When docked LEFT/RIGHT, the targets area
	 * component may be wrapped in a vertical split with the detail pane
	 * if a host detail is currently showing.
	 */
	private void buildScanSplitPane(DockPosition pos) {
		boolean isSide = (pos == DockPosition.LEFT || pos == DockPosition.RIGHT);
		boolean isTop = (pos == DockPosition.TOP);
		boolean placeholderActive = scanResultsPanel.isPlaceholderActive();

		// Detail is always external (managed by this layout, not ScanResultsPanel)
		scanResultsPanel.setExternalDetailMode(true);
		deltaResultsPanel.setExternalDetailMode(true);
		externalDetailSplit = null;

		// Pick the active detail scroll pane based on current mode
		JScrollPane activeDetailScroll = currentDeltaResult != null
				? deltaResultsPanel.getDetailScrollPane()
				: scanResultsPanel.getDetailScrollPane();

		if (isSide) {
			// LEFT/RIGHT: wrap targets + detail in a vertical split when needed
			boolean needsDetail = scanResultsPanel.isDetailShowing()
					|| currentDeltaResult != null || placeholderActive;
			Component targetsComponent = pnlTopTargets;
			if (needsDetail) {
				externalDetailSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
						pnlTopTargets, activeDetailScroll);
				externalDetailSplit.setResizeWeight(0.3);
				externalDetailSplit.setContinuousLayout(true);
				targetsComponent = externalDetailSplit;
			}

			if (pos == DockPosition.LEFT) {
				splitScan = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
						cardLayoutContainer, targetsComponent);
				splitScan.setResizeWeight(0.35);
			} else {
				splitScan = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
						targetsComponent, cardLayoutContainer);
				splitScan.setResizeWeight(0.65);
			}
		} else {
			// TOP: three-way vertical — targets | cards | detail
			externalDetailSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
					cardLayoutContainer, activeDetailScroll);
			externalDetailSplit.setResizeWeight(0.3);
			externalDetailSplit.setContinuousLayout(true);

			splitScan = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
					pnlTopTargets, externalDetailSplit);
			splitScan.setResizeWeight(0.25);
		}

		splitScan.setContinuousLayout(true);
		scanTabPanel.add(splitScan, java.awt.BorderLayout.CENTER);

		// Restore saved divider positions after layout is complete
		int savedScanDiv = themePrefs.getSplitScan();
		int savedExtDetail = themePrefs.getSplitExternalDetail();
		if (savedScanDiv >= 0 || savedExtDetail >= 0) {
			javax.swing.SwingUtilities.invokeLater(() -> {
				if (savedScanDiv >= 0) {
					splitScan.setDividerLocation(savedScanDiv);
				}
				if (savedExtDetail >= 0 && externalDetailSplit != null) {
					externalDetailSplit.setDividerLocation(savedExtDetail);
				}
			});
		}
	}

	/**
	 * Capture current splitter positions into preferences and persist.
	 */
	private void saveSplitterPositions() {
		if (splitScan != null) {
			themePrefs.setSplitScan(splitScan.getDividerLocation());
		}
		if (externalDetailSplit != null) {
			themePrefs.setSplitExternalDetail(externalDetailSplit.getDividerLocation());
		}
		int detailDiv = scanResultsPanel.getDetailDividerLocation();
		if (detailDiv >= 0) {
			themePrefs.setSplitDetail(detailDiv);
		}
		FontPreferences.save(themePrefs);
	}

	/**
	 * Rebuild the scan tab layout when the card panel dock position changes.
	 */
	private void rebuildScanLayout(DockPosition pos) {
		// Remove the old split pane from the center
		java.awt.BorderLayout layout = (java.awt.BorderLayout) scanTabPanel.getLayout();
		Component center = layout.getLayoutComponent(java.awt.BorderLayout.CENTER);
		if (center != null) {
			scanTabPanel.remove(center);
		}
		buildScanSplitPane(pos);
		scanTabPanel.revalidate();
		scanTabPanel.repaint();
	}

	/**
	 * Show or hide the external detail pane when the card panel dock
	 * position changes or the view state changes. For TOP dock, the
	 * detail pane is always present; for LEFT/RIGHT, it appears only
	 * when a host detail, delta report, or placeholder is active.
	 */
	private void updateExternalDetail() {
		DockPosition pos = dockableResultsPanel.getDockPosition();
		if (pos == DockPosition.TOP) return; // detail always present in 3-way split

		boolean isSide = (pos == DockPosition.LEFT || pos == DockPosition.RIGHT);
		boolean placeholderActive = scanResultsPanel.isPlaceholderActive();

		boolean needsDetail = isSide && (scanResultsPanel.isDetailShowing()
				|| currentDeltaResult != null || placeholderActive);
		boolean hasExternalSplit = (externalDetailSplit != null);

		if (needsDetail && !hasExternalSplit) {
			rebuildScanLayout(pos);
		} else if (!needsDetail && hasExternalSplit) {
			rebuildScanLayout(pos);
		}
	}

	/**
	 * Build (or rebuild) the target button layout inside pnlTargetRow based on
	 * the current {@link #targetButtonsDock} position (LEFT, RIGHT, TOP, BOTTOM).
	 */
	private void buildTargetButtonLayout() {
		pnlTargetRow.removeAll();

		boolean horizontal = "TOP".equals(targetButtonsDock) || "BOTTOM".equals(targetButtonsDock);

		pnlSelector = new JPanel(new GridBagLayout());
		pnlSelector.setComponentPopupMenu(targetDockMenu);
		pnlSelector.setInheritsPopupMenu(true);
		if (targetDragAdapter != null) {
			pnlSelector.addMouseListener(targetDragAdapter);
			pnlSelector.addMouseMotionListener(targetDragAdapter);
		}

		// Dedicated grip handle for the target buttons panel
		JPanel targetGrip = new JPanel() {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				paintTargetGrip(g, this);
			}
		};
		targetGrip.setOpaque(false);
		targetGrip.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.MOVE_CURSOR));
		targetGrip.setPreferredSize(horizontal
				? new Dimension(16, 0) : new Dimension(0, 16));
		if (targetDragAdapter != null) {
			targetGrip.addMouseListener(targetDragAdapter);
			targetGrip.addMouseMotionListener(targetDragAdapter);
		}
		targetGrip.setComponentPopupMenu(targetDockMenu);

		GridBagConstraints gbs = new GridBagConstraints();
		gbs.fill = GridBagConstraints.NONE;

		if (horizontal) {
			// Horizontal: grip | ▼ | Save | Load | Clear — all in one row
			pnlSelector.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
			gbs.gridy = 0;

			// Grip handle
			gbs.gridx = 0;
			gbs.anchor = GridBagConstraints.WEST;
			gbs.fill = GridBagConstraints.VERTICAL;
			gbs.insets = new Insets(0, 0, 0, 2);
			pnlSelector.add(targetGrip, gbs);

			gbs.fill = GridBagConstraints.NONE;
			gbs.insets = new Insets(0, 4, 0, 4);

			gbs.gridx = 1;
			pnlSelector.add(btnTestServers, gbs);
			gbs.gridx = 2;
			pnlSelector.add(btnSaveTargets, gbs);
			gbs.gridx = 3;
			pnlSelector.add(btnLoadFile, gbs);
			gbs.gridx = 4;
			pnlSelector.add(btnScanClear, gbs);

			// Push buttons left
			gbs.gridx = 5;
			gbs.weightx = 1.0;
			pnlSelector.add(javax.swing.Box.createGlue(), gbs);
		} else {
			// Vertical: grip on top, then ▼ + Save on first row, Load below, Clear below
			pnlSelector.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));

			// Grip handle spanning full width
			gbs.gridx = 0; gbs.gridy = 0;
			gbs.gridwidth = 2;
			gbs.anchor = GridBagConstraints.NORTHWEST;
			gbs.fill = GridBagConstraints.HORIZONTAL;
			gbs.insets = new Insets(0, 0, 2, 0);
			pnlSelector.add(targetGrip, gbs);
			gbs.gridwidth = 1;
			gbs.fill = GridBagConstraints.NONE;

			gbs.insets = new Insets(2, 0, 2, 4);

			if ("LEFT".equals(targetButtonsDock)) {
				// LEFT: Save first, ▼ to the right of Save
				gbs.gridx = 0; gbs.gridy = 1;
				pnlSelector.add(btnSaveTargets, gbs);
				gbs.gridx = 1; gbs.gridy = 1;
				pnlSelector.add(btnTestServers, gbs);
			} else {
				// RIGHT (default): ▼ first, Save to the right
				gbs.gridx = 0; gbs.gridy = 1;
				pnlSelector.add(btnTestServers, gbs);
				gbs.gridx = 1; gbs.gridy = 1;
				pnlSelector.add(btnSaveTargets, gbs);
			}

			int btnCol = "LEFT".equals(targetButtonsDock) ? 0 : 1;
			gbs.gridx = btnCol; gbs.gridy = 2;
			pnlSelector.add(btnLoadFile, gbs);
			gbs.gridx = btnCol; gbs.gridy = 3;
			pnlSelector.add(btnScanClear, gbs);

			// Push content to top
			gbs.gridx = 0; gbs.gridy = 4;
			gbs.gridwidth = 2;
			gbs.weighty = 1.0;
			pnlSelector.add(javax.swing.Box.createGlue(), gbs);
		}

		// Assemble target row: text area + selector at the dock position
		if (horizontal) {
			pnlTargetRow.setLayout(new java.awt.BorderLayout());
			String constraint = "TOP".equals(targetButtonsDock)
					? java.awt.BorderLayout.NORTH : java.awt.BorderLayout.SOUTH;
			pnlTargetRow.add(pnlSelector, constraint);
			pnlTargetRow.add(spTargets, java.awt.BorderLayout.CENTER);
		} else {
			pnlTargetRow.setLayout(new GridBagLayout());
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.gridy = 0;
			gbc.fill = GridBagConstraints.BOTH;
			gbc.weighty = 1.0;

			if ("LEFT".equals(targetButtonsDock)) {
				gbc.gridx = 0; gbc.weightx = 0.0;
				pnlTargetRow.add(pnlSelector, gbc);
				gbc.gridx = 1; gbc.weightx = 1.0;
				pnlTargetRow.add(spTargets, gbc);
			} else {
				gbc.gridx = 0; gbc.weightx = 1.0;
				pnlTargetRow.add(spTargets, gbc);
				gbc.gridx = 1; gbc.weightx = 0.0;
				pnlTargetRow.add(pnlSelector, gbc);
			}
		}

		pnlTargetRow.revalidate();
		pnlTargetRow.repaint();
	}

	/**
	 * Dock the target buttons to a new position and persist the choice.
	 */
	private void dockTargetButtons(String position) {
		if (position.equals(targetButtonsDock)) return;
		targetButtonsDock = position;
		buildTargetButtonLayout();
		themePrefs.setDockTargetButtons(position);
		FontPreferences.save(themePrefs);
	}

	/**
	 * Paint subtle grip dots on the leading edge of the target button panel.
	 * Vertical dots when horizontal dock, horizontal dots when vertical dock.
	 */
	private void paintTargetGrip(Graphics g, JPanel panel) {
		java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
		g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
				java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
		Color fg = panel.getForeground();
		g2.setColor(new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 80));

		boolean horizontal = "TOP".equals(targetButtonsDock) || "BOTTOM".equals(targetButtonsDock);
		if (horizontal) {
			// Vertical grip dots on the left edge
			int x = 6;
			int yStart = 5;
			int yEnd = panel.getHeight() - 5;
			for (int y = yStart; y < yEnd; y += 3) {
				g2.fillRect(x, y, 2, 1);
				g2.fillRect(x + 4, y, 2, 1);
			}
		} else {
			// Horizontal grip dots on the top edge
			int y = 6;
			int xStart = 5;
			int xEnd = panel.getWidth() - 5;
			for (int x = xStart; x < xEnd; x += 3) {
				g2.fillRect(x, y, 1, 2);
				g2.fillRect(x, y + 4, 1, 2);
			}
		}
		g2.dispose();
	}

	/**
	 * Show translucent drop zone overlay on pnlTargetRow for drag-to-dock.
	 */
	private void showTargetDropOverlay() {
		if (pnlTargetRow == null) return;

		targetDropOverlay = new JPanel(null) {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				paintTargetDropZones(g, this);
			}
		};
		targetDropOverlay.setOpaque(false);

		javax.swing.JRootPane rootPane = javax.swing.SwingUtilities.getRootPane(pnlTargetRow);
		if (rootPane != null) {
			javax.swing.JLayeredPane layered = rootPane.getLayeredPane();
			java.awt.Point loc = javax.swing.SwingUtilities.convertPoint(
					pnlTargetRow, 0, 0, layered);
			targetDropOverlay.setBounds(loc.x, loc.y,
					pnlTargetRow.getWidth(), pnlTargetRow.getHeight());
			layered.add(targetDropOverlay, javax.swing.JLayeredPane.DRAG_LAYER);
			layered.repaint();
		}
	}

	/**
	 * Remove the drag-to-dock drop zone overlay.
	 */
	private void hideTargetDropOverlay() {
		if (targetDropOverlay != null) {
			java.awt.Container parent = targetDropOverlay.getParent();
			if (parent != null) {
				parent.remove(targetDropOverlay);
				parent.repaint();
			}
			targetDropOverlay = null;
		}
	}

	/**
	 * Paint the four edge drop zones on the overlay panel. Top/bottom strips
	 * span the full width (20% height each). Left/right strips occupy the
	 * middle 60% height. Center is a dead zone (no dock change).
	 */
	private void paintTargetDropZones(Graphics g, JPanel overlay) {
		int w = overlay.getWidth();
		int h = overlay.getHeight();
		int topH = h / 5;
		int botY = h - topH;
		int midH = h - 2 * topH;
		int sideW = w / 5;

		java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
		g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
				java.awt.RenderingHints.VALUE_ANTIALIAS_ON);

		Color active = new Color(33, 150, 243, 80);
		Color inactive = new Color(33, 150, 243, 30);

		// Top zone (full width, top 20%)
		g2.setColor("TOP".equals(targetDropZone) ? active : inactive);
		g2.fillRect(0, 0, w, topH);

		// Bottom zone (full width, bottom 20%)
		g2.setColor("BOTTOM".equals(targetDropZone) ? active : inactive);
		g2.fillRect(0, botY, w, topH);

		// Left zone (left 20% width, middle 60% height)
		g2.setColor("LEFT".equals(targetDropZone) ? active : inactive);
		g2.fillRect(0, topH, sideW, midH);

		// Right zone (right 20% width, middle 60% height)
		g2.setColor("RIGHT".equals(targetDropZone) ? active : inactive);
		g2.fillRect(w - sideW, topH, sideW, midH);

		// Zone labels
		g2.setColor(new Color(255, 255, 255, 160));
		g2.setFont(g2.getFont().deriveFont(12f));
		java.awt.FontMetrics fm = g2.getFontMetrics();

		String topLabel = "\u25B2 Top";
		g2.drawString(topLabel, (w - fm.stringWidth(topLabel)) / 2,
				topH / 2 + fm.getAscent() / 2);

		String botLabel = "\u25BC Bottom";
		g2.drawString(botLabel, (w - fm.stringWidth(botLabel)) / 2,
				botY + topH / 2 + fm.getAscent() / 2);

		String leftLabel = "\u25C0 Left";
		g2.drawString(leftLabel, (sideW - fm.stringWidth(leftLabel)) / 2,
				topH + midH / 2 + fm.getAscent() / 2);

		String rightLabel = "Right \u25B6";
		g2.drawString(rightLabel,
				w - sideW + (sideW - fm.stringWidth(rightLabel)) / 2,
				topH + midH / 2 + fm.getAscent() / 2);

		g2.dispose();
	}

	/**
	 * Determine which drop zone the cursor is over based on screen coordinates.
	 */
	private void updateTargetDropZone(java.awt.Point screenPoint) {
		if (pnlTargetRow == null) return;

		java.awt.Point local = new java.awt.Point(screenPoint);
		javax.swing.SwingUtilities.convertPointFromScreen(local, pnlTargetRow);

		int w = pnlTargetRow.getWidth();
		int h = pnlTargetRow.getHeight();
		int topH = h / 5;
		int botY = h - topH;
		int sideW = w / 5;

		String newZone = null;
		if (local.x >= 0 && local.x < w && local.y >= 0 && local.y < h) {
			if (local.y < topH) {
				newZone = "TOP";
			} else if (local.y >= botY) {
				newZone = "BOTTOM";
			} else if (local.x < sideW) {
				newZone = "LEFT";
			} else if (local.x >= w - sideW) {
				newZone = "RIGHT";
			}
			// else: center dead zone — newZone stays null
		}

		if ((newZone == null && targetDropZone != null)
				|| (newZone != null && !newZone.equals(targetDropZone))) {
			targetDropZone = newZone;
			if (targetDropOverlay != null) {
				targetDropOverlay.repaint();
			}
		}
	}

	// ---- Scan toolbar dock-to-position methods ----

	/**
	 * Move the scan toolbar to a new dock position (NORTH, SOUTH, EAST, WEST)
	 * and persist the choice.
	 */
	private void dockToolbar(String position) {
		if (position.equals(toolbarDock)) return;
		toolbarDock = position;

		// Remove toolbar, status panel, and any south wrapper
		removeToolbarAndStatus();

		boolean vertical = "EAST".equals(toolbarDock) || "WEST".equals(toolbarDock);
		scanToolbar.setOrientation(vertical ? JToolBar.VERTICAL : JToolBar.HORIZONTAL);

		// Update grip preferred size based on orientation
		java.awt.Component grip = scanToolbar.getComponent(0);
		grip.setPreferredSize(vertical ? new Dimension(0, 16) : new Dimension(16, 0));

		addToolbarToPanel(scanTabPanel);
		addStatusPanelToScanTab(scanTabPanel);
		scanTabPanel.revalidate();
		scanTabPanel.repaint();

		themePrefs.setDockToolbar(position);
		FontPreferences.save(themePrefs);
	}

	/**
	 * Remove toolbar, status panel, and any south wrapper from the scan tab.
	 */
	private void removeToolbarAndStatus() {
		// Walk up from toolbar to find the component directly in scanTabPanel
		removeAncestorFrom(scanToolbar, scanTabPanel);
		// Walk up from status panel (may share a wrapper with toolbar)
		removeAncestorFrom(scanStatusPanel, scanTabPanel);
	}

	/** Remove the nearest ancestor of {@code child} that is a direct child of {@code parent}. */
	private static void removeAncestorFrom(Component child, java.awt.Container parent) {
		Component c = child;
		while (c != null && c.getParent() != parent) {
			c = c.getParent();
		}
		if (c != null) {
			parent.remove(c);
		}
	}

	/**
	 * Add the toolbar to the scan tab panel at the current dock position.
	 * When docking SOUTH, wraps toolbar above the status panel in a composite.
	 */
	private void addToolbarToPanel(JPanel panel) {
		// Wrap toolbar so buttons are left/top-justified rather than
		// stretched across the full toolbar width by DefaultToolBarLayout.
		boolean vertical = "EAST".equals(toolbarDock) || "WEST".equals(toolbarDock);
		JPanel tbWrap = new JPanel(new java.awt.BorderLayout());
		tbWrap.add(scanToolbar, vertical
				? java.awt.BorderLayout.NORTH : java.awt.BorderLayout.WEST);

		if ("SOUTH".equals(toolbarDock)) {
			// Wrap toolbar + status in a single SOUTH panel
			JPanel southWrapper = new JPanel(new java.awt.BorderLayout());
			southWrapper.add(tbWrap, java.awt.BorderLayout.NORTH);
			southWrapper.add(scanStatusPanel, java.awt.BorderLayout.SOUTH);
			panel.add(southWrapper, java.awt.BorderLayout.SOUTH);
		} else {
			String constraint = switch (toolbarDock) {
				case "EAST" -> java.awt.BorderLayout.EAST;
				case "WEST" -> java.awt.BorderLayout.WEST;
				default -> java.awt.BorderLayout.NORTH;
			};
			panel.add(tbWrap, constraint);
		}
	}

	/**
	 * Add the status panel to the scan tab at SOUTH, unless the toolbar
	 * is already docked SOUTH (in which case it's already inside a wrapper).
	 */
	private void addStatusPanelToScanTab(JPanel panel) {
		if (!"SOUTH".equals(toolbarDock)) {
			panel.add(scanStatusPanel, java.awt.BorderLayout.SOUTH);
		}
	}

	private void showToolbarDropOverlay() {
		if (scanTabPanel == null) return;

		toolbarDropOverlay = new JPanel(null) {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				paintToolbarDropZones(g, this);
			}
		};
		toolbarDropOverlay.setOpaque(false);

		javax.swing.JRootPane rootPane = javax.swing.SwingUtilities.getRootPane(scanTabPanel);
		if (rootPane != null) {
			javax.swing.JLayeredPane layered = rootPane.getLayeredPane();
			java.awt.Point loc = javax.swing.SwingUtilities.convertPoint(
					scanTabPanel, 0, 0, layered);
			toolbarDropOverlay.setBounds(loc.x, loc.y,
					scanTabPanel.getWidth(), scanTabPanel.getHeight());
			layered.add(toolbarDropOverlay, javax.swing.JLayeredPane.DRAG_LAYER);
			layered.repaint();
		}
	}

	private void hideToolbarDropOverlay() {
		if (toolbarDropOverlay != null) {
			java.awt.Container parent = toolbarDropOverlay.getParent();
			if (parent != null) {
				parent.remove(toolbarDropOverlay);
				parent.repaint();
			}
			toolbarDropOverlay = null;
		}
	}

	/**
	 * Paint the four edge drop zones on the toolbar overlay. Same layout
	 * as the target buttons overlay (top/bottom strips span full width,
	 * left/right strips occupy the middle height).
	 */
	private void paintToolbarDropZones(Graphics g, JPanel overlay) {
		int w = overlay.getWidth();
		int h = overlay.getHeight();
		int topH = h / 5;
		int botY = h - topH;
		int midH = h - 2 * topH;
		int sideW = w / 5;

		java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
		g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
				java.awt.RenderingHints.VALUE_ANTIALIAS_ON);

		Color active = new Color(33, 150, 243, 80);
		Color inactive = new Color(33, 150, 243, 30);

		// Top zone (NORTH)
		g2.setColor("NORTH".equals(toolbarDropZone) ? active : inactive);
		g2.fillRect(0, 0, w, topH);

		// Bottom zone (SOUTH)
		g2.setColor("SOUTH".equals(toolbarDropZone) ? active : inactive);
		g2.fillRect(0, botY, w, topH);

		// Left zone (WEST)
		g2.setColor("WEST".equals(toolbarDropZone) ? active : inactive);
		g2.fillRect(0, topH, sideW, midH);

		// Right zone (EAST)
		g2.setColor("EAST".equals(toolbarDropZone) ? active : inactive);
		g2.fillRect(w - sideW, topH, sideW, midH);

		// Zone labels
		g2.setColor(new Color(255, 255, 255, 160));
		g2.setFont(g2.getFont().deriveFont(12f));
		java.awt.FontMetrics fm = g2.getFontMetrics();

		String topLabel = "\u25B2 Top";
		g2.drawString(topLabel, (w - fm.stringWidth(topLabel)) / 2,
				topH / 2 + fm.getAscent() / 2);

		String botLabel = "\u25BC Bottom";
		g2.drawString(botLabel, (w - fm.stringWidth(botLabel)) / 2,
				botY + topH / 2 + fm.getAscent() / 2);

		String leftLabel = "\u25C0 Left";
		g2.drawString(leftLabel, (sideW - fm.stringWidth(leftLabel)) / 2,
				topH + midH / 2 + fm.getAscent() / 2);

		String rightLabel = "Right \u25B6";
		g2.drawString(rightLabel,
				w - sideW + (sideW - fm.stringWidth(rightLabel)) / 2,
				topH + midH / 2 + fm.getAscent() / 2);

		g2.dispose();
	}

	private void updateToolbarDropZone(java.awt.Point screenPoint) {
		if (scanTabPanel == null) return;

		java.awt.Point local = new java.awt.Point(screenPoint);
		javax.swing.SwingUtilities.convertPointFromScreen(local, scanTabPanel);

		int w = scanTabPanel.getWidth();
		int h = scanTabPanel.getHeight();
		int topH = h / 5;
		int botY = h - topH;
		int sideW = w / 5;

		String newZone = null;
		if (local.x >= 0 && local.x < w && local.y >= 0 && local.y < h) {
			if (local.y < topH) {
				newZone = "NORTH";
			} else if (local.y >= botY) {
				newZone = "SOUTH";
			} else if (local.x < sideW) {
				newZone = "WEST";
			} else if (local.x >= w - sideW) {
				newZone = "EAST";
			}
		}

		if ((newZone == null && toolbarDropZone != null)
				|| (newZone != null && !newZone.equals(toolbarDropZone))) {
			toolbarDropZone = newZone;
			if (toolbarDropOverlay != null) {
				toolbarDropOverlay.repaint();
			}
		}
	}

	/** Paint grip dots on the toolbar's grip handle panel. */
	private void paintToolbarGrip(Graphics g, JPanel grip) {
		java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
		g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
				java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
		Color fg = grip.getForeground();
		if (fg == null) fg = Color.GRAY;
		g2.setColor(new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 80));

		boolean vertical = scanToolbar.getOrientation() == JToolBar.VERTICAL;
		if (vertical) {
			// Horizontal grip dots across the top
			int y = 4;
			int xStart = 5;
			int xEnd = grip.getWidth() - 5;
			for (int x = xStart; x < xEnd; x += 3) {
				g2.fillRect(x, y, 1, 2);
				g2.fillRect(x, y + 4, 1, 2);
			}
		} else {
			// Vertical grip dots along the left
			int x = 4;
			int yStart = 5;
			int yEnd = grip.getHeight() - 5;
			for (int y = yStart; y < yEnd; y += 3) {
				g2.fillRect(x, y, 2, 1);
				g2.fillRect(x + 4, y, 2, 1);
			}
		}
		g2.dispose();
	}

	/**
	 * Load targets from a text file into the target area.
	 */
	private void onLoadFile() {
		JFileChooser chooser = new JFileChooser(targetsDir);
		chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
				"Text files", "txt", "csv"));
		int result = chooser.showOpenDialog(this);
		if (result == JFileChooser.APPROVE_OPTION) {
			File selected = chooser.getSelectedFile();
			try {
				byte[] rawBytes = java.nio.file.Files.readAllBytes(selected.toPath());
				String sha = FontPreferences.sha256Hex(rawBytes);
				scanTargetProvenance = new SourceProvenance(
						selected.getName(), selected.getAbsolutePath(), sha);
			} catch (IOException ex) {
				JOptionPane.showMessageDialog(this,
						"Error reading file: " + ex.getMessage(),
						"Load Error", JOptionPane.ERROR_MESSAGE);
				return;
			}
			try (BufferedReader br = new BufferedReader(new FileReader(selected))) {
				StringBuilder sb = new StringBuilder();
				String line;
				while ((line = br.readLine()) != null) {
					String trimmed = line.trim();
					if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
						sb.append(trimmed).append("\n");
					}
				}
				txtTargets.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
				targetsPlaceholder = false;
				txtTargets.setText(sb.toString());
			} catch (IOException ex) {
				JOptionPane.showMessageDialog(this,
						"Error reading file: " + ex.getMessage(),
						"Load Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	/**
	 * Clear the targets text area and restore placeholder.
	 */
	private void onClearTargets() {
		txtTargets.setText(SCAN_PLACEHOLDER_TEXT);
		txtTargets.setForeground(Color.GRAY);
		targetsPlaceholder = true;
	}

	/**
	 * Save current targets to a text file in the targets directory.
	 */
	private void onSaveTargets() {
		if (targetsPlaceholder || txtTargets.getText().trim().isEmpty()) {
			return;
		}
		String date = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
		String prefix = "batch-scan-target-" + date;
		int n = nextFileIndex(targetsDir, prefix, ".txt");
		String defaultName = prefix + "-" + n + ".txt";

		JFileChooser chooser = new JFileChooser(targetsDir);
		chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
				"Text files", "txt"));
		chooser.setSelectedFile(new File(targetsDir, defaultName));
		int result = chooser.showSaveDialog(this);
		if (result == JFileChooser.APPROVE_OPTION) {
			File outFile = chooser.getSelectedFile();
			String path = outFile.getAbsolutePath();
			if (!path.toLowerCase().endsWith(".txt")) {
				outFile = new File(path + ".txt");
			}
			try (FileWriter fw = new FileWriter(outFile)) {
				fw.write(txtTargets.getText());
				setStatusTemporary(STATUS_HDR + "Targets saved: " + outFile.getName());
			} catch (IOException ex) {
				JOptionPane.showMessageDialog(this,
						"Error saving targets: " + ex.getMessage(),
						"Save Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	/**
	 * Set a temporary status message that resets to "Ready" after 5 seconds.
	 */
	private void setStatusTemporary(String message) {
		if (statusResetTimer != null) statusResetTimer.stop();
		txtScanProgress.setText(message);
		statusResetTimer = new Timer(5000, e -> {
			((Timer) e.getSource()).stop();
			txtScanProgress.setText(STATUS_HDR + "Ready");
		});
		statusResetTimer.setRepeats(false);
		statusResetTimer.start();
	}

	/**
	 * Auto-hide a text field when its text is empty, auto-show when non-empty.
	 * Triggers revalidation of the status panel so the layout compacts.
	 */
	private void addAutoHideListener(JTextField field) {
		field.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
			private void update() {
				boolean visible = field.getText() != null && !field.getText().isEmpty();
				if (field.isVisible() != visible) {
					field.setVisible(visible);
					scanStatusPanel.revalidate();
					scanStatusPanel.repaint();
				}
			}
			@Override public void insertUpdate(javax.swing.event.DocumentEvent e) { update(); }
			@Override public void removeUpdate(javax.swing.event.DocumentEvent e) { update(); }
			@Override public void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
		});
	}

	/**
	 * Open the test servers dialog for target selection.
	 */
	private void onTestServersPressed() {
		List<String> recentLabels = new ArrayList<>();
		for (String[] entry : scanTargetHistory) {
			recentLabels.add(entry[0]);
		}
		TestServersDialog dialog = new TestServersDialog(this, recentLabels, true);
		dialog.setVisible(true);

		// Append selected recent target groups
		for (String label : dialog.getSelectedRecentItems()) {
			for (String[] entry : scanTargetHistory) {
				if (entry[0].equals(label)) {
					appendTarget(entry[1]);
					break;
				}
			}
		}

		// Append selected test server URLs
		for (String url : dialog.getSelectedTestServerUrls()) {
			appendTarget(url);
		}
	}

	/**
	 * Append target text to the targets text area.
	 */
	private void appendTarget(String text) {
		if (targetsPlaceholder) {
			txtTargets.setText("");
			txtTargets.setForeground(
					javax.swing.UIManager.getColor("TextArea.foreground"));
			targetsPlaceholder = false;
		}
		String current = txtTargets.getText();
		if (!current.isEmpty() && !current.endsWith("\n")) {
			current += "\n";
		}
		txtTargets.setText(current + text);
	}

	/**
	 * Dispatches the Scan/Stop button click based on whether a scan is running.
	 */
	private void onScanButtonClicked() {
		if (currentScanTask != null && currentScanTask.isRunning()) {
			currentScanTask.cancel();
			btnScan.setEnabled(false);
			txtScanStatus.setText(STATUS_HDR + "Stopping scan...");
		} else {
			onScanPressed();
		}
	}

	/**
	 * Start a scan using the targets entered in the text area.
	 */
	private void onScanPressed() {
		if (targetsPlaceholder) {
			JOptionPane.showMessageDialog(this,
					"Enter at least one target.",
					"No Targets", JOptionPane.WARNING_MESSAGE);
			return;
		}
		String targetText = txtTargets.getText();
		if (targetText == null || targetText.isBlank()) {
			JOptionPane.showMessageDialog(this,
					"Enter at least one target.",
					"No Targets", JOptionPane.WARNING_MESSAGE);
			return;
		}

		FontPreferences scanPrefs = FontPreferences.load();
		TargetParser.setMaxCidrExpansion(scanPrefs.getMaxCidrExpansion());
		List<String> targetUrls = TargetParser.parse(targetText);
		if (targetUrls.isEmpty()) {
			JOptionPane.showMessageDialog(this,
					"No valid targets found.",
					"Invalid Targets", JOptionPane.WARNING_MESSAGE);
			return;
		}

		// Save target history before scanning
		String targetText0 = txtTargets.getText();
		int targetCount = TargetParser.parse(targetText0).size();
		String histLabel = (scanTargetProvenance != null)
				? scanTargetProvenance.getFileName()
				: "Manual (" + targetCount + " targets)";
		scanTargetHistory.removeIf(e -> e[1].equals(targetText0));
		scanTargetHistory.add(0, new String[] { histLabel, targetText0 });
		if (scanTargetHistory.size() > 5) {
			scanTargetHistory = new ArrayList<>(scanTargetHistory.subList(0, 5));
		}
		FontPreferences.saveScanTargetHistory(scanTargetHistory);

		// Switch Scan button to Stop; disable other controls during scan
		btnScan.setText("Stop");
		btnLoadFile.setEnabled(false);
		btnSave.setVisible(false);
		btnSaveScan.setVisible(false);
		btnLoadScan.setEnabled(false);
		btnClearScan.setVisible(false);
		btnTestServers.setEnabled(false);
		btnScanClear.setEnabled(false);
		btnSaveTargets.setEnabled(false);
		txtTargets.setEnabled(false);
		txtActiveScan.setText("Active Scan: In progress");
		txtScanStatus.setText(STATUS_HDR + "Starting scan...");
		txtScanProgress.setText("");

		// Clear previous results
		scanResultsPanel.clearResults();
		try {
			scanResultsDoc.remove(0, scanResultsDoc.getLength());
		} catch (BadLocationException ignored) {
		}

		// Create scan task with engine preferences
		ScanTask scanTask = new ScanTask(targetUrls);

		// The scan engine always runs all sections (doInBackground builds the
		// full tree). Section flags passed here are display metadata only.
		CIPHER_NAME_CONVENTION convention = CIPHER_NAME_CONVENTION.IANA;
		try {
			convention = CIPHER_NAME_CONVENTION.valueOf(themePrefs.getCipherConvention());
		} catch (IllegalArgumentException e) {
			logger.warn("Unknown cipher convention, defaulting to IANA");
		}

		scanTask.applyPreferences(
				themePrefs.isSectionRiskAssessment(), themePrefs.isSectionRuntimeEnvironment(),
				themePrefs.isSectionHost(), themePrefs.isSectionHttpResponse(),
				themePrefs.isSectionConnection(), themePrefs.isSectionCipherSuites(),
				themePrefs.isSectionCertChain(),
				themePrefs.isSectionSecurityHeaders(),
				themePrefs.isSectionRevocation(), themePrefs.isSectionTlsFingerprint(),
				themePrefs.isProtocolSslv3(), themePrefs.isProtocolTls10(),
				themePrefs.isProtocolTls11(), themePrefs.isProtocolTls12(),
				themePrefs.isProtocolTls13(),
				convention, themePrefs.getRiskScale());

		scanTask.setWorkerThreadCount(themePrefs.getScanWorkerThreads());
		scanTask.setThrottleDelayMs(themePrefs.getScanThrottleDelayMs());

		// Custom cipher map
		if (themePrefs.isCustomCipherMapEnabled()) {
			String yaml = FontPreferences.loadCustomCipherMapYaml();
			if (yaml != null && !yaml.isBlank()) {
				try {
					DeepVioletFactory.loadCipherMap(new java.io.ByteArrayInputStream(
							yaml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
				} catch (Exception ex) {
					logger.warn("Failed to load custom cipher map for scan", ex);
				}
			}
		} else {
			try {
				DeepVioletFactory.resetCipherMap();
			} catch (Exception ex) {
				logger.warn("Failed to reset cipher map for scan", ex);
			}
		}

		// User risk rules
		if (themePrefs.isUserRiskRulesEnabled()) {
			String yaml = FontPreferences.loadUserRiskRulesYaml();
			if (yaml != null && !yaml.isBlank()) {
				scanTask.setUserRiskRulesYaml(yaml);
			}
		}

		// AI evaluation — generated at scan time when enabled and configured
		if (themePrefs.isSectionAiEvaluation() && themePrefs.isReportReady()) {
			scanTask.setAiConfig(
					themePrefs.getAiApiKey(), themePrefs.getAiProvider(),
					themePrefs.getAiModel(), themePrefs.getAiMaxTokens(),
					themePrefs.getAiTemperature(), themePrefs.getAiSystemPrompt(),
					themePrefs.getAiEndpointUrl());
		}

		scanTask.setCompletionCallback(() ->
				javax.swing.SwingUtilities.invokeLater(() -> onScanComplete()));

		currentScanTask = scanTask;
		scanStartTime = System.currentTimeMillis();
		scanTask.start();

		// Poll scan status for the worker status line
		if (scanStatusTimer != null) scanStatusTimer.stop();
		scanStatusTimer = new Timer(100, evt -> {
			if (currentScanTask == null || !currentScanTask.isRunning()) return;
			com.mps.deepviolettools.job.ScanTask.WorkerStatus[] statuses =
					currentScanTask.getWorkerStatuses();
			if (statuses == null) return;

			StringBuilder sb = new StringBuilder();
			for (int wi = 0; wi < statuses.length; wi++) {
				if (wi > 0) sb.append("  |  ");
				com.mps.deepviolettools.job.ScanTask.WorkerStatus ws = statuses[wi];
				sb.append("w").append(ws.getWorkerId()).append(":");
				if (ws.isActive()) {
					sb.append("t").append(ws.getTargetIndex()).append("->");
					UIBackgroundScanTask subtask = ws.getCurrentSubtask();
					if (subtask != null) {
						String msg = subtask.getStatusBarMessage();
						sb.append(msg != null ? msg : "Initializing");
					} else {
						sb.append("Initializing");
					}
				} else {
					sb.append(ws.getPhase());
				}
			}
			String statusMsg = sb.toString();

			// Truncate with "..." if too long for the status bar
			java.awt.FontMetrics fm = txtScanStatus.getFontMetrics(txtScanStatus.getFont());
			int availableWidth = txtScanStatus.getWidth() - txtScanStatus.getInsets().left - txtScanStatus.getInsets().right;
			if (availableWidth > 0 && fm.stringWidth(statusMsg) > availableWidth) {
				while (statusMsg.length() > 4 && fm.stringWidth(statusMsg + "...") > availableWidth) {
					statusMsg = statusMsg.substring(0, statusMsg.length() - 1);
				}
				statusMsg = statusMsg + "...";
			}
			txtScanStatus.setText(statusMsg);

			// Line 2: group progress (W=working, f=finished, p=partial, n=not started)
			int totalTargets = currentScanTask.getTargetCount();
			AtomicIntegerArray targetStates = currentScanTask.getTargetStates();
			if (targetStates != null && totalTargets > 0) {
				int nGroups = Math.min(20, totalTargets);
				boolean[] hasWorking = new boolean[nGroups];
				boolean[] hasNotStarted = new boolean[nGroups];
				boolean[] hasFinished = new boolean[nGroups];
				for (int t = 0; t < totalTargets; t++) {
					int g = HeatMapData.assignBlock(t, totalTargets, nGroups);
					int state = targetStates.get(t);
					if (state == ScanTask.TARGET_WORKING) hasWorking[g] = true;
					else if (state == ScanTask.TARGET_FINISHED) hasFinished[g] = true;
					else hasNotStarted[g] = true;
				}
				StringBuilder progress = new StringBuilder();
				for (int g = 0; g < nGroups; g++) {
					if (g > 0) progress.append("   ");
					char ch;
					if (hasWorking[g]) ch = 'w';
					else if (hasNotStarted[g] && hasFinished[g]) ch = 'p';
					else if (hasFinished[g]) ch = 'f';
					else ch = 'n';
					progress.append(ch).append('[').append(g + 1).append(']');
				}
				String progressMsg = progress.toString();
				java.awt.FontMetrics fm2 = txtScanProgress.getFontMetrics(txtScanProgress.getFont());
				int availWidth2 = txtScanProgress.getWidth() - txtScanProgress.getInsets().left - txtScanProgress.getInsets().right;
				if (availWidth2 > 0 && fm2.stringWidth(progressMsg) > availWidth2) {
					while (progressMsg.length() > 4 && fm2.stringWidth(progressMsg + "...") > availWidth2) {
						progressMsg = progressMsg.substring(0, progressMsg.length() - 1);
					}
					progressMsg = progressMsg + "...";
				}
				txtScanProgress.setText(progressMsg);
			}
		});
		scanStatusTimer.start();
	}

	/**
	 * Called on the EDT when scan completes. Renders results as styled text.
	 */
	private void onScanComplete() {
		ScanResult result = currentScanTask.getResult();
		if (scanTargetProvenance != null) {
			result.setTargetSource(scanTargetProvenance);
			scanTargetProvenance = null;
		}
		currentScanResult = result;

		// Update active scan indicator
		String datetime = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());
		txtActiveScan.setText("Active Scan: Completed \u2014 " + result.getTotalTargets()
				+ " targets \u2014 " + datetime);

		// Render graphical results panel
		scanResultsPanel.setResults(result);

		// Render results into off-screen styled text pane (for export & AI)
		renderScanResults(result);

		// Stop status polling; show final worker statuses briefly before completion message
		if (scanStatusTimer != null) scanStatusTimer.stop();
		String completionMsg = STATUS_HDR + "Scan complete, " + (System.currentTimeMillis() - scanStartTime) + "(ms)";
		Timer delayTimer = new Timer(3000, e -> {
			((Timer) e.getSource()).stop();
			txtScanStatus.setText("");
			setStatusTemporary(completionMsg);
		});
		delayTimer.setRepeats(false);
		delayTimer.start();

		// Restore Scan button and re-enable controls
		btnScan.setText("Scan");
		btnScan.setEnabled(true);
		btnLoadFile.setEnabled(true);
		btnTestServers.setEnabled(true);
		btnScanClear.setEnabled(true);
		btnSaveTargets.setEnabled(true);
		btnLoadScan.setEnabled(true);
		txtTargets.setEnabled(true);
		updateSaveButtons();
		btnClearScan.setVisible(scanResultsPanel.hasResults());

		// Scan data now available; re-evaluate AI tab state.
		// For multi-target scans, AI tab stays disabled until a host card is clicked.
		// For single-target scans, enable AI immediately with a ready message.
		if (result.getTotalTargets() == 1 && aiTerminal != null) {
			aiTerminal.clearSelection();
			aiTerminal.clear();
			aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
			aiTerminal.write(fmtSystem("Ready for questions about scan on " + datetime + "\n"));
		}
		updateAiTabState();
	}

	/**
	 * Render scan results into the results StyledDocument as
	 * text-based heat maps — one per enabled section.
	 */
	private void renderScanResults(ScanResult result) {
		// Ensure we're showing the scan panel, not delta
		if (cardLayoutSwitcher != null) {
			cardLayoutSwitcher.show(cardLayoutContainer, "SCAN");
		}
		try {
			scanResultsDoc.remove(0, scanResultsDoc.getLength());
		} catch (BadLocationException ignored) {
		}

		StyledDocument savedDoc = doc;
		doc = scanResultsDoc;
		try {

		Font font = themePrefs.getScanFont();
		Color noticeColor = themePrefs.getScanNotice();
		Color contentColor = themePrefs.getScanContent();
		Color headingColor = themePrefs.getScanHeading();
		Color warningColor = themePrefs.getScanWarning();
		int nBlocks = 20;

		// Banner + summary header
		String banner = ReportExporter.buildBannerText("DeepViolet Scan Report");
		for (String line : banner.split("\n", -1)) {
			appendStyled(line + "\n", font, noticeColor, true);
		}
		appendStyled("Targets: " + result.getTotalTargets()
				+ "  Success: " + result.getSuccessCount()
				+ "  Errors: " + result.getErrorCount() + "\n\n",
				font, contentColor, false);

		// Host index
		String hostIndexBody = ReportExporter.buildHostIndexBody(result, nBlocks);
		if (!hostIndexBody.isEmpty()) {
			appendStyled("[Host Index]\n", font, headingColor, true);
			appendStyled(hostIndexBody + "\n", font, contentColor, false);
		}

		// Render heat map sections based on scan section preferences
		if (themePrefs.isScanSectionRiskAssessment()) {
			renderHeatMapSection("TLS Risk Assessment", result.toRiskHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}
		if (themePrefs.isScanSectionSecurityHeaders()) {
			renderHeatMapSection("Security Headers Analysis", result.toSecurityHeadersHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}
		if (themePrefs.isScanSectionHttpResponse()) {
			renderHeatMapSection("HTTP Response Headers", result.toHttpResponseHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}
		if (themePrefs.isScanSectionConnection()) {
			renderHeatMapSection("Connection Characteristics", result.toConnectionHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}
		if (themePrefs.isScanSectionCipherSuites()) {
			renderHeatMapSection("Cipher Suites", result.toCipherHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}
		if (themePrefs.isScanSectionRevocation()) {
			renderHeatMapSection("Revocation Status", result.toRevocationHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}
		if (themePrefs.isScanSectionTlsFingerprint()) {
			renderHeatMapSection("TLS Fingerprint", result.toFingerprintHeatMap(nBlocks), font, nBlocks, headingColor, contentColor);
		}

		// Error summary
		boolean hasErrors = false;
		for (ScanResult.HostResult hr : result.getResults()) {
			if (!hr.isSuccess()) {
				if (!hasErrors) {
					appendStyled("\n[Error Summary]\n", font, headingColor, true);
					hasErrors = true;
				}
				appendStyled("  " + hr.getTargetUrl() + ": " + hr.getErrorMessage() + "\n",
						font, warningColor, false);
			}
		}

		} finally {
			doc = savedDoc;
		}

		// Scroll to top
		tpScanResults.setCaretPosition(0);
	}

	/**
	 * Render a single heat map section into the current StyledDocument with
	 * percentage-based display (N%, N%E, N%I, N%EI). Displays column headers,
	 * row labels, and a legend line.
	 */
	private void renderHeatMapSection(String title, HeatMapData heatMap, Font font, int nBlocks,
			Color headingColor, Color contentColor) {
		appendStyled("\n[" + title + "]\n", font, headingColor, true);

		if (heatMap == null || heatMap.getRows().isEmpty()) {
			appendStyled("  (no data)\n", font, contentColor, false);
			return;
		}

		// Fixed label column width so all sections align
		int maxLabelLen = 50;
		int colWidth = 7;

		// Column numbers header row
		StringBuilder colHeader = new StringBuilder();
		colHeader.append("  ");
		for (int pad = 0; pad < maxLabelLen; pad++) colHeader.append(' ');
		colHeader.append("  ");
		for (int c = 1; c <= nBlocks; c++) {
			colHeader.append(String.format("%" + colWidth + "d", c));
		}
		colHeader.append('\n');
		appendStyled(colHeader.toString(), font, contentColor, false);

		// Precompute host-start columns for '.' boundary logic
		int totalHosts = heatMap.getTotalHosts();
		java.util.Set<Integer> hostStartCols = new java.util.HashSet<>();
		if (totalHosts > 0 && totalHosts < nBlocks) {
			for (int h = 0; h < totalHosts; h++) {
				hostStartCols.add(h * nBlocks / totalHosts);
			}
		}

		HeatMapData.MapType mapType = heatMap.getMapType();

		// Rows
		for (HeatMapData.HeatMapRow row : heatMap.getRows()) {
			// Row label
			String label = row.getDescription() != null ? row.getDescription() : row.getId();
			if (row.getQualifier() != null) {
				label = label + " (" + row.getQualifier() + ")";
			}
			if (label.length() > 50) label = label.substring(0, 47) + "...";
			StringBuilder rowPrefix = new StringBuilder("  ");
			rowPrefix.append(label);
			for (int pad = label.length(); pad < maxLabelLen; pad++) rowPrefix.append(' ');
			rowPrefix.append("  ");
			appendStyled(rowPrefix.toString(), font, contentColor, false);

			// Cells — percentage display; use '.' for repeated values
			HeatMapData.HeatMapCell[] cells = row.getCells();
			String prevDisplay = null;
			for (int col = 0; col < nBlocks; col++) {
				boolean isErrorCol = heatMap.hasErrorColumn(col);
				String display = HeatMapData.cellPercentageText(cells[col], mapType, isErrorCol);
				boolean isHostBoundary = col > 0 && hostStartCols.contains(col);

				// Parse percentage for coloring
				int pct = 0;
				try {
					pct = Integer.parseInt(display.replaceAll("[^0-9]", ""));
				} catch (NumberFormatException ignored) {
				}
				boolean hasInconclusive = display.contains("I");
				Color pctColor = HeatMapData.percentageColor(pct, hasInconclusive, mapType);

				if (col > 0 && display.equals(prevDisplay) && !isHostBoundary) {
					// Pad to colWidth with dots
					String dotDisplay = String.format("%" + colWidth + "s", ".");
					appendStyled(dotDisplay, font, pctColor, false);
				} else {
					appendStyled(String.format("%" + colWidth + "s", display), font, pctColor, false);
				}
				prevDisplay = display;
			}
			appendStyled("\n", font, contentColor, false);
		}

		// Legend
		String legend = HeatMapData.legendText(mapType, totalHosts, nBlocks,
				heatMap.getHostsPerBlock(), heatMap.getBlocksPerHost());
		appendStyled("\n" + legend + "\n", font, contentColor, false);
	}

	/**
	 * Render scan result tree nodes into the current StyledDocument
	 * without clearing it first.
	 */
	private void renderTreeNodes(ScanNode treeRoot) {
		Font font = themePrefs.getFont();
		boolean wrap = themePrefs.isHardwrapEnabled();
		int wrapWidth = themePrefs.getHardwrapWidth();
		java.util.Set<String> visible = buildVisibleSections();

		// Track whether we are inside a hidden section so its children
		// are also skipped during the pre-order walk.
		final boolean[] skipping = {false};
		treeRoot.walkVisible(node -> {
			if (node.getType() == ScanNode.NodeType.SECTION) {
				skipping[0] = visible != null && !visible.contains(node.getKey());
				if (skipping[0]) return;
			}
			if (skipping[0]) return;

			String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
			switch (node.getType()) {
				case NOTICE:
					String noticeText = node.getKey();
					if (noticeText.contains("Server Target ")) {
						int idx = noticeText.indexOf("Server Target ");
						String prefix = noticeText.substring(0, idx + "Server Target ".length());
						String url = noticeText.substring(idx + "Server Target ".length());
						appendStyled(prefix, font, themePrefs.getNotice(), true);
						appendStyled(url + "\n", font, themePrefs.getHighlight(), true);
					} else {
						appendStyled(noticeText + "\n", font, themePrefs.getNotice(), true);
					}
					break;
				case SECTION:
					appendStyled("\n", font, themePrefs.getDefaultText(), false);
					appendStyled("[" + node.getKey() + "]\n", font, themePrefs.getHeading(), true);
					break;
				case SUBSECTION:
					Color subColor = node.getSeverity() != null
							? themePrefs.getColorForSeverity(node.getSeverity())
							: themePrefs.getSubsection();
					appendWrappedSingle(indent + node.getKey() + ":", indent + "   ",
							wrap, wrapWidth, font, subColor, true);
					break;
				case KEY_VALUE:
					String kvLine = indent + node.getKey() + "=" + node.getValue();
					if (wrap && kvLine.length() > wrapWidth) {
						String prefix = indent + node.getKey() + "=";
						String contIndent = indent + "   ";
						appendWrappedKeyValue(prefix, node.getValue(), contIndent,
								wrapWidth, font);
					} else {
						appendStyled(indent + node.getKey(), font, themePrefs.getKey(), false);
						appendStyled("=", font, themePrefs.getContent(), false);
						appendStyled(node.getValue() + "\n", font, themePrefs.getValue(), false);
					}
					break;
				case WARNING:
					Color warnColor = node.getSeverity() != null
							? themePrefs.getColorForSeverity(node.getSeverity())
							: themePrefs.getWarning();
					appendWrappedSingle(indent + node.getKey(), indent + "   ",
							wrap, wrapWidth, font, warnColor, true);
					break;
				case CONTENT:
					String contentText = indent + node.getKey();
					if (containsBarChars(contentText)) {
						appendBarLine(contentText, font);
					} else {
						appendWrappedSingle(contentText, indent + "   ",
								wrap, wrapWidth, font, themePrefs.getContent(), false);
					}
					break;
				case BLANK:
					appendStyled("\n", font, themePrefs.getDefaultText(), false);
					break;
				default:
					break;
			}
		});

		// If AI Evaluation is enabled in settings but the tree has no AI section
		// (e.g. loaded scan that was run without AI), show a placeholder message.
		if (themePrefs.isSectionAiEvaluation()
				&& (visible == null || visible.contains("AI Evaluation"))
				&& !treeRoot.hasSection("AI Evaluation")) {
			appendStyled("\n", font, themePrefs.getDefaultText(), false);
			appendStyled("[AI Evaluation]\n", font, themePrefs.getHeading(), true);
			appendStyled("   AI evaluation is only generated at scan time. "
					+ "Run a new scan with AI evaluation enabled to generate this section.\n",
					font, themePrefs.getContent(), false);
		}
	}

	/**
	 * Build the set of section names that should be visible based on the
	 * current section preferences. Returns null if all sections are enabled.
	 */
	private java.util.Set<String> buildVisibleSections() {
		// Normal mode: only show risk assessment regardless of stored prefs
		if (!themePrefs.isWorkbenchMode()) {
			java.util.Set<String> visible = new java.util.HashSet<>();
			visible.add("TLS Risk Assessment");
			return visible;
		}
		// Workbench mode: if all sections are enabled, return null (no filtering)
		if (themePrefs.isSectionRiskAssessment()
				&& themePrefs.isSectionRuntimeEnvironment()
				&& themePrefs.isSectionHost()
				&& themePrefs.isSectionHttpResponse()
				&& themePrefs.isSectionSecurityHeaders()
				&& themePrefs.isSectionConnection()
				&& themePrefs.isSectionCipherSuites()
				&& themePrefs.isSectionCertChain()
				&& themePrefs.isSectionRevocation()
				&& themePrefs.isSectionTlsFingerprint()) {
			return null;
		}
		java.util.Set<String> visible = new java.util.HashSet<>();
		if (themePrefs.isSectionRiskAssessment()) visible.add("TLS Risk Assessment");
		if (themePrefs.isSectionRuntimeEnvironment()) visible.add("Runtime environment");
		if (themePrefs.isSectionHost()) visible.add("Host information");
		if (themePrefs.isSectionHttpResponse()) visible.add("HTTP(S) response headers");
		if (themePrefs.isSectionSecurityHeaders()) visible.add("Security headers analysis");
		if (themePrefs.isSectionConnection()) visible.add("Connection characteristics");
		if (themePrefs.isSectionCipherSuites()) visible.add("Server cipher suites");
		if (themePrefs.isSectionCertChain()) {
			visible.add("Server certificate chain");
			visible.add("Chain details");
		}
		if (themePrefs.isSectionRevocation()) visible.add("Certificate revocation status");
		if (themePrefs.isSectionTlsFingerprint()) visible.add("TLS server fingerprint");
		if (themePrefs.isSectionAiEvaluation()) visible.add("AI Evaluation");
		return visible;
	}

	/**
	 * Render a host's scan tree into a target StyledDocument. Used as a callback
	 * by {@link ScanResultsPanel} to show host detail in the drill-down pane.
	 */
	private void renderHostDetail(ScanNode treeRoot, StyledDocument targetDoc) {
		StyledDocument savedDoc = doc;
		doc = targetDoc;
		try {
			renderTreeNodes(treeRoot);
		} finally {
			doc = savedDoc;
		}
	}

	/**
	 * Update Save Scan, Load Scan, and Save Report button visibility/text
	 * based on the current scan results panel state.
	 */
	private void updateSaveButtons() {
		boolean hasResults = scanResultsPanel.hasResults();
		boolean hasDelta = currentDeltaResult != null;
		btnSaveScan.setVisible(hasResults);
		btnClearScan.setVisible(hasResults || hasDelta);
		if (hasDelta) {
			btnSave.setVisible(true);
			btnSave.setText("Save Report");
		} else if (!hasResults) {
			btnSave.setVisible(false);
		} else if (scanResultsPanel.isDetailShowing()) {
			btnSave.setVisible(true);
			btnSave.setText("Save Detail");
		} else {
			btnSave.setVisible(true);
			btnSave.setText("Save Cards");
		}
	}

	/**
	 * Save the current scan result as an encrypted .dvscan file.
	 */
	private void onSaveScan() {
		if (currentScanResult == null) return;

		String dateStr = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
		String prefix = "batch-scan-" + dateStr;
		int idx = nextFileIndex(scansDir, prefix, ".dvscan");
		String defaultName = prefix + "-" + idx + ".dvscan";

		JFileChooser chooser = new JFileChooser(scansDir);
		chooser.setSelectedFile(new File(scansDir, defaultName));
		chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
				"DeepViolet Scan Files (*.dvscan)", "dvscan"));
		int ret = chooser.showSaveDialog(this);
		if (ret != JFileChooser.APPROVE_OPTION) return;

		File file = chooser.getSelectedFile().getAbsoluteFile();
		String path = file.getAbsolutePath();
		if (!path.endsWith(".dvscan")) {
			path = path + ".dvscan";
			file = new File(path);
		}

		try {
			SourceProvenance scanProv = ReportExporter.saveScanFile(file, currentScanResult);
			currentScanResult.setScanSource(scanProv);
			txtActiveScan.setText("Active Scan: " + file.getAbsolutePath());
			setStatusTemporary(STATUS_HDR + "Scan saved: " + file.getName());
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					"Error saving scan: " + ex.getMessage(),
					"Save Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Load a previously saved scan file and display results.
	 * Accepts both encrypted .dvscan files and legacy .dvscan.json files.
	 */
	private void onLoadScan() {
		JFileChooser chooser = new JFileChooser(scansDir);
		chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
				"DeepViolet Scan Files (*.dvscan, *.dvscan.json)", "dvscan", "json"));
		int ret = chooser.showOpenDialog(this);
		if (ret != JFileChooser.APPROVE_OPTION) return;

		File file = chooser.getSelectedFile();
		try {
			ScanResult result;
			if (file.getName().endsWith(".dvscan.json")) {
				result = ReportExporter.loadScanFromJson(file);
			} else {
				result = ReportExporter.loadScanFile(file);
			}
			currentScanResult = result;
			txtActiveScan.setText("Active Scan: " + file.getAbsolutePath());
			scanResultsPanel.setResults(result);
			renderScanResults(result);
			updateSaveButtons();
			setStatusTemporary(STATUS_HDR + "Loaded: " + file.getName());
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					"Error loading scan: " + ex.getMessage(),
					"Load Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Clear all scan cards and host details, resetting to the empty state.
	 */
	private void onClearScan() {
		currentScanResult = null;
		currentDeltaResult = null;
		scanResultsPanel.clearResults();
		deltaResultsPanel.clearResults();
		cardLayoutSwitcher.show(cardLayoutContainer, "SCAN");
		try {
			scanResultsDoc.remove(0, scanResultsDoc.getLength());
		} catch (BadLocationException ignored) {
		}
		txtActiveScan.setText("Active Scan: none");
		updateSaveButtons();
		setStatusTemporary(STATUS_HDR + "Scan cleared");
	}

	/**
	 * Check whether the current scan result has rule context data
	 * available for at least one host (enabling Run Report).
	 */
	/**
	 * Show delta scan dialog, compare two .dvscan files, and render the
	 * delta report into the scan results pane.
	 */
	private void onDeltaScan() {
		File scanDir = new File(FontPreferences.getHomeDir(),
				"ui" + File.separator + "batchscans");
		if (!scanDir.isDirectory()) scanDir = scansDir;

		DeltaScanDialog dlg = new DeltaScanDialog(this, scanDir);
		dlg.setVisible(true);
		File[] files = dlg.getSelectedFiles();
		if (files == null) return;

		try {
			ScanResult base = ReportExporter.loadScanFile(files[0]);
			ScanResult target = ReportExporter.loadScanFile(files[1]);

			DeltaScanResult result = DeltaScanner.compare(
					base, target, files[0], files[1]);

			currentDeltaResult = result;
			currentScanResult = null;
			renderDeltaResults(result);
			updateSaveButtons();
			setStatusTemporary(STATUS_HDR + "Delta: " + result.getChangedCount()
					+ " changed, " + result.getAddedCount() + " added, "
					+ result.getRemovedCount() + " removed");
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					"Error comparing scans: " + ex.getMessage(),
					"Delta Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Render delta scan results using the card-based DeltaResultsPanel.
	 * Switches the CardLayout to show the delta view and populates the
	 * off-screen doc for AI context.
	 */
	private void renderDeltaResults(DeltaScanResult result) {
		// Switch CardLayout to show delta panel
		cardLayoutSwitcher.show(cardLayoutContainer, "DELTA");
		deltaResultsPanel.setResults(result);

		// Populate the off-screen doc for text export / AI context
		try {
			scanResultsDoc.remove(0, scanResultsDoc.getLength());
		} catch (BadLocationException ignored) {
		}

		String fullText = ReportExporter.deltaToPlainText(result);
		Font font = themePrefs.getScanFont();
		Color contentColor = themePrefs.getScanContent();
		StyledDocument savedDoc = doc;
		doc = scanResultsDoc;
		try {
			appendStyled(fullText, font, contentColor, false);
		} finally {
			doc = savedDoc;
		}

		// Rebuild the layout to use the delta detail pane
		DockPosition pos = dockableResultsPanel.getDockPosition();
		rebuildScanLayout(pos);
	}

	/**
	 * Save scan results to a file using the same 5-format dialog.
	 * When detail view is active, exports only the selected host's
	 * scan report.
	 */
	private void onSavePressed() {
		// Delta mode — save delta report
		if (currentDeltaResult != null) {
			onSaveDeltaReport();
			return;
		}

		if (currentScanResult == null) return;

		// Check if we're in detail view — save single host only
		ScanResult.HostResult detailHost = scanResultsPanel.getSelectedHostResult();
		boolean isDetailSave = scanResultsPanel.isDetailShowing() && detailHost != null;

		if (isDetailSave && detailHost.getScanTree() != null) {
			onSaveHostDetail(detailHost);
			return;
		}

		// Cards-only view — save card summary
		onSaveCards();
	}

	/**
	 * Save the current delta scan report using the standard format chooser.
	 */
	private void onSaveDeltaReport() {
		if (currentDeltaResult == null) return;

		String dateStr = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

		JPanel formatPanel = new JPanel();
		formatPanel.setLayout(new BoxLayout(formatPanel, BoxLayout.Y_AXIS));
		formatPanel.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createEtchedBorder(), "Output Format",
				TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

		String lastFormat = FontPreferences.loadLastSaveFormat();
		ButtonGroup formatGroup = new ButtonGroup();
		JRadioButton rbAscii = new JRadioButton("ASCII Text (.txt)", "txt".equals(lastFormat));
		JRadioButton rbHtml = new JRadioButton("HTML (.html)", "html".equals(lastFormat));
		JRadioButton rbPdf = new JRadioButton("PDF (.pdf)", "pdf".equals(lastFormat));
		JRadioButton rbJson = new JRadioButton("JSON (.json)", "json".equals(lastFormat));

		formatGroup.add(rbAscii);
		formatGroup.add(rbHtml);
		formatGroup.add(rbPdf);
		formatGroup.add(rbJson);

		formatPanel.add(rbAscii);
		formatPanel.add(rbHtml);
		formatPanel.add(rbPdf);
		formatPanel.add(rbJson);

		JFileChooser chooser = new JFileChooser();
		chooser.setAccessory(formatPanel);

		String defaultExt;
		if (rbHtml.isSelected()) defaultExt = ".html";
		else if (rbPdf.isSelected()) defaultExt = ".pdf";
		else if (rbJson.isSelected()) defaultExt = ".json";
		else defaultExt = ".txt";

		String lastFolder = FontPreferences.loadLastSaveFolder();
		String saveDir = (lastFolder != null && new File(lastFolder).isDirectory())
				? lastFolder : reportsDir.getAbsolutePath();

		String prefix = "delta-report-" + dateStr;
		int idx = nextFileIndex(new File(saveDir), prefix, defaultExt);
		String baseFilename = prefix + "-" + idx;

		chooser.setCurrentDirectory(new File(saveDir));
		chooser.setSelectedFile(new File(saveDir, baseFilename + defaultExt));

		ActionListener formatChangeListener = e -> {
			File currentFile = chooser.getSelectedFile();
			if (currentFile != null) {
				String path = currentFile.getAbsolutePath();
				int lastDot = path.lastIndexOf('.');
				if (lastDot > 0) path = path.substring(0, lastDot);
				String newExt;
				if (rbHtml.isSelected()) newExt = ".html";
				else if (rbPdf.isSelected()) newExt = ".pdf";
				else if (rbJson.isSelected()) newExt = ".json";
				else newExt = ".txt";
				chooser.setSelectedFile(new File(path + newExt));
			}
		};
		rbAscii.addActionListener(formatChangeListener);
		rbHtml.addActionListener(formatChangeListener);
		rbPdf.addActionListener(formatChangeListener);
		rbJson.addActionListener(formatChangeListener);

		int returnVal = chooser.showSaveDialog(this);
		if (returnVal != JFileChooser.APPROVE_OPTION) return;

		File selectedfile = chooser.getSelectedFile().getAbsoluteFile();
		String ext;
		String formatKey;
		if (rbHtml.isSelected()) { ext = ".html"; formatKey = "html"; }
		else if (rbPdf.isSelected()) { ext = ".pdf"; formatKey = "pdf"; }
		else if (rbJson.isSelected()) { ext = ".json"; formatKey = "json"; }
		else { ext = ".txt"; formatKey = "txt"; }

		String filePath = selectedfile.getAbsolutePath();
		if (!filePath.toLowerCase().endsWith(ext)) {
			selectedfile = new File(filePath + ext);
		}

		try {
			switch (formatKey) {
				case "html":
					ReportExporter.saveDeltaAsHtml(selectedfile, currentDeltaResult);
					break;
				case "pdf":
					ReportExporter.saveDeltaAsPdf(selectedfile, currentDeltaResult);
					break;
				case "json":
					ReportExporter.saveDeltaAsJson(selectedfile, currentDeltaResult);
					break;
				default:
					ReportExporter.saveDeltaAsText(selectedfile, currentDeltaResult);
					break;
			}
			FontPreferences.saveLastSaveFolder(selectedfile.getParentFile().getAbsolutePath());
			FontPreferences.saveLastSaveFormat(formatKey);
			setStatusTemporary(STATUS_HDR + "Delta report saved: " + selectedfile.getName());
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					"Error saving delta report: " + ex.getMessage(),
					"Save Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Save a single host's scan report from the detail view.
	 */
	private void onSaveHostDetail(ScanResult.HostResult hr) {
		String dateStr = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

		JPanel formatPanel = new JPanel();
		formatPanel.setLayout(new BoxLayout(formatPanel, BoxLayout.Y_AXIS));
		formatPanel.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createEtchedBorder(), "Output Format",
				TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

		String lastFormat = FontPreferences.loadLastSaveFormat();
		ButtonGroup formatGroup = new ButtonGroup();
		JRadioButton rbAscii = new JRadioButton("ASCII Text (.txt)", "txt".equals(lastFormat));
		JRadioButton rbHtml = new JRadioButton("HTML (.html)", "html".equals(lastFormat));
		JRadioButton rbPdf = new JRadioButton("PDF (.pdf)", "pdf".equals(lastFormat));
		JRadioButton rbJson = new JRadioButton("JSON (.json)", "json".equals(lastFormat));

		formatGroup.add(rbAscii);
		formatGroup.add(rbHtml);
		formatGroup.add(rbPdf);
		formatGroup.add(rbJson);

		formatPanel.add(rbAscii);
		formatPanel.add(rbHtml);
		formatPanel.add(rbPdf);
		formatPanel.add(rbJson);

		JFileChooser chooser = new JFileChooser();
		chooser.setAccessory(formatPanel);

		String defaultExt;
		if (rbHtml.isSelected()) defaultExt = ".html";
		else if (rbPdf.isSelected()) defaultExt = ".pdf";
		else if (rbJson.isSelected()) defaultExt = ".json";
		else defaultExt = ".txt";

		String lastFolder = FontPreferences.loadLastSaveFolder();
		String saveDir = (lastFolder != null && new File(lastFolder).isDirectory())
				? lastFolder : reportsDir.getAbsolutePath();

		String hostLabel = ReportExporter.displayName(hr.getTargetUrl());
		String safeHost = hostLabel.replaceAll("[^a-zA-Z0-9._-]", "_");
		String prefix = "host-report-" + safeHost + "-" + dateStr;
		int idx = nextFileIndex(new File(saveDir), prefix, defaultExt);
		String baseFilename = prefix + "-" + idx;

		chooser.setCurrentDirectory(new File(saveDir));
		chooser.setSelectedFile(new File(saveDir, baseFilename + defaultExt));

		ActionListener formatChangeListener = e -> {
			File currentFile = chooser.getSelectedFile();
			if (currentFile != null) {
				String path = currentFile.getAbsolutePath();
				int lastDot = path.lastIndexOf('.');
				if (lastDot > 0) path = path.substring(0, lastDot);
				String newExt;
				if (rbHtml.isSelected()) newExt = ".html";
				else if (rbPdf.isSelected()) newExt = ".pdf";
				else if (rbJson.isSelected()) newExt = ".json";
				else newExt = ".txt";
				chooser.setSelectedFile(new File(path + newExt));
			}
		};
		rbAscii.addActionListener(formatChangeListener);
		rbHtml.addActionListener(formatChangeListener);
		rbPdf.addActionListener(formatChangeListener);
		rbJson.addActionListener(formatChangeListener);

		int returnVal = chooser.showSaveDialog(this);
		if (returnVal != JFileChooser.APPROVE_OPTION) return;

		File selectedfile = chooser.getSelectedFile().getAbsoluteFile();
		String ext;
		String formatKey;
		if (rbHtml.isSelected()) { ext = ".html"; formatKey = "html"; }
		else if (rbPdf.isSelected()) { ext = ".pdf"; formatKey = "pdf"; }
		else if (rbJson.isSelected()) { ext = ".json"; formatKey = "json"; }
		else { ext = ".txt"; formatKey = "txt"; }

		String filePath = selectedfile.getAbsolutePath();
		if (!filePath.toLowerCase().endsWith(ext)) {
			selectedfile = new File(filePath + ext);
		}

		try {
			selectedfile.createNewFile();
			ScanNode tree = hr.getScanTree();
			if (rbHtml.isSelected()) {
				ReportExporter.saveAsHtml(selectedfile, tree, themePrefs);
			} else if (rbPdf.isSelected()) {
				ReportExporter.saveAsPdf(selectedfile, tree, themePrefs);
			} else if (rbJson.isSelected()) {
				ReportExporter.saveAsJson(selectedfile, tree);
			} else {
				try (PrintWriter p = new PrintWriter(selectedfile)) {
					tree.walkVisible(node -> {
						String line = switch (node.getType()) {
							case SECTION -> "\n[" + node.getKey() + "]\n";
							case SUBSECTION -> "  " + node.getKey() + ":\n";
							case KEY_VALUE -> "    " + node.getKey() + "=" + node.getValue() + "\n";
							case WARNING -> ">>> " + node.getKey() + "\n";
							case NOTICE -> "*** " + node.getKey() + "\n";
							case CONTENT -> "    " + node.getKey() + "\n";
							case BLANK -> "\n";
							default -> "";
						};
						p.print(line);
					});
				}
			}
			FontPreferences.saveLastSaveFolder(selectedfile.getParentFile().getAbsolutePath());
			FontPreferences.saveLastSaveFormat(formatKey);
			setStatusTemporary(STATUS_HDR + "Report saved: " + selectedfile.getName());
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					"Error saving host report: " + ex.getMessage(),
					"Save Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Save a summary of the visible host cards (host, grade, score) to a file.
	 */
	private void onSaveCards() {
		List<ScanResult.HostResult> visibleHosts = scanResultsPanel.getVisibleHostResults();
		if (visibleHosts.isEmpty()) return;

		String dateStr = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

		JPanel formatPanel = new JPanel();
		formatPanel.setLayout(new BoxLayout(formatPanel, BoxLayout.Y_AXIS));
		formatPanel.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createEtchedBorder(), "Output Format",
				TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION));

		String lastFormat = FontPreferences.loadLastSaveFormat();
		ButtonGroup formatGroup = new ButtonGroup();
		JRadioButton rbAscii = new JRadioButton("ASCII Text (.txt)", "txt".equals(lastFormat));
		JRadioButton rbHtml = new JRadioButton("HTML (.html)", "html".equals(lastFormat));
		JRadioButton rbPdf = new JRadioButton("PDF (.pdf)", "pdf".equals(lastFormat));

		formatGroup.add(rbAscii);
		formatGroup.add(rbHtml);
		formatGroup.add(rbPdf);

		formatPanel.add(rbAscii);
		formatPanel.add(rbHtml);
		formatPanel.add(rbPdf);

		JFileChooser chooser = new JFileChooser();
		chooser.setAccessory(formatPanel);

		String defaultExt;
		if (rbHtml.isSelected()) defaultExt = ".html";
		else if (rbPdf.isSelected()) defaultExt = ".pdf";
		else defaultExt = ".txt";

		String lastFolder = FontPreferences.loadLastSaveFolder();
		String saveDir = (lastFolder != null && new File(lastFolder).isDirectory())
				? lastFolder : reportsDir.getAbsolutePath();

		String prefix = "cards-summary-" + dateStr;
		int idx = nextFileIndex(new File(saveDir), prefix, defaultExt);
		String baseFilename = prefix + "-" + idx;

		chooser.setCurrentDirectory(new File(saveDir));
		chooser.setSelectedFile(new File(saveDir, baseFilename + defaultExt));

		ActionListener formatChangeListener = e -> {
			File currentFile = chooser.getSelectedFile();
			if (currentFile != null) {
				String path = currentFile.getAbsolutePath();
				int lastDot = path.lastIndexOf('.');
				if (lastDot > 0) path = path.substring(0, lastDot);
				String newExt;
				if (rbHtml.isSelected()) newExt = ".html";
				else if (rbPdf.isSelected()) newExt = ".pdf";
				else newExt = ".txt";
				chooser.setSelectedFile(new File(path + newExt));
			}
		};
		rbAscii.addActionListener(formatChangeListener);
		rbHtml.addActionListener(formatChangeListener);
		rbPdf.addActionListener(formatChangeListener);

		int returnVal = chooser.showSaveDialog(this);
		if (returnVal != JFileChooser.APPROVE_OPTION) return;

		File selectedfile = chooser.getSelectedFile().getAbsoluteFile();
		String ext;
		String formatKey;
		if (rbHtml.isSelected()) { ext = ".html"; formatKey = "html"; }
		else if (rbPdf.isSelected()) { ext = ".pdf"; formatKey = "pdf"; }
		else { ext = ".txt"; formatKey = "txt"; }

		String filePath = selectedfile.getAbsolutePath();
		if (!filePath.toLowerCase().endsWith(ext)) {
			selectedfile = new File(filePath + ext);
		}

		try {
			selectedfile.createNewFile();
			if (rbHtml.isSelected()) {
				ReportExporter.saveCardsAsHtml(selectedfile, visibleHosts);
			} else if (rbPdf.isSelected()) {
				ReportExporter.saveCardsAsPdf(selectedfile, visibleHosts);
			} else {
				ReportExporter.saveCardsAsText(selectedfile, visibleHosts);
			}
			FontPreferences.saveLastSaveFolder(selectedfile.getParentFile().getAbsolutePath());
			FontPreferences.saveLastSaveFormat(formatKey);
			setStatusTemporary(STATUS_HDR + "Report saved: " + selectedfile.getName());
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(this,
					"Error saving cards summary: " + ex.getMessage(),
					"Save Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	// ---- AI Chat Panel ----

	private JPanel buildAiChatPanel() {
		JPanel panel = new JPanel(new java.awt.BorderLayout(0, 4));

		// Terminal display with Matrix-style slow-rolling cursor (read-only)
		aiTerminalView = new TerminalView();
		aiTerminal = aiTerminalView.getTerminal();
		aiTerminal.setWordWrap(true);
		aiTerminal.setAutoFollowEnabled(true);
		aiTerminal.setCharRenderDelay(5);
		aiTerminal.setBlinkCycleTime(250);
		aiTerminal.setReadOnly(true);
		applyAiTerminalColors();
		aiTerminal.addFocusListener(new java.awt.event.FocusAdapter() {
			@Override
			public void focusLost(java.awt.event.FocusEvent e) {
				aiTerminal.clearSelection();
			}
		});

		panel.add(aiTerminalView, java.awt.BorderLayout.CENTER);

		// Input bar: [Scan combo] [text input...] [Send]
		JPanel pnlInput = new JPanel(new GridBagLayout());
		GridBagConstraints gc = new GridBagConstraints();
		gc.insets = new Insets(2, 2, 2, 2);
		gc.gridy = 0;

		btnScanSelector = new JButton("(no scans)");
		refreshCachedScanFiles();
		updateScanSelectorButton();

		// Welcome message — after button is populated so we know if saved scans exist
		updateAiWelcomeMessage();
		btnScanSelector.addActionListener(e -> {
			if (currentScanResult != null && currentScanResult.getTotalTargets() > 1) {
				showHostSelectorPopup();
			} else {
				showScanSelectorPopup();
			}
		});
		gc.gridx = 0;
		gc.fill = GridBagConstraints.HORIZONTAL;
		gc.weightx = 0.0;
		pnlInput.add(btnScanSelector, gc);

		txtAiInput = new JTextField();
		gc.gridx = 1;
		gc.weightx = 1.0;
		gc.fill = GridBagConstraints.HORIZONTAL;
		pnlInput.add(txtAiInput, gc);

		btnAiSend = new JButton("Send");
		gc.gridx = 2;
		gc.weightx = 0.0;
		gc.fill = GridBagConstraints.NONE;
		pnlInput.add(btnAiSend, gc);

		panel.add(pnlInput, java.awt.BorderLayout.SOUTH);

		// Listeners
		btnAiSend.addActionListener(e -> sendAiMessage());
		txtAiInput.addActionListener(e -> sendAiMessage());

		return panel;
	}

	private void sendAiMessage() {
		String apiKey = themePrefs.getAiChatApiKey();
		boolean isOllama = "Ollama".equalsIgnoreCase(themePrefs.getAiChatProvider());
		if (!isOllama && (apiKey == null || apiKey.isBlank())) {
			aiTerminal.write(fmtError("API key not configured. Go to System > Settings > AI to enter your API key.") + "\n");
			return;
		}
		String userText = txtAiInput.getText().trim();
		if (userText.isEmpty()) return;
		txtAiInput.setText("");

		// Display and log user message
		aiTerminal.write(fmtUserPrefix("User> ") + fmtUserText(userText) + "\n");
		chatLog.info("User> {}", userText);

		// Build system context: include scan report if available
		String systemContext = themePrefs.getAiChatSystemPrompt();
		if (aiActiveHost != null) {
			systemContext += "\n\nHere is the TLS scan report for "
					+ aiActiveHost.getTargetUrl() + ":\n"
					+ hostResultToPlainText(aiActiveHost);
		} else if (selectedScanText != null && !selectedScanText.isBlank()) {
			systemContext += "\n\nHere is the current TLS scan report for context:\n"
					+ selectedScanText;
		} else if (currentScanResult != null) {
			systemContext += "\n\nHere is the current scan report for context:\n"
					+ scanResultToPlainText(currentScanResult);
		}

		// Add to chat history
		chatHistory.add(new AiAnalysisService.ChatMessage("user", userText));

		// Disable input while waiting
		txtAiInput.setEnabled(false);
		btnAiSend.setEnabled(false);

		// Show "AI> " prefix immediately; dots start after 3 seconds
		aiTerminal.write(fmtAiPrefix("AI> "));
		aiDotCount = 0;
		final long startTime = System.currentTimeMillis();
		aiDotTimer = new Timer(1000, e -> {
			long elapsed = System.currentTimeMillis() - startTime;
			if (elapsed >= 3000) {
				aiDotCount++;
				aiTerminal.write(fmtAiText("."));
			}
		});
		aiDotTimer.start();

		String finalSystemContext = systemContext;
		new Thread(() -> {
			try {
				AiAnalysisService service = new AiAnalysisService();
				String response = service.chat(
						chatHistory, themePrefs.getAiChatApiKey(),
						themePrefs.getAiChatProvider(), themePrefs.getAiChatModel(),
						themePrefs.getAiChatMaxTokens(), themePrefs.getAiChatTemperature(),
						finalSystemContext, themePrefs.getAiChatEndpointUrl());

				// Truncate to 5 sentences BEFORE logging or storing in history
				String cleaned = stripMarkdown(response);
				chatHistory.add(new AiAnalysisService.ChatMessage("assistant", cleaned));
				chatLog.info("AI> {}", cleaned);

				javax.swing.SwingUtilities.invokeLater(() -> {
					aiDotTimer.stop();
					aiTerminal.write("\r");
					aiTerminal.write(fmtAiPrefix("AI> ") + fmtAiText(cleaned) + "\n\n");
					txtAiInput.setEnabled(true);
					btnAiSend.setEnabled(true);
					txtAiInput.requestFocusInWindow();
				});
			} catch (AiAnalysisService.AiAnalysisException ex) {
				javax.swing.SwingUtilities.invokeLater(() -> {
					aiDotTimer.stop();
					// Clear the "AI> ..." line, rewrite with error
					aiTerminal.write("\r");
					aiTerminal.write(fmtAiPrefix("AI> ")
							+ fmtError(ex.getMessage() + ", see log for details.") + "\n");
					chatLog.error("AI error: {}", ex.getMessage());
					// Remove the failed user message from history
					if (!chatHistory.isEmpty()) chatHistory.remove(chatHistory.size() - 1);
					txtAiInput.setEnabled(true);
					btnAiSend.setEnabled(true);
					txtAiInput.requestFocusInWindow();
				});
			}
		}, "ai-chat").start();
	}

	private String fmtUserPrefix(String text) {
		return "{fg:" + hexColor(themePrefs.getAiTerminalUserPrefix()) + "}{+bold}" + text + "{-bold}{reset}";
	}

	private String fmtUserText(String text) {
		return "{fg:" + hexColor(themePrefs.getAiTerminalUserText()) + "}" + escapeTerminal(text) + "{reset}";
	}

	private String fmtAiPrefix(String text) {
		return "{fg:" + hexColor(themePrefs.getAiTerminalAiPrefix()) + "}{+bold}" + text + "{-bold}{reset}";
	}

	private String fmtAiText(String text) {
		return "{fg:" + hexColor(themePrefs.getAiTerminalAiText()) + "}" + escapeTerminal(text) + "{reset}";
	}

	private String fmtError(String text) {
		return "{fg:" + hexColor(themePrefs.getAiTerminalError()) + "}" + escapeTerminal(text) + "{reset}\n";
	}

	private String fmtSystem(String text) {
		return "{fg:" + hexColor(themePrefs.getAiTerminalSystem()) + "}" + escapeTerminal(text) + "{reset}\n";
	}

	private String hexColor(Color c) {
		return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue());
	}

	private String escapeTerminal(String text) {
		return text.replace("{", "{{");
	}

	private static final int MAX_SENTENCES = 5;

	/** Strip markdown, collapse to single paragraph, truncate after MAX_SENTENCES. */
	private String stripMarkdown(String text) {
		// Remove bold/italic markers
		text = text.replaceAll("\\*\\*(.+?)\\*\\*", "$1");
		text = text.replaceAll("\\*(.+?)\\*", "$1");
		text = text.replaceAll("__(.+?)__", "$1");
		text = text.replaceAll("(?<=\\s|^)_(.+?)_(?=\\s|$|[.,!?])", "$1");
		// Remove headers
		text = text.replaceAll("(?m)^#{1,6}\\s+", "");
		// Remove bullet/dash/numbered list markers
		text = text.replaceAll("(?m)^\\s*[-*+]\\s+", "");
		text = text.replaceAll("(?m)^\\s*\\d+\\.\\s+", "");
		// Collapse to single paragraph
		text = text.replaceAll("\\n\\s*\\n", " ");
		text = text.replace('\n', ' ');
		text = text.replaceAll("  +", " ");
		text = text.trim();

		// Truncate after MAX_SENTENCES (count sentence-ending periods)
		int count = 0;
		for (int i = 0; i < text.length(); i++) {
			char ch = text.charAt(i);
			if ((ch == '.' || ch == '!' || ch == '?')
					&& (i + 1 >= text.length() || text.charAt(i + 1) == ' ' || text.charAt(i + 1) == '"')) {
				count++;
				if (count >= MAX_SENTENCES) {
					return text.substring(0, i + 1);
				}
			}
		}
		return text;
	}

	private void applyAiTerminalColors() {
		if (aiTerminal != null) {
			aiTerminal.setBackground(themePrefs.getAiTerminalBg());
			aiTerminal.setSelectionColor(themePrefs.getAiTerminalSelectionBg());
			aiTerminal.setSelectedTextColor(themePrefs.getAiTerminalSelectionFg());
		}
	}

	// ---- Scan Auto-Save & Selector ----

	/**
	 * Write the AI terminal welcome message based on current state.
	 * Loads the most recent saved scan if available.
	 */
	private void updateAiWelcomeMessage() {
		if (aiTerminal == null) return;
		aiTerminal.clear();
		aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));

		// Host card selected — show host-specific ready message
		if (aiActiveHost != null) {
			updateScanSelectorButton();
			if (!themePrefs.isChatReady()) {
				aiTerminal.write(fmtSystem("API key not configured. Go to System > Settings > AI to enter your API key.\n"));
			} else {
				aiTerminal.write(fmtSystem("Ready for questions about: "
						+ aiActiveHost.getTargetUrl() + "\n"));
			}
			return;
		}

		if (!cachedScanFiles.isEmpty()) {
			String topLabel = formatScanLabel(cachedScanFiles.get(0).getName());
			loadScanFromFileSilent(cachedScanFiles.get(0));
			selectedScanLabel = topLabel;
			updateScanSelectorButton();
			if (!themePrefs.isChatReady()) {
				aiTerminal.write(fmtSystem("Scan loaded: " + topLabel));
				aiTerminal.write(fmtSystem("API key not configured. Go to System > Settings > AI to enter your API key.\n"));
			} else {
				aiTerminal.write(fmtSystem("Ready for questions about: " + topLabel + "\n"));
			}
			return;
		}

		if (!themePrefs.isChatReady()) {
			aiTerminal.write(fmtSystem("API key not configured. Go to System > Settings > AI to enter your API key.\n"));
		} else {
			aiTerminal.write(fmtSystem("Scan a server to get started.\n"));
		}
	}

	/**
	 * Returns true if the AI Assistant tab should be enabled.
	 * Requires: AI configured AND either a host card selected (multi-target)
	 * or scan data available (individual/saved scans).
	 */
	private boolean isAiTabEnabled() {
		if (!themePrefs.isChatReady()) return false;
		if (aiActiveHost != null) return true;
		if (selectedScanText != null && !selectedScanText.isBlank()) return true;
		if (currentScanResult != null && currentScanResult.getTotalTargets() == 1) return true;
		if (!cachedScanFiles.isEmpty()) return true;
		return false;
	}

	/**
	 * Re-evaluate and update the enabled state of the AI Assistant tab.
	 */
	private void updateAiTabState() {
		mainTabs.setEnabledAt(1, isAiTabEnabled());
	}

	/**
	 * Write a context-aware "Ready for questions" message to the AI terminal
	 * based on the current scan type radio and available scan data.
	 */
	private void updateAiReadyMessage() {
		if (aiTerminal == null) return;

		if (aiActiveHost != null) {
			aiTerminal.write(fmtSystem("Ready for questions about: "
					+ aiActiveHost.getTargetUrl() + "\n"));
		} else if (selectedScanText != null && selectedScanLabel != null) {
			aiTerminal.write(fmtSystem("Ready for questions about: " + selectedScanLabel + "\n"));
		} else if (currentScanResult != null) {
			String datetime = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());
			aiTerminal.write(fmtSystem("Ready for questions about scan ("
					+ currentScanResult.getTotalTargets() + " targets) on " + datetime + "\n"));
		} else {
			aiTerminal.write(fmtSystem("No scan available. Run a scan to get started.\n"));
		}
	}

	/**
	 * Convert a {@link ScanResult} to plain text for AI context.
	 */
	private String scanResultToPlainText(ScanResult result) {
		StringBuilder sb = new StringBuilder();
		sb.append("Scan Results\n");
		sb.append("Total targets: ").append(result.getTotalTargets()).append("\n");
		sb.append("Successful: ").append(result.getSuccessCount()).append("\n");
		sb.append("Errors: ").append(result.getErrorCount()).append("\n\n");
		for (ScanResult.HostResult hr : result.getResults()) {
			sb.append(hostResultToPlainText(hr));
		}
		return sb.toString();
	}

	/**
	 * Convert a single {@link ScanResult.HostResult} to plain text for AI context.
	 */
	private String hostResultToPlainText(ScanResult.HostResult hr) {
		StringBuilder sb = new StringBuilder();
		sb.append("=== ").append(hr.getTargetUrl()).append(" ===\n");
		if (hr.isSuccess() && hr.getScanTree() != null) {
			hr.getScanTree().walkVisible(node -> {
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
		} else if (!hr.isSuccess()) {
			sb.append("Error: ").append(hr.getErrorMessage()).append("\n");
		}
		sb.append("\n");
		return sb.toString();
	}

	/**
	 * Sync the scan selector with the latest files on disk.
	 * If a new scan exists that isn't currently selected, update the combo
	 * and load it.
	 */
	private void syncScanSelector() {
		if (btnScanSelector == null) return;

		refreshCachedScanFiles();
		updateScanSelectorButton();

		// If user explicitly has no report selected, don't auto-load a file;
		// just refresh the ready message (they may be using in-memory scan data)
		if (selectedScanLabel == null) {
			if (aiTerminal != null) {
				aiTerminal.clearSelection();
				aiTerminal.clear();
				aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
				updateAiReadyMessage();
			}
			return;
		}

		if (cachedScanFiles.isEmpty()) return;

		String newestLabel = formatScanLabel(cachedScanFiles.get(0).getName());

		// If newest scan is already selected, nothing to do
		if (newestLabel.equals(selectedScanLabel)) return;

		selectedScanLabel = newestLabel;
		updateScanSelectorButton();
		loadScanFromFileSilent(cachedScanFiles.get(0));

		// Update terminal message without clearing chat history
		if (aiTerminal != null) {
			aiTerminal.clearSelection();
			aiTerminal.clear();
			aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
			aiTerminal.write(fmtSystem("Ready for questions about: " + newestLabel + "\n"));
		}
	}

	/**
	 * Scan a directory for files matching {prefix}-{N}{ext} and return max(N)+1,
	 * or 1 if no matching files are found.
	 */
	private int nextFileIndex(File dir, String prefix, String ext) {
		int max = 0;
		File[] files = dir.listFiles();
		if (files != null) {
			for (File f : files) {
				String name = f.getName();
				if (name.startsWith(prefix + "-") && name.endsWith(ext)) {
					String middle = name.substring(prefix.length() + 1,
							name.length() - ext.length());
					try {
						int n = Integer.parseInt(middle);
						if (n > max) max = n;
					} catch (NumberFormatException ignored) {
					}
				}
			}
		}
		return max + 1;
	}

	private void updateScanSelectorButton() {
		if (btnScanSelector == null) return;

		if (aiActiveHost != null) {
			String host = aiActiveHost.getTargetUrl();
			btnScanSelector.setText(truncateLabel(host, 35) + " \u25BE");
			btnScanSelector.setToolTipText(host);
			// Enable if multi-target scan so user can switch hosts
			btnScanSelector.setEnabled(currentScanResult != null
					&& currentScanResult.getTotalTargets() > 1);
			return;
		}

		if (selectedScanLabel != null) {
			btnScanSelector.setText(truncateLabel(selectedScanLabel, 35) + " \u25BE");
			btnScanSelector.setToolTipText(selectedScanLabel);
			btnScanSelector.setEnabled(true);
			return;
		}

		// No report selected — show placeholder, keep enabled so user can pick
		btnScanSelector.setText("(no report selected) \u25BE");
		btnScanSelector.setToolTipText(null);
		btnScanSelector.setEnabled(true);
	}

	private void refreshScanSelector(String filename) {
		refreshCachedScanFiles();
		if (filename != null) {
			selectedScanLabel = formatScanLabel(filename);
		}
		updateScanSelectorButton();
	}

	private String formatScanLabel(String filename) {
		// Individual new format: scan-report-yyyy-MM-dd-N.txt -> Scan Report — yyyy-MM-dd #N
		// Batch new format: batch-scan-report-yyyy-MM-dd-N.txt -> Batch Report — yyyy-MM-dd #N
		// Legacy individual: hostname-yyyyMMdd-HHmmss.txt -> hostname — yyyy-MM-dd HH:mm:ss
		// Legacy batch: batch-Ntargets-yyyyMMdd-HHmmss.txt -> Batch (N targets) — yyyy-MM-dd HH:mm:ss
		String name = filename;
		if (name.endsWith(".txt")) {
			name = name.substring(0, name.length() - 4);
		}

		if (name.startsWith("batch-scan-report-")) {
			// Batch new format: batch-scan-report-yyyy-MM-dd-N
			String rest = name.substring("batch-scan-report-".length()); // yyyy-MM-dd-N
			int lastDash = rest.lastIndexOf('-');
			if (lastDash > 0) {
				String date = rest.substring(0, lastDash);
				String num = rest.substring(lastDash + 1);
				return "Batch Report \u2014 " + date + " #" + num;
			}
			return filename; // fallback
		}

		if (name.startsWith("scan-report-")) {
			// Individual new format: scan-report-yyyy-MM-dd-N
			String rest = name.substring("scan-report-".length()); // yyyy-MM-dd-N
			int lastDash = rest.lastIndexOf('-');
			if (lastDash > 0) {
				String date = rest.substring(0, lastDash);
				String num = rest.substring(lastDash + 1);
				return "Scan Report \u2014 " + date + " #" + num;
			}
			return filename; // fallback
		}

		// Legacy batch format: batch-Ntargets-yyyyMMdd-HHmmss
		if (name.startsWith("batch-") && name.contains("targets-")) {
			int tsStart = name.length() - 15;
			if (tsStart > 0 && name.charAt(tsStart - 1) == '-') {
				String prefix = name.substring(0, tsStart - 1); // "batch-Ntargets"
				String ts = name.substring(tsStart); // yyyyMMdd-HHmmss
				if (ts.length() == 15 && ts.charAt(8) == '-') {
					String nStr = prefix.replace("batch-", "").replace("targets", "");
					String formatted = ts.substring(0, 4) + "-" + ts.substring(4, 6) + "-" + ts.substring(6, 8)
							+ " " + ts.substring(9, 11) + ":" + ts.substring(11, 13) + ":" + ts.substring(13, 15);
					return "Batch (" + nStr + " targets) \u2014 " + formatted;
				}
			}
		}

		// Legacy individual format: hostname-yyyyMMdd-HHmmss
		int tsStart = name.length() - 15;
		if (tsStart < 1 || name.charAt(tsStart - 1) != '-') {
			return filename; // fallback
		}
		String host = name.substring(0, tsStart - 1);
		String ts = name.substring(tsStart); // yyyyMMdd-HHmmss

		if (ts.length() != 15 || ts.charAt(8) != '-') {
			return filename; // fallback
		}

		String formatted = ts.substring(0, 4) + "-" + ts.substring(4, 6) + "-" + ts.substring(6, 8)
				+ " " + ts.substring(9, 11) + ":" + ts.substring(11, 13) + ":" + ts.substring(13, 15);
		return host + " \u2014 " + formatted;
	}

	private String labelToFilename(String label) {
		// Individual new: Scan Report — yyyy-MM-dd #N -> scan-report-yyyy-MM-dd-N.txt
		// Batch new: Batch Report — yyyy-MM-dd #N -> batch-scan-report-yyyy-MM-dd-N.txt
		// Legacy individual: hostname — yyyy-MM-dd HH:mm:ss -> hostname-yyyyMMdd-HHmmss.txt
		// Legacy batch: Batch (N targets) — yyyy-MM-dd HH:mm:ss -> batch-Ntargets-yyyyMMdd-HHmmss.txt
		int sep = label.lastIndexOf(" \u2014 ");
		if (sep < 0) return label;

		String prefix = label.substring(0, sep);
		String suffix = label.substring(sep + 3).trim();

		if ("Scan Report".equals(prefix)) {
			String[] parts = suffix.split(" #");
			if (parts.length == 2) {
				return "scan-report-" + parts[0] + "-" + parts[1] + ".txt";
			}
		}

		if ("Batch Report".equals(prefix)) {
			String[] parts = suffix.split(" #");
			if (parts.length == 2) {
				return "batch-scan-report-" + parts[0] + "-" + parts[1] + ".txt";
			}
		}

		// Legacy batch format: Batch (N targets) — yyyy-MM-dd HH:mm:ss
		if (prefix.startsWith("Batch (") && prefix.endsWith(" targets)")) {
			String n = prefix.replaceAll("\\D+", "");
			String ts = suffix.replace("-", "").replace(":", "").replace(" ", "-");
			return "batch-" + n + "targets-" + ts + ".txt";
		}

		// Legacy individual format
		String ts = suffix.replace("-", "").replace(":", "").replace(" ", "-");
		return prefix + "-" + ts + ".txt";
	}

	private void loadScanFromFileSilent(File file) {
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			StringBuilder sb = new StringBuilder();
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line).append("\n");
			}
			selectedScanText = sb.toString();
		} catch (IOException e) {
			logger.error("Failed to load scan from file: {}", e.getMessage(), e);
		}
	}

	private void loadScanFromFile(File file) {
		loadScanFromFileSilent(file);
		selectedScanLabel = formatScanLabel(file.getName());
		updateScanSelectorButton();
		chatHistory.clear();
		if (aiTerminal != null) {
			aiTerminal.clearSelection();
			aiTerminal.clear();
			aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
			aiTerminal.write(fmtSystem("Loaded scan: " + selectedScanLabel + "\n"));
		}
	}

	// ---- Scan Selector Popup ----

	private String truncateLabel(String label, int maxLen) {
		if (label.length() <= maxLen) return label;
		int sep = label.indexOf(" \u2014 ");
		if (sep < 0) {
			return label.substring(0, maxLen - 3) + "...";
		}
		String datePart = label.substring(sep);
		int hostMax = maxLen - datePart.length() - 3;
		if (hostMax <= 0) {
			return label.substring(0, maxLen - 3) + "...";
		}
		return label.substring(0, hostMax) + "..." + datePart;
	}

	private void refreshCachedScanFiles() {
		File[] files = scansDir.listFiles((dir, name) -> name.endsWith(".txt"));
		if (files == null || files.length == 0) {
			cachedScanFiles = new ArrayList<>();
			return;
		}
		Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
		cachedScanFiles = new ArrayList<>(Arrays.asList(files));
	}

	private void showScanSelectorPopup() {
		refreshCachedScanFiles();

		JPopupMenu popup = new JPopupMenu();
		popup.setLayout(new java.awt.BorderLayout());

		JPanel content = new JPanel(new java.awt.BorderLayout(0, 4));
		content.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		// Filter field
		JTextField filterField = new JTextField();
		filterField.setToolTipText("Regex filter (e.g. google.*)");
		content.add(filterField, java.awt.BorderLayout.NORTH);

		// List
		DefaultListModel<String> listModel = new DefaultListModel<>();
		JList<String> list = new JList<>(listModel);
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.setVisibleRowCount(8);
		JScrollPane listScroll = new JScrollPane(list);
		listScroll.setPreferredSize(new Dimension(300, 160));
		content.add(listScroll, java.awt.BorderLayout.CENTER);

		populateFilteredList(listModel, "");

		// Filter listener
		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) { populateFilteredList(listModel, filterField.getText()); }
			@Override
			public void removeUpdate(DocumentEvent e) { populateFilteredList(listModel, filterField.getText()); }
			@Override
			public void changedUpdate(DocumentEvent e) { populateFilteredList(listModel, filterField.getText()); }
		});

		// Selection listener — single click selects
		list.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				onPopupItemSelected(popup, list);
			}
		});

		popup.add(content);
		popup.show(btnScanSelector, 0, btnScanSelector.getHeight());
		javax.swing.SwingUtilities.invokeLater(() -> filterField.requestFocusInWindow());
	}

	/**
	 * Show a popup listing hosts from the current multi-target scan result.
	 * Selecting a host switches AI context to that host.
	 */
	private void showHostSelectorPopup() {
		if (currentScanResult == null) return;

		JPopupMenu popup = new JPopupMenu();
		popup.setLayout(new java.awt.BorderLayout());

		JPanel content = new JPanel(new java.awt.BorderLayout(0, 4));
		content.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		// Filter field
		JTextField filterField = new JTextField();
		filterField.setToolTipText("Regex filter (e.g. google.*)");
		content.add(filterField, java.awt.BorderLayout.NORTH);

		// List
		DefaultListModel<String> listModel = new DefaultListModel<>();
		JList<String> list = new JList<>(listModel);
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.setVisibleRowCount(8);
		JScrollPane listScroll = new JScrollPane(list);
		listScroll.setPreferredSize(new Dimension(300, 160));
		content.add(listScroll, java.awt.BorderLayout.CENTER);

		populateHostList(listModel, "");

		// Filter listener
		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) { populateHostList(listModel, filterField.getText()); }
			@Override
			public void removeUpdate(DocumentEvent e) { populateHostList(listModel, filterField.getText()); }
			@Override
			public void changedUpdate(DocumentEvent e) { populateHostList(listModel, filterField.getText()); }
		});

		// Selection listener — single click selects
		list.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				String selected = list.getSelectedValue();
				if (selected == null) return;
				popup.setVisible(false);

				// Find matching HostResult
				for (ScanResult.HostResult hr : currentScanResult.getResults()) {
					if (hr.getTargetUrl().equals(selected)) {
						aiActiveHost = hr;
						chatHistory.clear();
						if (aiTerminal != null) {
							aiTerminal.clear();
							aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
							aiTerminal.write(fmtSystem("Ready for questions about: "
									+ hr.getTargetUrl() + "\n"));
						}
						updateScanSelectorButton();
						return;
					}
				}
			}
		});

		popup.add(content);
		popup.show(btnScanSelector, 0, btnScanSelector.getHeight());
		javax.swing.SwingUtilities.invokeLater(() -> filterField.requestFocusInWindow());
	}

	/**
	 * Populate a list model with host URLs from the current scan result,
	 * optionally filtered by a regex pattern.
	 */
	private void populateHostList(DefaultListModel<String> model, String filterText) {
		model.clear();
		if (currentScanResult == null) return;

		String trimmed = filterText.trim();
		Pattern pattern = null;
		if (!trimmed.isEmpty()) {
			try {
				pattern = Pattern.compile(trimmed, Pattern.CASE_INSENSITIVE);
			} catch (PatternSyntaxException e) {
				return;
			}
		}

		for (ScanResult.HostResult hr : currentScanResult.getResults()) {
			String url = hr.getTargetUrl();
			if (pattern == null || pattern.matcher(url).find()) {
				model.addElement(url);
			}
		}
	}

	private static final String NO_REPORT_ITEM = "No report selected";

	private void populateFilteredList(DefaultListModel<String> model, String filterText) {
		model.clear();
		String trimmed = filterText.trim();

		if (trimmed.isEmpty()) {
			model.addElement(NO_REPORT_ITEM);
			int limit = Math.min(cachedScanFiles.size(), 5);
			for (int i = 0; i < limit; i++) {
				model.addElement(formatScanLabel(cachedScanFiles.get(i).getName()));
			}
		} else {
			Pattern pattern;
			try {
				pattern = Pattern.compile(trimmed, Pattern.CASE_INSENSITIVE);
			} catch (PatternSyntaxException e) {
				model.addElement("Browse\u2026");
				return;
			}
			for (File f : cachedScanFiles) {
				if (pattern.matcher(f.getName()).find()) {
					model.addElement(formatScanLabel(f.getName()));
				}
			}
		}
		model.addElement("Browse\u2026");
	}

	private void onPopupItemSelected(JPopupMenu popup, JList<String> list) {
		String selected = list.getSelectedValue();
		if (selected == null) return;

		popup.setVisible(false);

		if (NO_REPORT_ITEM.equals(selected)) {
			selectedScanLabel = null;
			selectedScanText = null;
			updateScanSelectorButton();
			chatHistory.clear();
			if (aiTerminal != null) {
				aiTerminal.clear();
				aiTerminal.write(fmtSystem("Welcome to DeepViolet AI Assistant."));
				updateAiReadyMessage();
			}
			return;
		}

		if ("Browse\u2026".equals(selected)) {
			JFileChooser chooser = new JFileChooser(scansDir);
			chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text files", "txt"));
			int result = chooser.showOpenDialog(this);
			if (result == JFileChooser.APPROVE_OPTION) {
				loadScanFromFile(chooser.getSelectedFile());
			}
			return;
		}

		String filename = labelToFilename(selected);
		File file = new File(scansDir, filename);
		if (file.exists()) {
			loadScanFromFile(file);
		}
	}

	/**
	 * Auto-save scan results to the unified scans directory.
	 */
	private void autoSaveScanResult() {
		if (currentScanResult == null) return;

		String date = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
		String prefix = "batch-scan-report-" + date;
		int n = nextFileIndex(scansDir, prefix, ".txt");
		String filename = prefix + "-" + n + ".txt";
		File outFile = new File(scansDir, filename);

		try {
			ReportExporter.saveScanAsText(outFile, currentScanResult, 20, themePrefs);
		} catch (IOException e) {
			logger.error("Failed to auto-save scan result: {}", e.getMessage(), e);
		}

		// Also auto-save as .dvscan for reloadable structured data
		File dvscanFile = new File(scansDir, prefix + "-" + n + ".dvscan");
		try {
			ReportExporter.saveScanFile(dvscanFile, currentScanResult);
		} catch (IOException e) {
			logger.error("Failed to auto-save .dvscan file: {}", e.getMessage(), e);
		}

		refreshCachedScanFiles();
	}

}
