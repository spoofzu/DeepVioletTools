package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.image.BufferedImage;
import java.util.HashSet;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JColorChooser;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JPasswordField;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SpinnerNumberModel;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.util.FontPreferences;
import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ai.AiAnalysisException;
import com.mps.deepviolet.api.ai.AiAnalysisService;
import com.mps.deepviolet.api.ai.AiConfig;
import com.mps.deepviolet.api.ai.AiProvider;
import com.mps.deepviolet.api.ai.IAiAnalysisService;

import org.ms.terminal.gui.TerminalPanel;
import org.ms.terminal.gui.TerminalView;

/**
 * Modal dialog for configuring font and theme colors.
 *
 * @author Milton Smith
 */
public class FontChooserDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private JComboBox<String> cmbFontFamily;
	private JComboBox<Integer> cmbFontSize;
	private JTextPane txtPreview;

	private JButton btnBackground;
	private JButton btnDefault;
	private JButton btnNotice;
	private JButton btnHeading;
	private JButton btnContent;
	private JButton btnKey;
	private JButton btnValue;
	private JButton btnWarning;
	private JButton btnSubsection;
	private JButton btnHighlight;
	private JButton btnRiskPass;
	private JButton btnRiskInconclusive;
	private JButton btnRiskFail;
	private JButton btnRiskCritical;
	private JButton btnRiskHigh;
	private JButton btnRiskMedium;
	private JButton btnRiskLow;
	private JButton btnRiskInfo;

	private JCheckBox chkHardwrap;
	private JSpinner spnHardwrapWidth;

	// Engine tab controls
	private JCheckBox chkRiskAssessment;
	private JCheckBox chkRuntimeEnvironment;
	private JCheckBox chkHost;
	private JCheckBox chkHttpResponse;
	private JCheckBox chkSecurityHeaders;
	private JCheckBox chkConnection;
	private JCheckBox chkCipherSuites;
	private JCheckBox chkCertChain;
	private JCheckBox chkRevocation;
	private JCheckBox chkTlsFingerprint;
	private JComboBox<String> cmbCipherConvention;
	private JCheckBox chkSslv3;
	private JCheckBox chkTls10;
	private JCheckBox chkTls11;
	private JCheckBox chkTls12;
	private JCheckBox chkTls13;
	private JCheckBox chkAiEvaluation;
	private JSpinner spnRiskScale;

	// Scanning priority controls (unified)
	private JSpinner spnWorkerThreads;
	private JSpinner spnThrottleDelayMs;

	// AI Chat config controls
	private JCheckBox chkAiChatEnabled;
	private JComboBox<String> cmbAiChatProvider;
	private JPasswordField txtAiChatApiKey;
	private JLabel lblAiChatApiKey;
	private JTextField txtAiChatEndpointUrl;
	private JLabel lblAiChatEndpointUrl;
	private JComboBox<String> cmbAiChatModel;
	private JSpinner spnAiChatMaxTokens;
	private JSpinner spnAiChatTemperature;
	private JButton btnAiChatTest;
	private JLabel lblAiChatTestResult;

	// AI Report config controls
	private JCheckBox chkAiReportEnabled;
	private JComboBox<String> cmbAiReportProvider;
	private JPasswordField txtAiReportApiKey;
	private JLabel lblAiReportApiKey;
	private JTextField txtAiReportEndpointUrl;
	private JLabel lblAiReportEndpointUrl;
	private JComboBox<String> cmbAiReportModel;
	private JSpinner spnAiReportMaxTokens;
	private JSpinner spnAiReportTemperature;
	private JButton btnAiReportTest;
	private JLabel lblAiReportTestResult;

	// AI Prompts controls
	private JTextArea txtAiSystemPrompt;
	private JTextArea txtAiChatSystemPrompt;

	// AI Terminal Colors controls
	private JButton btnAiTermBg;
	private JButton btnAiTermUserPrefix;
	private JButton btnAiTermUserText;
	private JButton btnAiTermAiPrefix;
	private JButton btnAiTermAiText;
	private JButton btnAiTermError;
	private JButton btnAiTermSystem;
	private JButton btnAiTermSelectionBg;
	private JButton btnAiTermSelectionFg;
	private TerminalPanel aiPreviewTerminal;

	// Cipher Map tab controls
	private JCheckBox chkCipherMapEnabled;
	private JTextArea txtCipherMapYaml;
	private boolean cipherMapPlaceholderActive;

	// User Risks tab controls
	private JCheckBox chkUserRiskRulesEnabled;
	private JTextArea txtUserRiskRulesYaml;
	private boolean userRiskRulesPlaceholderActive;

	// Card display controls
	private JComboBox<String> cmbCardFontFamily;
	private JComboBox<Integer> cmbCardFontSize;
	private JSpinner spnCardBadgeSize;
	private JButton btnCardBg;
	private JButton btnCardText;
	private JButton btnCardDim;
	private JButton btnCardBorder;
	private JButton btnCardSelected;
	private JButton btnCardError;
	private CardMetaPalette cardMetaPalette;
	private CardLayoutPreview cardLayoutPreview;
	private CardGridEditor cardGridEditor;
	private CardTrashPanel cardTrashPanel;

	// Application tab controls
	private JCheckBox chkSuppressSaveWarning;
	private JComboBox<String> cmbAppFontFamily;
	private JComboBox<Integer> cmbAppFontSize;
	private JButton btnAppBg;
	private JButton btnAppFg;
	private JButton btnAppButtonBg;
	private JButton btnAppButtonFg;

	// Promoted to instance fields for mode visibility control
	private JTabbedPane settingsTabbedPane;
	private JTabbedPane aiSubTabs;
	private JPanel pnlReportSections;

	private FontPreferences prefs;
	private boolean approved = false;
	private boolean applyingTheme = false;

	private static final Integer[] SIZES = { 8, 9, 10, 11, 12, 13, 14, 16,
			18, 20, 24, 28, 32 };

	/** Pre-computed set of monospaced font family names on this system. */
	private static final Set<String> MONO_FONTS = detectMonospacedFonts();

	private static Set<String> detectMonospacedFonts() {
		Set<String> mono = new HashSet<>();
		Graphics g = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB).getGraphics();
		for (String family : GraphicsEnvironment.getLocalGraphicsEnvironment()
				.getAvailableFontFamilyNames()) {
			FontMetrics fm = g.getFontMetrics(new Font(family, Font.PLAIN, 12));
			if (fm.charWidth('i') == fm.charWidth('W')) {
				mono.add(family);
			}
		}
		g.dispose();
		return mono;
	}

	/**
	 * CTOR
	 *
	 * @param owner   Parent frame
	 * @param current Current theme preferences
	 */
	private FontPreferences originalPrefs;

	public FontChooserDialog(JFrame owner, FontPreferences current) {
		super(owner, "Settings", true);
		this.prefs = copyPrefs(current);
		this.originalPrefs = copyPrefs(current);
		initComponents();
		setSize((int) (owner.getWidth() * 0.75),
				(int) (owner.getHeight() * 0.75));
		setLocationRelativeTo(owner);

		// Warn on window-close if unsaved changes exist
		setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
		addWindowListener(new java.awt.event.WindowAdapter() {
			@Override
			public void windowClosing(java.awt.event.WindowEvent e) {
				syncPrefsFromControls();
				if (hasUnsavedChanges()) {
					int choice = javax.swing.JOptionPane.showConfirmDialog(
							FontChooserDialog.this,
							"Unsaved changes exist. Press OK to save or Cancel to discard changes.",
							"Settings",
							javax.swing.JOptionPane.OK_CANCEL_OPTION,
							javax.swing.JOptionPane.WARNING_MESSAGE);
					if (choice == javax.swing.JOptionPane.OK_OPTION) {
						approved = true;
						syncPrefsFromControls();
						dispose();
					} else {
						FontPreferences.applyAppTheme(originalPrefs);
						dispose();
					}
				} else {
					FontPreferences.applyAppTheme(originalPrefs);
					dispose();
				}
			}
		});
	}

	private void initComponents() {

		// ---- font panel ----
		JPanel pnlFont = new JPanel(new GridBagLayout());
		pnlFont.setBorder(BorderFactory.createTitledBorder("Font"));
		GridBagConstraints c = new GridBagConstraints();
		c.insets = new Insets(4, 6, 4, 6);

		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.WEST;
		pnlFont.add(new JLabel("Family:"), c);

		String[] families = GraphicsEnvironment.getLocalGraphicsEnvironment()
				.getAvailableFontFamilyNames();
		cmbFontFamily = new JComboBox<>(families);
		cmbFontFamily.setRenderer(createMonoTagRenderer());
		cmbFontFamily.setPrototypeDisplayValue("Monospaced Extended");
		cmbFontFamily.setSelectedItem(prefs.getFont().getFamily());
		c.gridx = 1;
		c.fill = GridBagConstraints.NONE;
		c.weightx = 0;
		pnlFont.add(cmbFontFamily, c);
		// Spacer absorbs extra width
		c.gridx = 2;
		c.weightx = 1.0;
		c.fill = GridBagConstraints.HORIZONTAL;
		pnlFont.add(new JPanel(), c);

		c.gridx = 0;
		c.gridy = 1;
		c.fill = GridBagConstraints.NONE;
		c.weightx = 0;
		pnlFont.add(new JLabel("Size:"), c);

		cmbFontSize = new JComboBox<>(SIZES);
		cmbFontSize.setSelectedItem(prefs.getFont().getSize());
		if (cmbFontSize.getSelectedItem() == null
				|| (int) cmbFontSize.getSelectedItem() != prefs.getFont()
						.getSize()) {
			cmbFontSize.addItem(prefs.getFont().getSize());
			cmbFontSize.setSelectedItem(prefs.getFont().getSize());
		}
		cmbFontSize.setEditable(true);
		c.gridx = 1;
		c.fill = GridBagConstraints.NONE;
		c.weightx = 0;
		c.anchor = GridBagConstraints.WEST;
		pnlFont.add(cmbFontSize, c);

		// ---- color panel (two-column layout) ----
		JPanel pnlColors = new JPanel(new GridBagLayout());
		pnlColors.setBorder(BorderFactory.createTitledBorder("Colors"));
		GridBagConstraints cc = new GridBagConstraints();
		cc.insets = new Insets(3, 6, 3, 6);
		cc.anchor = GridBagConstraints.WEST;

		// Left column (gridx 0-1), rows 0-4
		btnBackground = addColorRow(pnlColors, cc, 0, 0, "Background:",
				prefs.getBackground());
		btnDefault = addColorRow(pnlColors, cc, 1, 0, "Default Text:",
				prefs.getDefaultText());
		btnNotice = addColorRow(pnlColors, cc, 2, 0, "Notice:",
				prefs.getNotice());
		btnHeading = addColorRow(pnlColors, cc, 3, 0, "Heading:",
				prefs.getHeading());
		btnContent = addColorRow(pnlColors, cc, 4, 0, "Content:",
				prefs.getContent());

		// Right column (gridx 2-3), rows 0-3
		btnKey = addColorRow(pnlColors, cc, 0, 2, "Key:",
				prefs.getKey());
		btnValue = addColorRow(pnlColors, cc, 1, 2, "Value:",
				prefs.getValue());
		btnWarning = addColorRow(pnlColors, cc, 2, 2, "Warning:",
				prefs.getWarning());
		btnSubsection = addColorRow(pnlColors, cc, 3, 2, "Subsection:",
				prefs.getSubsection());
		btnHighlight = addColorRow(pnlColors, cc, 4, 2, "Highlight:",
				prefs.getHighlight());
		// Spacer absorbs extra width
		cc.gridx = 4; cc.gridy = 0; cc.weightx = 1.0;
		cc.fill = GridBagConstraints.HORIZONTAL;
		pnlColors.add(new JPanel(), cc);

		// ---- presets panel ----
		JPanel pnlPresets = new JPanel(new GridBagLayout());
		pnlPresets.setBorder(BorderFactory.createTitledBorder("Presets"));
		GridBagConstraints pc = new GridBagConstraints();
		pc.insets = new Insets(4, 6, 4, 6);
		pc.gridy = 0;
		pc.fill = GridBagConstraints.HORIZONTAL;
		pc.weightx = 1.0;

		JButton btnSystemDefault = new JButton("System Default");
		pc.gridx = 0;
		pnlPresets.add(btnSystemDefault, pc);

		JButton btnLightDefault = new JButton("Light Default");
		pc.gridx = 1;
		pnlPresets.add(btnLightDefault, pc);

		JButton btnDarkDefault = new JButton("Dark Default");
		pc.gridx = 2;
		pnlPresets.add(btnDarkDefault, pc);

		// ---- TLS Risk Assessment panel ----
		JPanel pnlRiskColors = new JPanel(new GridBagLayout());
		pnlRiskColors.setBorder(BorderFactory.createTitledBorder("TLS Risk Assessment"));
		GridBagConstraints rc2 = new GridBagConstraints();
		rc2.insets = new Insets(3, 6, 3, 6);
		rc2.anchor = GridBagConstraints.WEST;

		btnRiskPass = addColorRow(pnlRiskColors, rc2, 0, 0, "Pass:",
				prefs.getRiskPass());
		btnRiskInconclusive = addColorRow(pnlRiskColors, rc2, 0, 2, "Inconclusive:",
				prefs.getRiskInconclusive());
		btnRiskFail = addColorRow(pnlRiskColors, rc2, 0, 4, "Fail:",
				prefs.getRiskFail());

		rc2.gridx = 0; rc2.gridy = 1;
		rc2.gridwidth = 1;
		rc2.fill = GridBagConstraints.NONE;
		rc2.weightx = 0;
		rc2.insets = new Insets(3, 6, 3, 6);
		pnlRiskColors.add(new JLabel("Scale:"), rc2);

		spnRiskScale = new JSpinner(new SpinnerNumberModel(
				Math.max(10, Math.min(50, prefs.getRiskScale())), 10, 50, 5));
		rc2.gridx = 1;
		pnlRiskColors.add(spnRiskScale, rc2);

		rc2.gridx = 2; rc2.gridwidth = 4;
		pnlRiskColors.add(new JLabel("blocks"), rc2);
		rc2.gridwidth = 1;
		// Spacer absorbs extra width
		rc2.gridx = 6; rc2.gridy = 0; rc2.weightx = 1.0;
		rc2.fill = GridBagConstraints.HORIZONTAL;
		pnlRiskColors.add(new JPanel(), rc2);

		// ---- risk priority panel ----
		JPanel pnlRiskPriority = new JPanel(new GridBagLayout());
		pnlRiskPriority.setBorder(BorderFactory.createTitledBorder("Risk Priority"));
		GridBagConstraints rpc = new GridBagConstraints();
		rpc.insets = new Insets(3, 6, 3, 6);
		rpc.anchor = GridBagConstraints.WEST;

		btnRiskCritical = addColorRow(pnlRiskPriority, rpc, 0, 0, "Critical:",
				prefs.getRiskCritical());
		btnRiskHigh = addColorRow(pnlRiskPriority, rpc, 0, 2, "High:",
				prefs.getRiskHigh());
		btnRiskMedium = addColorRow(pnlRiskPriority, rpc, 1, 0, "Medium:",
				prefs.getRiskMedium());
		btnRiskLow = addColorRow(pnlRiskPriority, rpc, 1, 2, "Low:",
				prefs.getRiskLow());
		btnRiskInfo = addColorRow(pnlRiskPriority, rpc, 2, 0, "Info:",
				prefs.getRiskInfo());
		// Spacer absorbs extra width
		rpc.gridx = 4; rpc.gridy = 0; rpc.weightx = 1.0;
		rpc.fill = GridBagConstraints.HORIZONTAL;
		pnlRiskPriority.add(new JPanel(), rpc);

		// ---- output panel ----
		JPanel pnlOutput = new JPanel(new GridBagLayout());
		pnlOutput.setBorder(BorderFactory.createTitledBorder("Output"));
		GridBagConstraints oc = new GridBagConstraints();
		oc.insets = new Insets(4, 6, 4, 6);
		oc.anchor = GridBagConstraints.WEST;
		oc.gridy = 0;

		chkHardwrap = new JCheckBox("Hard wrap lines");
		chkHardwrap.setSelected(prefs.isHardwrapEnabled());
		oc.gridx = 0;
		pnlOutput.add(chkHardwrap, oc);

		oc.gridx = 1;
		pnlOutput.add(new JLabel("Width:"), oc);

		spnHardwrapWidth = new JSpinner(new SpinnerNumberModel(
				prefs.getHardwrapWidth(), 40, 300, 10));
		spnHardwrapWidth.setEnabled(prefs.isHardwrapEnabled());
		oc.gridx = 2;
		pnlOutput.add(spnHardwrapWidth, oc);

		oc.gridx = 3;
		pnlOutput.add(new JLabel("characters"), oc);
		// Spacer absorbs extra width
		oc.gridx = 4; oc.weightx = 1.0;
		oc.fill = GridBagConstraints.HORIZONTAL;
		pnlOutput.add(new JPanel(), oc);

		// ---- card font panel ----
		JPanel pnlCardFont = new JPanel(new GridBagLayout());
		pnlCardFont.setBorder(BorderFactory.createTitledBorder("Card Font"));
		GridBagConstraints cfc = new GridBagConstraints();
		cfc.insets = new Insets(4, 6, 4, 6);

		cfc.gridx = 0; cfc.gridy = 0;
		cfc.anchor = GridBagConstraints.WEST;
		pnlCardFont.add(new JLabel("Family:"), cfc);

		cmbCardFontFamily = new JComboBox<>(families);
		cmbCardFontFamily.setRenderer(createMonoTagRenderer());
		cmbCardFontFamily.setPrototypeDisplayValue("Monospaced Extended");
		cmbCardFontFamily.setSelectedItem(prefs.getCardFont().getFamily());
		cfc.gridx = 1;
		cfc.fill = GridBagConstraints.NONE;
		cfc.weightx = 0;
		pnlCardFont.add(cmbCardFontFamily, cfc);
		// Spacer absorbs extra width
		cfc.gridx = 2;
		cfc.weightx = 1.0;
		cfc.fill = GridBagConstraints.HORIZONTAL;
		pnlCardFont.add(new JPanel(), cfc);

		cfc.gridx = 0; cfc.gridy = 1;
		cfc.fill = GridBagConstraints.NONE;
		cfc.weightx = 0;
		pnlCardFont.add(new JLabel("Size:"), cfc);

		cmbCardFontSize = new JComboBox<>(SIZES);
		cmbCardFontSize.setSelectedItem(prefs.getCardFont().getSize());
		if (cmbCardFontSize.getSelectedItem() == null
				|| (int) cmbCardFontSize.getSelectedItem() != prefs.getCardFont().getSize()) {
			cmbCardFontSize.addItem(prefs.getCardFont().getSize());
			cmbCardFontSize.setSelectedItem(prefs.getCardFont().getSize());
		}
		cmbCardFontSize.setEditable(true);
		cfc.gridx = 1;
		cfc.fill = GridBagConstraints.NONE;
		cfc.weightx = 0;
		cfc.anchor = GridBagConstraints.WEST;
		pnlCardFont.add(cmbCardFontSize, cfc);

		cfc.gridx = 0; cfc.gridy = 2;
		pnlCardFont.add(new JLabel("Grade Size:"), cfc);

		spnCardBadgeSize = new JSpinner(new SpinnerNumberModel(
				Math.max(12, Math.min(48, prefs.getCardBadgeSize())), 12, 48, 1));
		cfc.gridx = 1;
		pnlCardFont.add(spnCardBadgeSize, cfc);

		// ---- card colors panel ----
		JPanel pnlCardColors = new JPanel(new GridBagLayout());
		pnlCardColors.setBorder(BorderFactory.createTitledBorder("Colors"));
		GridBagConstraints ccc = new GridBagConstraints();
		ccc.insets = new Insets(3, 6, 3, 6);
		ccc.anchor = GridBagConstraints.WEST;

		btnCardBg = addColorRow(pnlCardColors, ccc, 0, 0, "Background:", prefs.getCardBg());
		btnCardText = addColorRow(pnlCardColors, ccc, 1, 0, "Text:", prefs.getCardText());
		btnCardDim = addColorRow(pnlCardColors, ccc, 2, 0, "Dim Text:", prefs.getCardDim());
		btnCardBorder = addColorRow(pnlCardColors, ccc, 0, 2, "Border:", prefs.getCardBorder());
		btnCardSelected = addColorRow(pnlCardColors, ccc, 1, 2, "Selected:", prefs.getCardSelected());
		btnCardError = addColorRow(pnlCardColors, ccc, 2, 2, "Error:", prefs.getCardError());
		// Spacer absorbs extra width
		ccc.gridx = 4; ccc.gridy = 0; ccc.weightx = 1.0;
		ccc.fill = GridBagConstraints.HORIZONTAL;
		pnlCardColors.add(new JPanel(), ccc);

		// ---- card layout editor (palette | grid | trash+spinners) ----
		cardMetaPalette = new CardMetaPalette();
		cardMetaPalette.updateVisibility(prefs.getCardLayout());
		JScrollPane paletteScroll = new JScrollPane(cardMetaPalette,
				JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		paletteScroll.setPreferredSize(new Dimension(140, 340));
		paletteScroll.setMinimumSize(new Dimension(140, 210));

		cardGridEditor = new CardGridEditor(prefs);
		cardTrashPanel = new CardTrashPanel(prefs);

		// Read-only preview below the editor
		cardLayoutPreview = new CardLayoutPreview(prefs);

		Runnable gridChanged = () -> {
			syncPrefsFromControls();
			cardMetaPalette.updateVisibility(cardGridEditor.getCardLayout());
			cardLayoutPreview.setCardLayout(cardGridEditor.getCardLayout());
			cardLayoutPreview.repaint();
		};
		cardGridEditor.setOnLayoutChanged(gridChanged);
		cardTrashPanel.setOnLayoutChanged(() -> {
			// Sync the grid editor with the trash panel's layout changes
			cardGridEditor.setCardLayout(cardTrashPanel.cardLayout());
			gridChanged.run();
		});
		cardTrashPanel.setOnResetClicked(() -> {
			CardLayout defLayout = CardLayout.defaultLayout();
			cardGridEditor.setCardLayout(defLayout);
			cardTrashPanel.setCardLayout(defLayout);
			cardLayoutPreview.setCardLayout(defLayout);
			cardMetaPalette.updateVisibility(defLayout);
			syncPrefsFromControls();
		});
		cardTrashPanel.setOnCardSizeChanged(() -> {
			syncPrefsFromControls();
			cardLayoutPreview.setPrefs(prefs);
		});

		JPanel editorPanel = new JPanel(new BorderLayout());
		editorPanel.add(paletteScroll, BorderLayout.WEST);
		editorPanel.add(cardGridEditor, BorderLayout.CENTER);
		editorPanel.add(cardTrashPanel, BorderLayout.EAST);

		JPanel pnlCardLayout = new JPanel(new BorderLayout());
		pnlCardLayout.setBorder(BorderFactory.createTitledBorder("Card Layout"));
		pnlCardLayout.add(editorPanel, BorderLayout.CENTER);

		JPanel pnlCardPreviewWrapper = new JPanel(new BorderLayout());
		pnlCardPreviewWrapper.setBorder(BorderFactory.createTitledBorder("Card Preview"));
		pnlCardPreviewWrapper.add(cardLayoutPreview, BorderLayout.CENTER);

		// ---- Reporting sub-tabs ----
		JTabbedPane reportingTabs = new JTabbedPane();

		// ---- preview ----
		txtPreview = new JTextPane();
		txtPreview.setEditable(false);
		JScrollPane spPreview = new JScrollPane(txtPreview);
		spPreview.setBorder(BorderFactory.createTitledBorder("Report Preview"));
		spPreview.setMinimumSize(new Dimension(200, 180));

		// Sub-tab 1: Host Detail (report font, colors, output, risk graph, presets, preview)
		JPanel pnlHostDetail = new JPanel(new GridBagLayout());
		GridBagConstraints hc = new GridBagConstraints();
		hc.fill = GridBagConstraints.HORIZONTAL;
		hc.weightx = 1.0;
		hc.gridx = 0;

		hc.gridy = 0;
		pnlHostDetail.add(pnlFont, hc);
		hc.gridy = 1;
		pnlHostDetail.add(pnlColors, hc);
		hc.gridy = 2;
		pnlHostDetail.add(pnlOutput, hc);
		hc.gridy = 3;
		pnlRiskColors.setBorder(BorderFactory.createTitledBorder("Risk Graph"));
		pnlHostDetail.add(pnlRiskColors, hc);
		hc.gridy = 4;
		pnlHostDetail.add(pnlRiskPriority, hc);
		hc.gridy = 5;
		pnlHostDetail.add(pnlPresets, hc);
		// Report Preview fills remaining space
		hc.gridy = 6;
		hc.weighty = 1.0;
		hc.fill = GridBagConstraints.BOTH;
		pnlHostDetail.add(spPreview, hc);

		reportingTabs.addTab("Host Detail", new JScrollPane(pnlHostDetail));

		// Sub-tab 2: Cards (card font, card colors, card preview)
		JPanel pnlCards = new JPanel(new GridBagLayout());
		GridBagConstraints cdc = new GridBagConstraints();
		cdc.fill = GridBagConstraints.HORIZONTAL;
		cdc.weightx = 1.0;
		cdc.gridx = 0;

		cdc.gridy = 0;
		pnlCards.add(pnlCardFont, cdc);
		cdc.gridy = 1;
		pnlCards.add(pnlCardColors, cdc);
		cdc.gridy = 2;
		cdc.fill = GridBagConstraints.BOTH;
		cdc.weighty = 0.5;
		pnlCards.add(pnlCardLayout, cdc);
		cdc.gridy = 3;
		cdc.fill = GridBagConstraints.BOTH;
		cdc.weighty = 0.5;
		pnlCards.add(pnlCardPreviewWrapper, cdc);

		reportingTabs.addTab("Cards", pnlCards);

		JPanel pnlReporting = new JPanel(new BorderLayout());
		pnlReporting.add(reportingTabs, BorderLayout.CENTER);

		// ---- Engine tab content ----
		JPanel pnlEngine = buildEngineTab();

		// ---- Application tab content ----
		JPanel pnlApplication = buildApplicationTab();

		// ---- AI tab content ----
		JPanel pnlAi = buildAiTab();

		// ---- Cipher Map tab content ----
		JPanel pnlCipherMap = buildCipherMapTab();

		// ---- User Risks tab content ----
		JPanel pnlUserRisks = buildUserRisksTab();

		// ---- tabbed pane ----
		settingsTabbedPane = new JTabbedPane();
		settingsTabbedPane.addTab("Reporting", pnlReporting);
		settingsTabbedPane.addTab("Engine", pnlEngine);
		settingsTabbedPane.addTab("AI", pnlAi);
		settingsTabbedPane.addTab("Cipher Map", pnlCipherMap);
		settingsTabbedPane.addTab("User Risks", pnlUserRisks);
		settingsTabbedPane.addTab("Application", pnlApplication);

		// ---- buttons ----
		JPanel pnlButtons = new JPanel();
		JButton btnOk = new JButton("OK");
		JButton btnResetDefaults = new JButton("Default");
		JButton btnCancel = new JButton("Cancel");
		pnlButtons.add(btnOk);
		pnlButtons.add(btnResetDefaults);
		pnlButtons.add(btnCancel);

		// ---- layout ----
		getContentPane().setLayout(new BorderLayout(5, 5));
		getContentPane().add(settingsTabbedPane, BorderLayout.CENTER);
		getContentPane().add(pnlButtons, BorderLayout.SOUTH);

		// ---- listeners ----
		cmbFontFamily.addActionListener(e -> {
			syncPrefsFromControls();
			updatePreview();
		});
		cmbFontSize.addActionListener(e -> {
			syncPrefsFromControls();
			updatePreview();
		});

		chkHardwrap.addActionListener(e -> {
			spnHardwrapWidth.setEnabled(chkHardwrap.isSelected());
			syncPrefsFromControls();
		});
		spnHardwrapWidth.addChangeListener(e -> {
			syncPrefsFromControls();
		});

		btnBackground.addActionListener(e -> pickColor(btnBackground, "Background"));
		btnDefault.addActionListener(e -> pickColor(btnDefault, "Default Text"));
		btnNotice.addActionListener(e -> pickColor(btnNotice, "Notice"));
		btnHeading.addActionListener(e -> pickColor(btnHeading, "Section Heading"));
		btnContent.addActionListener(e -> pickColor(btnContent, "Section Content"));
		btnKey.addActionListener(e -> pickColor(btnKey, "Content Key"));
		btnValue.addActionListener(e -> pickColor(btnValue, "Content Value"));
		btnWarning.addActionListener(e -> pickColor(btnWarning, "Warning"));
		btnSubsection.addActionListener(e -> pickColor(btnSubsection, "Subsection"));
		btnHighlight.addActionListener(e -> pickColor(btnHighlight, "Highlight"));
		btnRiskPass.addActionListener(e -> pickColor(btnRiskPass, "Risk Pass"));
		btnRiskInconclusive.addActionListener(e -> pickColor(btnRiskInconclusive, "Risk Inconclusive"));
		btnRiskFail.addActionListener(e -> pickColor(btnRiskFail, "Risk Fail"));
		btnRiskCritical.addActionListener(e -> pickColor(btnRiskCritical, "Risk Critical"));
		btnRiskHigh.addActionListener(e -> pickColor(btnRiskHigh, "Risk High"));
		btnRiskMedium.addActionListener(e -> pickColor(btnRiskMedium, "Risk Medium"));
		btnRiskLow.addActionListener(e -> pickColor(btnRiskLow, "Risk Low"));
		btnRiskInfo.addActionListener(e -> pickColor(btnRiskInfo, "Risk Info"));

		// Card font listeners
		cmbCardFontFamily.addActionListener(e -> {
			syncPrefsFromControls();
			updateCardPreview();
		});
		cmbCardFontSize.addActionListener(e -> {
			syncPrefsFromControls();
			updateCardPreview();
		});
		spnCardBadgeSize.addChangeListener(e -> {
			syncPrefsFromControls();
			updateCardPreview();
		});

		// Card color listeners
		btnCardBg.addActionListener(e -> pickCardColor(btnCardBg, "Card Background"));
		btnCardText.addActionListener(e -> pickCardColor(btnCardText, "Card Text"));
		btnCardDim.addActionListener(e -> pickCardColor(btnCardDim, "Card Dim Text"));
		btnCardBorder.addActionListener(e -> pickCardColor(btnCardBorder, "Card Border"));
		btnCardSelected.addActionListener(e -> pickCardColor(btnCardSelected, "Card Selected"));
		btnCardError.addActionListener(e -> pickCardColor(btnCardError, "Card Error"));

		btnResetDefaults.addActionListener(e -> {
			String tabTitle = settingsTabbedPane.getTitleAt(settingsTabbedPane.getSelectedIndex());
			if ("Reporting".equals(tabTitle)) {
				FontPreferences d = FontPreferences.defaults();
				// Font
				cmbFontFamily.setSelectedItem(d.getFont().getFamily());
				cmbFontSize.setSelectedItem(d.getFont().getSize());
				// Colors
				btnBackground.setBackground(d.getBackground());
				btnDefault.setBackground(d.getDefaultText());
				btnNotice.setBackground(d.getNotice());
				btnHeading.setBackground(d.getHeading());
				btnContent.setBackground(d.getContent());
				btnKey.setBackground(d.getKey());
				btnValue.setBackground(d.getValue());
				btnWarning.setBackground(d.getWarning());
				btnSubsection.setBackground(d.getSubsection());
				btnHighlight.setBackground(d.getHighlight());
				// Risk colors
				btnRiskPass.setBackground(d.getRiskPass());
				btnRiskInconclusive.setBackground(d.getRiskInconclusive());
				btnRiskFail.setBackground(d.getRiskFail());
				// Risk priority colors
				btnRiskCritical.setBackground(d.getRiskCritical());
				btnRiskHigh.setBackground(d.getRiskHigh());
				btnRiskMedium.setBackground(d.getRiskMedium());
				btnRiskLow.setBackground(d.getRiskLow());
				btnRiskInfo.setBackground(d.getRiskInfo());
				// Output
				chkHardwrap.setSelected(d.isHardwrapEnabled());
				spnHardwrapWidth.setValue(d.getHardwrapWidth());
				spnHardwrapWidth.setEnabled(d.isHardwrapEnabled());
				// Card font
				cmbCardFontFamily.setSelectedItem(d.getCardFont().getFamily());
				cmbCardFontSize.setSelectedItem(d.getCardFont().getSize());
				spnCardBadgeSize.setValue(d.getCardBadgeSize());
				// Card colors
				btnCardBg.setBackground(d.getCardBg());
				btnCardText.setBackground(d.getCardText());
				btnCardDim.setBackground(d.getCardDim());
				btnCardBorder.setBackground(d.getCardBorder());
				btnCardSelected.setBackground(d.getCardSelected());
				btnCardError.setBackground(d.getCardError());
				syncPrefsFromControls();
				updatePreview();
				updateCardPreview();
			} else if ("AI".equals(tabTitle)) {
				btnAiTermBg.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_BG);
				btnAiTermUserPrefix.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_USER_PREFIX);
				btnAiTermUserText.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_USER_TEXT);
				btnAiTermAiPrefix.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_AI_PREFIX);
				btnAiTermAiText.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_AI_TEXT);
				btnAiTermError.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_ERROR);
				btnAiTermSystem.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_SYSTEM);
				btnAiTermSelectionBg.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_SELECTION_BG);
				btnAiTermSelectionFg.setBackground(FontPreferences.DEFAULT_AI_TERMINAL_SELECTION_FG);
				syncPrefsFromControls();
				updateAiTerminalPreview();
			} else if ("Cipher Map".equals(tabTitle)) {
				String apiDefault = FontPreferences.loadApiDefaultCipherMapYaml();
				if (apiDefault != null) {
					txtCipherMapYaml.setText(apiDefault);
					txtCipherMapYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
					cipherMapPlaceholderActive = false;
				}
				chkCipherMapEnabled.setSelected(true);
				syncPrefsFromControls();
			} else if ("User Risks".equals(tabTitle)) {
				chkUserRiskRulesEnabled.setSelected(true);
				txtUserRiskRulesYaml.setText(FontPreferences.DEFAULT_USER_RISK_RULES);
				txtUserRiskRulesYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
				userRiskRulesPlaceholderActive = false;
				syncPrefsFromControls();
			} else if ("Application".equals(tabTitle)) {
				applyAppPreset(FontPreferences.appSystemDefaults());
			}
		});

		btnSystemDefault.addActionListener(
				e -> applyPreset(FontPreferences.systemDefaults()));
		btnLightDefault.addActionListener(
				e -> applyPreset(FontPreferences.lightDefaults()));
		btnDarkDefault.addActionListener(
				e -> applyPreset(FontPreferences.darkDefaults()));

		btnOk.addActionListener(e -> {
			approved = true;
			syncPrefsFromControls();
			// Save cipher map YAML to disk
			if (!cipherMapPlaceholderActive && !txtCipherMapYaml.getText().isBlank()) {
				FontPreferences.saveCustomCipherMapYaml(txtCipherMapYaml.getText());
			} else if (!prefs.isCustomCipherMapEnabled()) {
				FontPreferences.deleteCustomCipherMapYaml();
			}
			// Save user risk rules YAML to disk
			if (!userRiskRulesPlaceholderActive && !txtUserRiskRulesYaml.getText().isBlank()) {
				FontPreferences.saveUserRiskRulesYaml(txtUserRiskRulesYaml.getText());
			} else if (!prefs.isUserRiskRulesEnabled()) {
				FontPreferences.deleteUserRiskRulesYaml();
			}
			dispose();
		});

		btnCancel.addActionListener(e -> {
			// Revert any live app theme changes
			FontPreferences.applyAppTheme(originalPrefs);
			dispose();
		});

		getRootPane().setDefaultButton(btnOk);
		updatePreview();
		updateCardPreview();
		applyModeVisibility();
	}

	/**
	 * Hide settings panels/tabs that are not relevant in normal mode.
	 * In workbench mode everything stays visible.
	 */
	private void applyModeVisibility() {
		if (prefs.isWorkbenchMode()) {
			return;
		}
		// Normal mode: hide Report Sections, Prompts sub-tab, Cipher Map, User Risks
		pnlReportSections.setVisible(false);

		// Remove "Prompts" sub-tab from AI sub-tabs
		for (int i = aiSubTabs.getTabCount() - 1; i >= 0; i--) {
			if ("Prompts".equals(aiSubTabs.getTitleAt(i))) {
				aiSubTabs.removeTabAt(i);
				break;
			}
		}

		// Remove "Cipher Map" and "User Risks" tabs from settings
		for (int i = settingsTabbedPane.getTabCount() - 1; i >= 0; i--) {
			String title = settingsTabbedPane.getTitleAt(i);
			if ("Cipher Map".equals(title) || "User Risks".equals(title)) {
				settingsTabbedPane.removeTabAt(i);
			}
		}
	}

	private JPanel buildEngineTab() {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel pnlEngine = buildEnginePanel();

		JScrollPane spEngine = new JScrollPane(pnlEngine);
		spEngine.setBorder(null);
		panel.add(spEngine, BorderLayout.CENTER);

		return panel;
	}

	/**
	 * Build the unified engine settings panel with report sections,
	 * scanning priority, cipher convention, and protocol versions.
	 */
	private JPanel buildEnginePanel() {
		JPanel panel = new JPanel(new GridBagLayout());
		GridBagConstraints ec = new GridBagConstraints();
		ec.fill = GridBagConstraints.HORIZONTAL;
		ec.weightx = 1.0;
		ec.gridx = 0;
		ec.insets = new Insets(4, 6, 4, 6);

		// ---- Report Sections panel (two-column layout) ----
		pnlReportSections = new JPanel(new GridBagLayout());
		pnlReportSections.setBorder(BorderFactory.createTitledBorder("Report Sections"));
		GridBagConstraints rc = new GridBagConstraints();
		rc.anchor = GridBagConstraints.WEST;
		rc.insets = new Insets(2, 6, 2, 6);

		// Left column
		chkRiskAssessment = new JCheckBox("TLS risk assessment");
		chkRiskAssessment.setSelected(prefs.isSectionRiskAssessment());
		rc.gridx = 0; rc.gridy = 0;
		pnlReportSections.add(chkRiskAssessment, rc);

		chkAiEvaluation = new JCheckBox("AI evaluation");
		chkAiEvaluation.setSelected(prefs.isSectionAiEvaluation());
		boolean aiConfigured = prefs.isAiReportEnabled()
				&& ("Ollama".equalsIgnoreCase(prefs.getAiProvider())
					|| (prefs.getAiApiKey() != null && !prefs.getAiApiKey().isBlank()));
		chkAiEvaluation.setEnabled(aiConfigured);
		rc.gridx = 0; rc.gridy = 1;
		pnlReportSections.add(chkAiEvaluation, rc);

		chkRuntimeEnvironment = new JCheckBox("Runtime environment");
		chkRuntimeEnvironment.setSelected(prefs.isSectionRuntimeEnvironment());
		rc.gridx = 0; rc.gridy = 2;
		pnlReportSections.add(chkRuntimeEnvironment, rc);

		chkHost = new JCheckBox("Host information");
		chkHost.setSelected(prefs.isSectionHost());
		rc.gridx = 0; rc.gridy = 3;
		pnlReportSections.add(chkHost, rc);

		chkHttpResponse = new JCheckBox("HTTP response headers");
		chkHttpResponse.setSelected(prefs.isSectionHttpResponse());
		rc.gridx = 0; rc.gridy = 4;
		pnlReportSections.add(chkHttpResponse, rc);

		chkSecurityHeaders = new JCheckBox("Security headers");
		chkSecurityHeaders.setSelected(prefs.isSectionSecurityHeaders());
		rc.gridx = 0; rc.gridy = 5;
		pnlReportSections.add(chkSecurityHeaders, rc);

		// Right column
		rc.insets = new Insets(2, 18, 2, 6);

		chkConnection = new JCheckBox("Connection characteristics");
		chkConnection.setSelected(prefs.isSectionConnection());
		rc.gridx = 1; rc.gridy = 0;
		pnlReportSections.add(chkConnection, rc);

		chkCipherSuites = new JCheckBox("Cipher suites");
		chkCipherSuites.setSelected(prefs.isSectionCipherSuites());
		rc.gridx = 1; rc.gridy = 1;
		pnlReportSections.add(chkCipherSuites, rc);

		chkCertChain = new JCheckBox("Certificate chain");
		chkCertChain.setSelected(prefs.isSectionCertChain());
		rc.gridx = 1; rc.gridy = 2;
		pnlReportSections.add(chkCertChain, rc);

		chkRevocation = new JCheckBox("Revocation status");
		chkRevocation.setSelected(prefs.isSectionRevocation());
		rc.gridx = 1; rc.gridy = 3;
		pnlReportSections.add(chkRevocation, rc);

		chkTlsFingerprint = new JCheckBox("TLS server fingerprint");
		chkTlsFingerprint.setSelected(prefs.isSectionTlsFingerprint());
		rc.gridx = 1; rc.gridy = 4;
		pnlReportSections.add(chkTlsFingerprint, rc);
		// Spacer absorbs extra width
		rc.gridx = 2; rc.gridy = 0; rc.weightx = 1.0;
		rc.fill = GridBagConstraints.HORIZONTAL;
		rc.insets = new Insets(2, 6, 2, 6);
		pnlReportSections.add(new JPanel(), rc);
		rc.weightx = 0; rc.fill = GridBagConstraints.NONE;

		// Select All / Deselect All buttons spanning both columns
		JPanel pnlSelectBtns = new JPanel();
		JButton btnSelectAll = new JButton("Select All");
		JButton btnDeselectAll = new JButton("Deselect All");
		pnlSelectBtns.add(btnSelectAll);
		pnlSelectBtns.add(btnDeselectAll);
		rc.gridx = 0; rc.gridy = 7;
		rc.gridwidth = 2;
		rc.anchor = GridBagConstraints.CENTER;
		rc.insets = new Insets(2, 6, 2, 6);
		pnlReportSections.add(pnlSelectBtns, rc);
		rc.gridwidth = 1;

		JCheckBox[] sectionBoxes = { chkRiskAssessment, chkAiEvaluation,
				chkRuntimeEnvironment,
				chkHost, chkHttpResponse, chkSecurityHeaders, chkConnection,
				chkCipherSuites, chkCertChain, chkRevocation, chkTlsFingerprint };
		btnSelectAll.addActionListener(e -> {
			for (JCheckBox cb : sectionBoxes) {
				if (cb.isEnabled()) cb.setSelected(true);
			}
		});
		btnDeselectAll.addActionListener(e -> {
			for (JCheckBox cb : sectionBoxes) cb.setSelected(false);
		});

		ec.gridy = 0;
		panel.add(pnlReportSections, ec);

		// ---- Cipher Suite Naming panel ----
		JPanel pnlCipher = new JPanel(new GridBagLayout());
		pnlCipher.setBorder(BorderFactory.createTitledBorder("Cipher Suite Naming"));
		GridBagConstraints cpc = new GridBagConstraints();
		cpc.insets = new Insets(4, 6, 4, 6);
		cpc.anchor = GridBagConstraints.WEST;

		cpc.gridx = 0;
		cpc.gridy = 0;
		pnlCipher.add(new JLabel("Convention:"), cpc);

		String[] conventions = { "IANA", "OpenSSL", "GnuTLS", "NSS" };
		cmbCipherConvention = new JComboBox<>(conventions);
		cmbCipherConvention.setPrototypeDisplayValue("Monospaced Extended");
		cmbCipherConvention.setSelectedItem(prefs.getCipherConvention());
		cpc.gridx = 1;
		cpc.fill = GridBagConstraints.NONE;
		cpc.weightx = 0;
		pnlCipher.add(cmbCipherConvention, cpc);
		// Spacer absorbs extra width
		cpc.gridx = 2; cpc.weightx = 1.0;
		cpc.fill = GridBagConstraints.HORIZONTAL;
		pnlCipher.add(new JPanel(), cpc);

		ec.gridy = 1;
		panel.add(pnlCipher, ec);

		// ---- Protocol Versions panel (two-column layout) ----
		JPanel pnlProtocol = new JPanel(new GridBagLayout());
		pnlProtocol.setBorder(BorderFactory.createTitledBorder("Protocol Versions"));
		GridBagConstraints pc = new GridBagConstraints();
		pc.anchor = GridBagConstraints.WEST;
		pc.insets = new Insets(2, 6, 2, 6);

		// Left column
		chkSslv3 = new JCheckBox("SSLv3 (insecure)");
		chkSslv3.setSelected(prefs.isProtocolSslv3());
		pc.gridx = 0; pc.gridy = 0;
		pnlProtocol.add(chkSslv3, pc);

		chkTls10 = new JCheckBox("TLS 1.0 (deprecated)");
		chkTls10.setSelected(prefs.isProtocolTls10());
		pc.gridx = 0; pc.gridy = 1;
		pnlProtocol.add(chkTls10, pc);

		chkTls11 = new JCheckBox("TLS 1.1 (deprecated)");
		chkTls11.setSelected(prefs.isProtocolTls11());
		pc.gridx = 0; pc.gridy = 2;
		pnlProtocol.add(chkTls11, pc);

		// Right column
		pc.insets = new Insets(2, 18, 2, 6);

		chkTls12 = new JCheckBox("TLS 1.2");
		chkTls12.setSelected(prefs.isProtocolTls12());
		pc.gridx = 1; pc.gridy = 0;
		pnlProtocol.add(chkTls12, pc);

		chkTls13 = new JCheckBox("TLS 1.3");
		chkTls13.setSelected(prefs.isProtocolTls13());
		pc.gridx = 1; pc.gridy = 1;
		pnlProtocol.add(chkTls13, pc);
		// Spacer absorbs extra width
		pc.gridx = 2; pc.gridy = 0; pc.weightx = 1.0;
		pc.fill = GridBagConstraints.HORIZONTAL;
		pc.insets = new Insets(2, 6, 2, 6);
		pnlProtocol.add(new JPanel(), pc);

		ec.gridy = 2;
		panel.add(pnlProtocol, ec);

		// ---- Scanning Priority panel ----
		JPanel pnlPriority = new JPanel(new GridBagLayout());
		pnlPriority.setBorder(BorderFactory.createTitledBorder("Scanning Priority"));
		GridBagConstraints pc2 = new GridBagConstraints();
		pc2.insets = new Insets(4, 6, 4, 6);
		pc2.anchor = GridBagConstraints.WEST;

		pc2.gridx = 0; pc2.gridy = 0;
		pnlPriority.add(new JLabel("Worker Threads:"), pc2);
		spnWorkerThreads = new JSpinner(new SpinnerNumberModel(
				prefs.getWorkerThreads(), 1, 10, 1));
		pc2.gridx = 1;
		pnlPriority.add(spnWorkerThreads, pc2);

		pc2.gridx = 0; pc2.gridy = 1;
		pnlPriority.add(new JLabel("Throttle Delay:"), pc2);
		spnThrottleDelayMs = new JSpinner(new SpinnerNumberModel(
				(int) prefs.getThrottleDelayMs(), 0, 10000, 100));
		pc2.gridx = 1;
		pnlPriority.add(spnThrottleDelayMs, pc2);
		pc2.gridx = 2;
		pnlPriority.add(new JLabel("ms"), pc2);
		// Spacer absorbs extra width
		pc2.gridx = 3; pc2.gridy = 0; pc2.weightx = 1.0;
		pc2.fill = GridBagConstraints.HORIZONTAL;
		pnlPriority.add(new JPanel(), pc2);

		ec.gridy = 3;
		panel.add(pnlPriority, ec);

		// Spacer to push content to top
		ec.gridy = 4;
		ec.weighty = 1.0;
		ec.fill = GridBagConstraints.BOTH;
		panel.add(new JPanel(), ec);

		return panel;
	}

	private JPanel buildAiTab() {
		JPanel wrapper = new JPanel(new java.awt.BorderLayout());
		aiSubTabs = new JTabbedPane();

		// ============ Sub-tab 1: Configuration ============
		JPanel pnlConfig = new JPanel(new GridBagLayout());
		GridBagConstraints ac = new GridBagConstraints();
		ac.fill = GridBagConstraints.HORIZONTAL;
		ac.weightx = 1.0;
		ac.gridx = 0;
		ac.insets = new Insets(4, 6, 4, 6);

		// ---- Chat section ----
		chkAiChatEnabled = new JCheckBox("Enable AI-powered Chat");
		cmbAiChatProvider = new JComboBox<>(new String[]{ "Anthropic", "OpenAI", "Ollama" });
		lblAiChatApiKey = new JLabel("API Key:");
		txtAiChatApiKey = new JPasswordField(prefs.getAiChatApiKey(), 20);
		lblAiChatEndpointUrl = new JLabel("Endpoint URL:");
		txtAiChatEndpointUrl = new JTextField(prefs.getAiChatEndpointUrl(), 20);
		cmbAiChatModel = new JComboBox<>();
		spnAiChatMaxTokens = new JSpinner(new SpinnerNumberModel(
				prefs.getAiChatMaxTokens(), 256, 32768, 256));
		spnAiChatTemperature = new JSpinner(new SpinnerNumberModel(
				prefs.getAiChatTemperature(), 0.0, 1.0, 0.1));
		JSpinner.NumberEditor chatTempEditor = new JSpinner.NumberEditor(spnAiChatTemperature, "0.0");
		spnAiChatTemperature.setEditor(chatTempEditor);
		btnAiChatTest = new JButton("Test Chat Configuration");
		lblAiChatTestResult = new JLabel(" ");

		JPanel pnlChat = buildAiProviderSection("AI-powered Chat",
				chkAiChatEnabled, cmbAiChatProvider, lblAiChatApiKey, txtAiChatApiKey,
				lblAiChatEndpointUrl, txtAiChatEndpointUrl, cmbAiChatModel,
				spnAiChatMaxTokens, spnAiChatTemperature, btnAiChatTest, lblAiChatTestResult,
				prefs.getAiChatProvider(), prefs.getAiChatApiKey(), prefs.getAiChatEndpointUrl(),
				prefs.getAiChatModel(), prefs.isAiChatEnabled());

		ac.gridy = 0;
		pnlConfig.add(pnlChat, ac);

		// ---- Report section ----
		chkAiReportEnabled = new JCheckBox("Enable AI-powered Reports");
		cmbAiReportProvider = new JComboBox<>(new String[]{ "Anthropic", "OpenAI", "Ollama" });
		lblAiReportApiKey = new JLabel("API Key:");
		txtAiReportApiKey = new JPasswordField(prefs.getAiApiKey(), 20);
		lblAiReportEndpointUrl = new JLabel("Endpoint URL:");
		txtAiReportEndpointUrl = new JTextField(prefs.getAiEndpointUrl(), 20);
		cmbAiReportModel = new JComboBox<>();
		spnAiReportMaxTokens = new JSpinner(new SpinnerNumberModel(
				prefs.getAiMaxTokens(), 256, 32768, 256));
		spnAiReportTemperature = new JSpinner(new SpinnerNumberModel(
				prefs.getAiTemperature(), 0.0, 1.0, 0.1));
		JSpinner.NumberEditor reportTempEditor = new JSpinner.NumberEditor(spnAiReportTemperature, "0.0");
		spnAiReportTemperature.setEditor(reportTempEditor);
		btnAiReportTest = new JButton("Test Report Configuration");
		lblAiReportTestResult = new JLabel(" ");

		JPanel pnlReport = buildAiProviderSection("AI-powered Reports",
				chkAiReportEnabled, cmbAiReportProvider, lblAiReportApiKey, txtAiReportApiKey,
				lblAiReportEndpointUrl, txtAiReportEndpointUrl, cmbAiReportModel,
				spnAiReportMaxTokens, spnAiReportTemperature, btnAiReportTest, lblAiReportTestResult,
				prefs.getAiProvider(), prefs.getAiApiKey(), prefs.getAiEndpointUrl(),
				prefs.getAiModel(), prefs.isAiReportEnabled());

		ac.gridy = 1;
		pnlConfig.add(pnlReport, ac);

		// ---- Info label ----
		JLabel lblInfo = new JLabel(
				"<html>Encrypted AI keys stored locally in ~/DeepVioletTools/deepviolet.properties</html>");
		lblInfo.setFont(lblInfo.getFont().deriveFont(Font.PLAIN,
				lblInfo.getFont().getSize() - 1f));
		ac.gridy = 2;
		pnlConfig.add(lblInfo, ac);

		// Spacer to push content to top
		ac.gridy = 3;
		ac.weighty = 1.0;
		pnlConfig.add(new JPanel(), ac);

		aiSubTabs.addTab("Configuration", pnlConfig);

		// ============ Sub-tab 2: Prompts ============
		JPanel pnlPrompts = new JPanel(new GridBagLayout());
		GridBagConstraints prc = new GridBagConstraints();
		prc.fill = GridBagConstraints.BOTH;
		prc.weightx = 1.0;
		prc.gridx = 0;
		prc.insets = new Insets(4, 6, 4, 6);

		// ---- Report System Prompt panel ----
		JPanel pnlPrompt = new JPanel(new GridBagLayout());
		pnlPrompt.setBorder(BorderFactory.createTitledBorder(
				"Report System Prompt (controls AI Evaluation in scan report)"));
		GridBagConstraints tc = new GridBagConstraints();
		tc.insets = new Insets(4, 6, 4, 6);
		tc.gridx = 0;
		tc.gridy = 0;
		tc.fill = GridBagConstraints.BOTH;
		tc.weightx = 1.0;
		tc.weighty = 1.0;

		txtAiSystemPrompt = new JTextArea(prefs.getAiSystemPrompt(), 5, 40);
		txtAiSystemPrompt.setLineWrap(true);
		txtAiSystemPrompt.setWrapStyleWord(true);
		JScrollPane spPrompt = new JScrollPane(txtAiSystemPrompt);
		spPrompt.setMinimumSize(new Dimension(200, 80));
		pnlPrompt.add(spPrompt, tc);

		prc.gridy = 0;
		prc.weighty = 0.5;
		pnlPrompts.add(pnlPrompt, prc);

		// ---- Chat System Prompt panel ----
		JPanel pnlChatPrompt = new JPanel(new GridBagLayout());
		pnlChatPrompt.setBorder(BorderFactory.createTitledBorder(
				"Chat System Prompt (controls AI Assistant on main window)"));
		GridBagConstraints tc2 = new GridBagConstraints();
		tc2.insets = new Insets(4, 6, 4, 6);
		tc2.gridx = 0;
		tc2.gridy = 0;
		tc2.fill = GridBagConstraints.BOTH;
		tc2.weightx = 1.0;
		tc2.weighty = 1.0;

		txtAiChatSystemPrompt = new JTextArea(prefs.getAiChatSystemPrompt(), 5, 40);
		txtAiChatSystemPrompt.setLineWrap(true);
		txtAiChatSystemPrompt.setWrapStyleWord(true);
		JScrollPane spChatPrompt = new JScrollPane(txtAiChatSystemPrompt);
		spChatPrompt.setMinimumSize(new Dimension(200, 80));
		pnlChatPrompt.add(spChatPrompt, tc2);

		prc.gridy = 1;
		prc.weighty = 0.5;
		pnlPrompts.add(pnlChatPrompt, prc);

		aiSubTabs.addTab("Prompts", pnlPrompts);

		// ============ Sub-tab 3: Terminal Colors ============
		JPanel pnlAiTermColors = new JPanel(new GridBagLayout());
		pnlAiTermColors.setBorder(BorderFactory.createTitledBorder("Terminal Colors"));
		GridBagConstraints atc = new GridBagConstraints();
		atc.insets = new Insets(3, 6, 3, 6);
		atc.anchor = GridBagConstraints.WEST;

		// Column headers
		atc.gridx = 0; atc.gridy = 0; atc.gridwidth = 2;
		pnlAiTermColors.add(new JLabel("  System"), atc);
		atc.gridx = 2; atc.gridwidth = 2;
		pnlAiTermColors.add(new JLabel("  User"), atc);
		atc.gridx = 4; atc.gridwidth = 2;
		pnlAiTermColors.add(new JLabel("  AI"), atc);
		atc.gridwidth = 1;

		// Row 1
		btnAiTermBg = addColorRow(pnlAiTermColors, atc, 1, 0, "Background:",
				prefs.getAiTerminalBg());
		btnAiTermUserPrefix = addColorRow(pnlAiTermColors, atc, 1, 2, "Prefix:",
				prefs.getAiTerminalUserPrefix());
		btnAiTermAiPrefix = addColorRow(pnlAiTermColors, atc, 1, 4, "Prefix:",
				prefs.getAiTerminalAiPrefix());

		// Row 2
		btnAiTermSystem = addColorRow(pnlAiTermColors, atc, 2, 0, "System:",
				prefs.getAiTerminalSystem());
		btnAiTermUserText = addColorRow(pnlAiTermColors, atc, 2, 2, "Text:",
				prefs.getAiTerminalUserText());
		btnAiTermAiText = addColorRow(pnlAiTermColors, atc, 2, 4, "Text:",
				prefs.getAiTerminalAiText());

		// Row 3
		btnAiTermSelectionBg = addColorRow(pnlAiTermColors, atc, 3, 0, "Select Bg:",
				prefs.getAiTerminalSelectionBg());
		btnAiTermError = addColorRow(pnlAiTermColors, atc, 3, 2, "Error:",
				prefs.getAiTerminalError());

		// Row 4
		btnAiTermSelectionFg = addColorRow(pnlAiTermColors, atc, 4, 0, "Select Fg:",
				prefs.getAiTerminalSelectionFg());
		// Spacer absorbs extra width
		atc.gridx = 6; atc.gridy = 0; atc.weightx = 1.0;
		atc.fill = GridBagConstraints.HORIZONTAL;
		pnlAiTermColors.add(new JPanel(), atc);

		// Preview terminal
		TerminalView aiPreviewView = new TerminalView();
		aiPreviewTerminal = aiPreviewView.getTerminal();
		aiPreviewTerminal.setWordWrap(true);
		aiPreviewTerminal.setReadOnly(true);
		aiPreviewTerminal.setCharRenderDelay(0);
		aiPreviewTerminal.setAutoFollowEnabled(true);
		JPanel pnlPreview = new JPanel(new BorderLayout());
		pnlPreview.setBorder(BorderFactory.createTitledBorder("Preview"));
		pnlPreview.add(aiPreviewView, BorderLayout.CENTER);
		pnlPreview.setMinimumSize(new Dimension(200, 120));

		// Split pane: colors on top, preview on bottom
		JSplitPane splitColors = new JSplitPane(
				JSplitPane.VERTICAL_SPLIT, pnlAiTermColors, pnlPreview);
		splitColors.setResizeWeight(0.4);
		splitColors.setDividerSize(6);
		splitColors.setContinuousLayout(true);

		aiSubTabs.addTab("Terminal Colors", splitColors);

		// ============ Listeners ============
		// Chat section listeners
		setSectionControlsEnabled(chkAiChatEnabled.isSelected(),
				cmbAiChatProvider, txtAiChatApiKey, txtAiChatEndpointUrl,
				cmbAiChatModel, spnAiChatMaxTokens, spnAiChatTemperature, btnAiChatTest);
		chkAiChatEnabled.addActionListener(e -> setSectionControlsEnabled(
				chkAiChatEnabled.isSelected(),
				cmbAiChatProvider, txtAiChatApiKey, txtAiChatEndpointUrl,
				cmbAiChatModel, spnAiChatMaxTokens, spnAiChatTemperature, btnAiChatTest));
		wireProviderListener(cmbAiChatProvider, lblAiChatApiKey, txtAiChatApiKey,
				lblAiChatEndpointUrl, txtAiChatEndpointUrl, cmbAiChatModel, "chat");
		btnAiChatTest.addActionListener(e -> runAiConnectionTest(
				txtAiChatApiKey, cmbAiChatProvider, cmbAiChatModel,
				txtAiChatEndpointUrl, btnAiChatTest, lblAiChatTestResult, chkAiChatEnabled));

		// Report section listeners
		setSectionControlsEnabled(chkAiReportEnabled.isSelected(),
				cmbAiReportProvider, txtAiReportApiKey, txtAiReportEndpointUrl,
				cmbAiReportModel, spnAiReportMaxTokens, spnAiReportTemperature, btnAiReportTest);
		chkAiReportEnabled.addActionListener(e -> {
			setSectionControlsEnabled(chkAiReportEnabled.isSelected(),
					cmbAiReportProvider, txtAiReportApiKey, txtAiReportEndpointUrl,
					cmbAiReportModel, spnAiReportMaxTokens, spnAiReportTemperature, btnAiReportTest);
			updateAiEvaluationCheckbox();
		});
		wireProviderListener(cmbAiReportProvider, lblAiReportApiKey, txtAiReportApiKey,
				lblAiReportEndpointUrl, txtAiReportEndpointUrl, cmbAiReportModel, "report");
		btnAiReportTest.addActionListener(e -> runAiConnectionTest(
				txtAiReportApiKey, cmbAiReportProvider, cmbAiReportModel,
				txtAiReportEndpointUrl, btnAiReportTest, lblAiReportTestResult, chkAiReportEnabled));

		btnAiTermBg.addActionListener(e -> pickColor(btnAiTermBg, "Terminal Background"));
		btnAiTermUserPrefix.addActionListener(e -> pickColor(btnAiTermUserPrefix, "User Prefix Color"));
		btnAiTermUserText.addActionListener(e -> pickColor(btnAiTermUserText, "User Text Color"));
		btnAiTermAiPrefix.addActionListener(e -> pickColor(btnAiTermAiPrefix, "AI Prefix Color"));
		btnAiTermAiText.addActionListener(e -> pickColor(btnAiTermAiText, "AI Text Color"));
		btnAiTermError.addActionListener(e -> pickColor(btnAiTermError, "Error Color"));
		btnAiTermSystem.addActionListener(e -> pickColor(btnAiTermSystem, "System Color"));
		btnAiTermSelectionBg.addActionListener(e -> pickColor(btnAiTermSelectionBg, "Selection Background"));
		btnAiTermSelectionFg.addActionListener(e -> pickColor(btnAiTermSelectionFg, "Selection Foreground"));

		updateAiTerminalPreview();

		wrapper.add(aiSubTabs, java.awt.BorderLayout.CENTER);
		return wrapper;
	}

	/**
	 * Build one AI provider section panel (used for both Chat and Report).
	 */
	private JPanel buildAiProviderSection(String title,
			JCheckBox chk, JComboBox<String> cmbProvider,
			JLabel lblKey, JPasswordField txtKey,
			JLabel lblEndpoint, JTextField txtEndpoint,
			JComboBox<String> cmbModel,
			JSpinner spnTokens, JSpinner spnTemp,
			JButton btnTest, JLabel lblResult,
			String savedProvider, String savedApiKey, String savedEndpoint,
			String savedModel, boolean savedEnabled) {

		JPanel section = new JPanel(new GridBagLayout());
		section.setBorder(BorderFactory.createTitledBorder(title));
		GridBagConstraints pc = new GridBagConstraints();
		pc.insets = new Insets(3, 6, 3, 6);
		pc.anchor = GridBagConstraints.WEST;

		// Row 0: Checkbox
		pc.gridx = 0; pc.gridy = 0; pc.gridwidth = 4;
		chk.setSelected(savedEnabled);
		section.add(chk, pc);
		pc.gridwidth = 1;
		// Spacer absorbs extra width
		pc.gridx = 4; pc.weightx = 1.0;
		pc.fill = GridBagConstraints.HORIZONTAL;
		section.add(new JPanel(), pc);
		pc.weightx = 0; pc.fill = GridBagConstraints.NONE;

		// Row 1: Provider
		pc.gridx = 0; pc.gridy = 1;
		section.add(new JLabel("Provider:"), pc);
		cmbProvider.setPrototypeDisplayValue("Monospaced Extended");
		cmbProvider.setSelectedItem(savedProvider);
		pc.gridx = 1; pc.gridwidth = 3;
		section.add(cmbProvider, pc);
		pc.gridwidth = 1;

		// Row 2: API Key / Endpoint
		pc.gridx = 0; pc.gridy = 2;
		section.add(lblKey, pc);
		txtKey.setColumns(20);
		pc.gridx = 1; pc.gridwidth = 3;
		section.add(txtKey, pc);
		pc.gridwidth = 1;

		pc.gridx = 0; pc.gridy = 3;
		section.add(lblEndpoint, pc);
		txtEndpoint.setColumns(20);
		pc.gridx = 1; pc.gridwidth = 3;
		section.add(txtEndpoint, pc);
		pc.gridwidth = 1;

		boolean isOllama = "Ollama".equalsIgnoreCase(savedProvider);
		lblKey.setVisible(!isOllama);
		txtKey.setVisible(!isOllama);
		lblEndpoint.setVisible(isOllama);
		txtEndpoint.setVisible(isOllama);

		// Row 4: Model
		pc.gridx = 0; pc.gridy = 4; pc.fill = GridBagConstraints.NONE; pc.weightx = 0;
		section.add(new JLabel("Model:"), pc);

		AiProvider currentProvider = AiProvider.fromDisplayName(savedProvider);
		String[] defaultModels = currentProvider.getDefaultModels();
		for (String m : defaultModels) cmbModel.addItem(m);
		cmbModel.setSelectedItem(savedModel);

		// Fetch actual models from provider on dialog open
		{
			IAiAnalysisService aiService = DeepVioletFactory.getAiService();
			String threadPrefix = title.contains("Chat") ? "chat" : "report";
			String threadName;
			java.util.function.Supplier<String[]> fetcher;
			if (currentProvider == AiProvider.OLLAMA) {
				threadName = threadPrefix + "-ollama-model-fetch-init";
				fetcher = () -> aiService.fetchModels(AiProvider.OLLAMA, null, savedEndpoint);
			} else if (currentProvider == AiProvider.ANTHROPIC) {
				threadName = threadPrefix + "-anthropic-model-fetch-init";
				fetcher = () -> aiService.fetchModels(AiProvider.ANTHROPIC, savedApiKey, null);
			} else {
				threadName = threadPrefix + "-openai-model-fetch-init";
				fetcher = () -> aiService.fetchModels(AiProvider.OPENAI, savedApiKey, null);
			}
			new Thread(() -> {
				String[] models = fetcher.get();
				javax.swing.SwingUtilities.invokeLater(() -> {
					cmbModel.removeAllItems();
					for (String m : models) cmbModel.addItem(m);
					if (savedModel != null && !savedModel.isEmpty()) {
						cmbModel.setSelectedItem(savedModel);
					}
				});
			}, threadName).start();
		}

		pc.gridx = 1;
		section.add(cmbModel, pc);

		// Row 5: Max Tokens + Temperature side by side
		pc.gridx = 0; pc.gridy = 5;
		section.add(new JLabel("Max Tokens:"), pc);
		pc.gridx = 1;
		section.add(spnTokens, pc);

		pc.gridx = 2;
		section.add(new JLabel("Temperature:"), pc);
		pc.gridx = 3;
		section.add(spnTemp, pc);

		// Row 6: Test button and result
		pc.gridx = 0; pc.gridy = 6;
		section.add(btnTest, pc);
		pc.gridx = 1; pc.gridwidth = 3;
		section.add(lblResult, pc);
		pc.gridwidth = 1;

		return section;
	}

	private void setSectionControlsEnabled(boolean enabled,
			JComboBox<String> cmbProvider, JPasswordField txtKey, JTextField txtEndpoint,
			JComboBox<String> cmbModel, JSpinner spnTokens, JSpinner spnTemp, JButton btnTest) {
		cmbProvider.setEnabled(enabled);
		txtKey.setEnabled(enabled);
		txtEndpoint.setEnabled(enabled);
		cmbModel.setEnabled(enabled);
		spnTokens.setEnabled(enabled);
		spnTemp.setEnabled(enabled);
		btnTest.setEnabled(enabled);
	}

	private void wireProviderListener(JComboBox<String> cmbProvider,
			JLabel lblKey, JPasswordField txtKey,
			JLabel lblEndpoint, JTextField txtEndpoint,
			JComboBox<String> cmbModel, String section) {
		cmbProvider.addActionListener(e -> {
			String selected = (String) cmbProvider.getSelectedItem();
			AiProvider p = AiProvider.fromDisplayName(selected);
			boolean ollama = (p == AiProvider.OLLAMA);
			lblKey.setVisible(!ollama);
			txtKey.setVisible(!ollama);
			lblEndpoint.setVisible(ollama);
			txtEndpoint.setVisible(ollama);
			String threadName = section + "-" + selected.toLowerCase() + "-model-fetch";
			IAiAnalysisService aiService = DeepVioletFactory.getAiService();
			java.util.function.Supplier<String[]> fetcher;
			if (ollama) {
				fetcher = () -> aiService.fetchModels(AiProvider.OLLAMA, null, txtEndpoint.getText());
			} else if (p == AiProvider.ANTHROPIC) {
				fetcher = () -> aiService.fetchModels(AiProvider.ANTHROPIC, new String(txtKey.getPassword()), null);
			} else {
				fetcher = () -> aiService.fetchModels(AiProvider.OPENAI, new String(txtKey.getPassword()), null);
			}
			new Thread(() -> {
				String[] models = fetcher.get();
				javax.swing.SwingUtilities.invokeLater(() -> {
					cmbModel.removeAllItems();
					for (String m : models) cmbModel.addItem(m);
				});
			}, threadName).start();
			if ("report".equals(section)) {
				updateAiEvaluationCheckbox();
			}
		});
	}

	private void updateAiEvaluationCheckbox() {
		boolean enabled = chkAiReportEnabled.isSelected();
		String provider = (String) cmbAiReportProvider.getSelectedItem();
		boolean isOllama = "Ollama".equalsIgnoreCase(provider);
		boolean hasKey = txtAiReportApiKey.getPassword().length > 0;
		if (enabled && (isOllama || hasKey)) {
			chkAiEvaluation.setEnabled(true);
			chkAiEvaluation.setSelected(true);
		} else {
			chkAiEvaluation.setEnabled(false);
			chkAiEvaluation.setSelected(false);
		}
	}

	private void runAiConnectionTest(JPasswordField txtKey, JComboBox<String> cmbProvider,
			JComboBox<String> cmbModel, JTextField txtEndpoint,
			JButton btnTest, JLabel lblResult, JCheckBox chkEnabled) {
		String apiKey = new String(txtKey.getPassword());
		String provider = (String) cmbProvider.getSelectedItem();
		String model = (String) cmbModel.getSelectedItem();
		String endpointUrl = txtEndpoint.getText();
		boolean isOllama = "Ollama".equalsIgnoreCase(provider);

		if (!isOllama && apiKey.isBlank()) {
			lblResult.setForeground(java.awt.Color.RED);
			lblResult.setText("API key is required");
			return;
		}

		btnTest.setEnabled(false);
		lblResult.setForeground(java.awt.Color.GRAY);
		lblResult.setText("Testing...");

		new Thread(() -> {
			try {
				AiConfig config = AiConfig.builder()
						.provider(AiProvider.fromDisplayName(provider))
						.apiKey(apiKey)
						.model(model)
						.maxTokens(32)
						.temperature(0.0)
						.systemPrompt("You are a connectivity test. Respond with exactly the word 'operational' and nothing else.")
						.endpointUrl(endpointUrl)
						.build();

				IAiAnalysisService aiService = DeepVioletFactory.getAiService();
				java.io.InputStream testStream = new java.io.ByteArrayInputStream(
						"Respond with the single word: operational".getBytes(java.nio.charset.StandardCharsets.UTF_8));
				String response = aiService.analyze(testStream, config);

				boolean ok = response.toLowerCase().contains("operational");
				javax.swing.SwingUtilities.invokeLater(() -> {
					btnTest.setEnabled(chkEnabled.isSelected());
					if (ok) {
						lblResult.setForeground(new java.awt.Color(0x1A, 0x7F, 0x37));
						lblResult.setText("Connected - " + provider + " / " + model);
					} else {
						lblResult.setForeground(java.awt.Color.ORANGE);
						lblResult.setText("Unexpected response: " + response.substring(0, Math.min(60, response.length())));
					}
				});
			} catch (AiAnalysisException ex) {
				javax.swing.SwingUtilities.invokeLater(() -> {
					btnTest.setEnabled(chkEnabled.isSelected());
					lblResult.setForeground(java.awt.Color.RED);
					lblResult.setText("Failed: " + ex.getMessage());
				});
			}
		}, "ai-config-test").start();
	}

	private JPanel buildApplicationTab() {
		JPanel panel = new JPanel(new GridBagLayout());
		GridBagConstraints ac = new GridBagConstraints();
		ac.fill = GridBagConstraints.HORIZONTAL;
		ac.weightx = 1.0;
		ac.gridx = 0;
		ac.insets = new Insets(4, 6, 4, 6);

		// ---- General panel ----
		JPanel pnlGeneral = new JPanel(new GridBagLayout());
		pnlGeneral.setBorder(BorderFactory.createTitledBorder("General"));
		GridBagConstraints gc = new GridBagConstraints();
		gc.gridx = 0;
		gc.gridy = 0;
		gc.anchor = GridBagConstraints.WEST;
		gc.fill = GridBagConstraints.NONE;
		gc.weightx = 0;
		gc.insets = new Insets(4, 6, 4, 6);
		chkSuppressSaveWarning = new JCheckBox("Suppress Save Scan Warning",
				prefs.isSuppressSaveWarning());
		pnlGeneral.add(chkSuppressSaveWarning, gc);
		// Spacer absorbs extra width
		gc.gridx = 1;
		gc.weightx = 1.0;
		gc.fill = GridBagConstraints.HORIZONTAL;
		pnlGeneral.add(new JPanel(), gc);

		ac.gridy = 0;
		panel.add(pnlGeneral, ac);

		// ---- Font panel ----
		JPanel pnlAppFont = new JPanel(new GridBagLayout());
		pnlAppFont.setBorder(BorderFactory.createTitledBorder("Application UI Font"));
		GridBagConstraints fc = new GridBagConstraints();
		fc.insets = new Insets(4, 6, 4, 6);

		fc.gridx = 0;
		fc.gridy = 0;
		fc.anchor = GridBagConstraints.WEST;
		pnlAppFont.add(new JLabel("Family:"), fc);

		String[] families = GraphicsEnvironment.getLocalGraphicsEnvironment()
				.getAvailableFontFamilyNames();
		cmbAppFontFamily = new JComboBox<>(families);
		cmbAppFontFamily.setRenderer(createMonoTagRenderer());
		cmbAppFontFamily.setPrototypeDisplayValue("Monospaced Extended");
		cmbAppFontFamily.setSelectedItem(prefs.getAppFont().getFamily());
		fc.gridx = 1;
		fc.fill = GridBagConstraints.NONE;
		fc.weightx = 0;
		pnlAppFont.add(cmbAppFontFamily, fc);
		// Spacer absorbs extra width
		fc.gridx = 2;
		fc.weightx = 1.0;
		fc.fill = GridBagConstraints.HORIZONTAL;
		pnlAppFont.add(new JPanel(), fc);

		fc.gridx = 0;
		fc.gridy = 1;
		fc.fill = GridBagConstraints.NONE;
		fc.weightx = 0;
		pnlAppFont.add(new JLabel("Size:"), fc);

		cmbAppFontSize = new JComboBox<>(SIZES);
		cmbAppFontSize.setSelectedItem(prefs.getAppFont().getSize());
		if (cmbAppFontSize.getSelectedItem() == null
				|| (int) cmbAppFontSize.getSelectedItem() != prefs.getAppFont().getSize()) {
			cmbAppFontSize.addItem(prefs.getAppFont().getSize());
			cmbAppFontSize.setSelectedItem(prefs.getAppFont().getSize());
		}
		cmbAppFontSize.setEditable(true);
		fc.gridx = 1;
		fc.fill = GridBagConstraints.NONE;
		fc.weightx = 0;
		fc.anchor = GridBagConstraints.WEST;
		pnlAppFont.add(cmbAppFontSize, fc);

		ac.gridy = 1;
		panel.add(pnlAppFont, ac);

		// ---- Colors panel ----
		JPanel pnlAppColors = new JPanel(new GridBagLayout());
		pnlAppColors.setBorder(BorderFactory.createTitledBorder("Colors"));
		GridBagConstraints cc = new GridBagConstraints();
		cc.insets = new Insets(3, 6, 3, 6);
		cc.anchor = GridBagConstraints.WEST;

		btnAppBg = addColorRow(pnlAppColors, cc, 0, 0, "Window Bg:",
				prefs.getAppBackground());
		btnAppButtonBg = addColorRow(pnlAppColors, cc, 0, 2, "Button Bg:",
				prefs.getAppButtonBg());
		btnAppFg = addColorRow(pnlAppColors, cc, 1, 0, "Window Fg:",
				prefs.getAppForeground());
		btnAppButtonFg = addColorRow(pnlAppColors, cc, 1, 2, "Button Fg:",
				prefs.getAppButtonFg());
		// Spacer absorbs extra width
		cc.gridx = 4; cc.gridy = 0; cc.weightx = 1.0;
		cc.fill = GridBagConstraints.HORIZONTAL;
		pnlAppColors.add(new JPanel(), cc);

		ac.gridy = 2;
		panel.add(pnlAppColors, ac);

		// ---- Presets panel ----
		JPanel pnlAppPresets = new JPanel(new GridBagLayout());
		pnlAppPresets.setBorder(BorderFactory.createTitledBorder("Presets"));
		GridBagConstraints apc = new GridBagConstraints();
		apc.insets = new Insets(4, 6, 4, 6);
		apc.gridy = 0;
		apc.fill = GridBagConstraints.HORIZONTAL;
		apc.weightx = 1.0;

		JButton btnAppSystem = new JButton("System");
		apc.gridx = 0;
		pnlAppPresets.add(btnAppSystem, apc);

		JButton btnAppLight = new JButton("Light");
		apc.gridx = 1;
		pnlAppPresets.add(btnAppLight, apc);

		JButton btnAppDark = new JButton("Dark");
		apc.gridx = 2;
		pnlAppPresets.add(btnAppDark, apc);

		ac.gridy = 3;
		panel.add(pnlAppPresets, ac);

		// Spacer
		ac.gridy = 4;
		ac.weighty = 1.0;
		ac.fill = GridBagConstraints.BOTH;
		panel.add(new JPanel(), ac);

		// ---- Listeners ----
		chkSuppressSaveWarning.addActionListener(e -> syncPrefsFromControls());
		cmbAppFontFamily.addActionListener(e -> {
			if (applyingTheme) return;
			prefs.setAppThemeCustom(true);
			syncPrefsFromControls();
			applyThemeAndRefresh();
		});
		cmbAppFontSize.addActionListener(e -> {
			if (applyingTheme) return;
			prefs.setAppThemeCustom(true);
			syncPrefsFromControls();
			applyThemeAndRefresh();
		});

		btnAppBg.addActionListener(e -> pickAppColor(btnAppBg, "Window Background"));
		btnAppFg.addActionListener(e -> pickAppColor(btnAppFg, "Window Foreground"));
		btnAppButtonBg.addActionListener(e -> pickAppColor(btnAppButtonBg, "Button Background"));
		btnAppButtonFg.addActionListener(e -> pickAppColor(btnAppButtonFg, "Button Foreground"));

		btnAppSystem.addActionListener(e -> applyAppPreset(FontPreferences.appSystemDefaults()));
		btnAppLight.addActionListener(e -> applyAppPreset(FontPreferences.appLightDefaults()));
		btnAppDark.addActionListener(e -> applyAppPreset(FontPreferences.appDarkDefaults()));

		return panel;
	}

	private static final String CIPHER_MAP_PLACEHOLDER =
			"metadata:\n"
			+ "  version: \"1.0\"\n"
			+ "  description: \"Custom cipher suite map\"\n"
			+ "cipher_suites:\n"
			+ "  - id: \"0x13,0x01\"\n"
			+ "    names:\n"
			+ "      IANA: \"TLS_AES_128_GCM_SHA256\"\n"
			+ "      OpenSSL: \"AEAD-AES128-GCM-SHA256\"\n"
			+ "    strength: STRONG\n"
			+ "    tls_versions: [\"TLSv1.3\"]\n"
			+ "  - id: \"0x00,0x2F\"\n"
			+ "    names:\n"
			+ "      IANA: \"TLS_RSA_WITH_AES_128_CBC_SHA\"\n"
			+ "    strength: MEDIUM\n"
			+ "    tls_versions: [\"TLSv1.2\"]\n";

	private static final String USER_RISK_RULES_PLACEHOLDER =
			"# Example: add your own rules using ${var} meta interpolation\n"
			+ "categories:\n"
			+ "  CUSTOM_CATEGORY:\n"
			+ "    display_name: \"My Custom Rules\"\n"
			+ "    rules:\n"
			+ "      my_custom_rule:\n"
			+ "        id: USR-0100001\n"
			+ "        description: \"Key size ${key_size} bits is too small\"\n"
			+ "        score: 0.7\n"
			+ "        when: cert.key_size < 2048\n"
			+ "        meta:\n"
			+ "          key_size: cert.key_size\n"
			+ "        enabled: true\n";

	private JPanel buildCipherMapTab() {
		JPanel panel = new JPanel(new BorderLayout(6, 6));
		panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

		// Enable checkbox
		chkCipherMapEnabled = new JCheckBox("Enable custom cipher map (replaces built-in)");
		chkCipherMapEnabled.setSelected(prefs.isCustomCipherMapEnabled());
		panel.add(chkCipherMapEnabled, BorderLayout.NORTH);

		// YAML text area
		txtCipherMapYaml = new JTextArea();
		txtCipherMapYaml.setFont(prefs.getAppFont());
		txtCipherMapYaml.setTabSize(2);

		// Load saved content, fall back to API default, then placeholder
		String saved = FontPreferences.loadCustomCipherMapYaml();
		if (saved != null && !saved.isBlank()) {
			txtCipherMapYaml.setText(saved);
			cipherMapPlaceholderActive = false;
		} else {
			String apiDefault = FontPreferences.loadApiDefaultCipherMapYaml();
			if (apiDefault != null) {
				txtCipherMapYaml.setText(apiDefault);
				cipherMapPlaceholderActive = false;
			} else {
				setCipherMapPlaceholder();
			}
		}

		// Placeholder focus listeners
		txtCipherMapYaml.addFocusListener(new java.awt.event.FocusAdapter() {
			@Override
			public void focusGained(java.awt.event.FocusEvent e) {
				if (cipherMapPlaceholderActive) {
					txtCipherMapYaml.setText("");
					txtCipherMapYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
					cipherMapPlaceholderActive = false;
				}
			}
			@Override
			public void focusLost(java.awt.event.FocusEvent e) {
				if (txtCipherMapYaml.getText().isBlank()) {
					setCipherMapPlaceholder();
				}
			}
		});

		JScrollPane scrollYaml = new JScrollPane(txtCipherMapYaml);
		panel.add(scrollYaml, BorderLayout.CENTER);

		// Buttons
		JPanel pnlButtons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 6, 4));
		JButton btnLoadFile = new JButton("Load File");
		JButton btnSaveToFile = new JButton("Save to File");
		JButton btnDefault = new JButton("Default");
		pnlButtons.add(btnLoadFile);
		pnlButtons.add(btnSaveToFile);
		pnlButtons.add(btnDefault);
		panel.add(pnlButtons, BorderLayout.SOUTH);

		btnLoadFile.addActionListener(e -> {
			JFileChooser fc = new JFileChooser();
			fc.setFileFilter(new FileNameExtensionFilter("YAML files", "yaml", "yml"));
			if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
				try {
					String content = java.nio.file.Files.readString(
							fc.getSelectedFile().toPath(), java.nio.charset.StandardCharsets.UTF_8);
					txtCipherMapYaml.setText(content);
					txtCipherMapYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
					cipherMapPlaceholderActive = false;
					chkCipherMapEnabled.setSelected(true);
				} catch (java.io.IOException ex) {
					javax.swing.JOptionPane.showMessageDialog(this,
							"Failed to read file: " + ex.getMessage(),
							"Error", javax.swing.JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		btnSaveToFile.addActionListener(e -> {
			if (cipherMapPlaceholderActive || txtCipherMapYaml.getText().isBlank()) return;
			JFileChooser fc = new JFileChooser();
			fc.setFileFilter(new FileNameExtensionFilter("YAML files", "yaml", "yml"));
			fc.setSelectedFile(new java.io.File("custom-ciphermap.yaml"));
			if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
				try {
					java.nio.file.Files.writeString(
							fc.getSelectedFile().toPath(), txtCipherMapYaml.getText(),
							java.nio.charset.StandardCharsets.UTF_8);
				} catch (java.io.IOException ex) {
					javax.swing.JOptionPane.showMessageDialog(this,
							"Failed to write file: " + ex.getMessage(),
							"Error", javax.swing.JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		btnDefault.addActionListener(e -> {
			String apiDefault = FontPreferences.loadApiDefaultCipherMapYaml();
			if (apiDefault != null) {
				txtCipherMapYaml.setText(apiDefault);
				txtCipherMapYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
				cipherMapPlaceholderActive = false;
				chkCipherMapEnabled.setSelected(true);
			}
		});

		return panel;
	}

	private void setCipherMapPlaceholder() {
		txtCipherMapYaml.setText(CIPHER_MAP_PLACEHOLDER);
		txtCipherMapYaml.setForeground(Color.GRAY);
		cipherMapPlaceholderActive = true;
	}

	private JPanel buildUserRisksTab() {
		JPanel panel = new JPanel(new BorderLayout(6, 6));
		panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

		// Enable checkbox
		chkUserRiskRulesEnabled = new JCheckBox("Enable user risk rules (merged with system rules)");
		chkUserRiskRulesEnabled.setSelected(prefs.isUserRiskRulesEnabled());
		panel.add(chkUserRiskRulesEnabled, BorderLayout.NORTH);

		// YAML text area
		txtUserRiskRulesYaml = new JTextArea();
		txtUserRiskRulesYaml.setFont(prefs.getAppFont());
		txtUserRiskRulesYaml.setTabSize(2);

		// Load saved content or show placeholder
		String saved = FontPreferences.loadUserRiskRulesYaml();
		if (saved != null && !saved.isBlank()) {
			txtUserRiskRulesYaml.setText(saved);
			userRiskRulesPlaceholderActive = false;
		} else {
			setUserRiskRulesPlaceholder();
		}

		// Placeholder focus listeners
		txtUserRiskRulesYaml.addFocusListener(new java.awt.event.FocusAdapter() {
			@Override
			public void focusGained(java.awt.event.FocusEvent e) {
				if (userRiskRulesPlaceholderActive) {
					txtUserRiskRulesYaml.setText("");
					txtUserRiskRulesYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
					userRiskRulesPlaceholderActive = false;
				}
			}
			@Override
			public void focusLost(java.awt.event.FocusEvent e) {
				if (txtUserRiskRulesYaml.getText().isBlank()) {
					setUserRiskRulesPlaceholder();
				}
			}
		});

		JScrollPane scrollYaml = new JScrollPane(txtUserRiskRulesYaml);
		panel.add(scrollYaml, BorderLayout.CENTER);

		// Buttons
		JPanel pnlButtons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 6, 4));
		JButton btnLoadFile = new JButton("Load File");
		JButton btnSaveToFile = new JButton("Save to File");
		JButton btnClear = new JButton("Clear");
		pnlButtons.add(btnLoadFile);
		pnlButtons.add(btnSaveToFile);
		pnlButtons.add(btnClear);
		panel.add(pnlButtons, BorderLayout.SOUTH);

		btnLoadFile.addActionListener(e -> {
			JFileChooser fc = new JFileChooser();
			fc.setFileFilter(new FileNameExtensionFilter("YAML files", "yaml", "yml"));
			if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
				try {
					String content = java.nio.file.Files.readString(
							fc.getSelectedFile().toPath(), java.nio.charset.StandardCharsets.UTF_8);
					txtUserRiskRulesYaml.setText(content);
					txtUserRiskRulesYaml.setForeground(javax.swing.UIManager.getColor("TextArea.foreground"));
					userRiskRulesPlaceholderActive = false;
					chkUserRiskRulesEnabled.setSelected(true);
				} catch (java.io.IOException ex) {
					javax.swing.JOptionPane.showMessageDialog(this,
							"Failed to read file: " + ex.getMessage(),
							"Error", javax.swing.JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		btnSaveToFile.addActionListener(e -> {
			if (userRiskRulesPlaceholderActive || txtUserRiskRulesYaml.getText().isBlank()) return;
			JFileChooser fc = new JFileChooser();
			fc.setFileFilter(new FileNameExtensionFilter("YAML files", "yaml", "yml"));
			fc.setSelectedFile(new java.io.File("user-riskrules.yaml"));
			if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
				try {
					java.nio.file.Files.writeString(
							fc.getSelectedFile().toPath(), txtUserRiskRulesYaml.getText(),
							java.nio.charset.StandardCharsets.UTF_8);
				} catch (java.io.IOException ex) {
					javax.swing.JOptionPane.showMessageDialog(this,
							"Failed to write file: " + ex.getMessage(),
							"Error", javax.swing.JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		btnClear.addActionListener(e -> {
			chkUserRiskRulesEnabled.setSelected(false);
			setUserRiskRulesPlaceholder();
		});

		return panel;
	}

	private void setUserRiskRulesPlaceholder() {
		txtUserRiskRulesYaml.setText(USER_RISK_RULES_PLACEHOLDER);
		txtUserRiskRulesYaml.setForeground(Color.GRAY);
		userRiskRulesPlaceholderActive = true;
	}

	private void applyThemeAndRefresh() {
		applyingTheme = true;
		try {
			FontPreferences.applyAppTheme(prefs);
			refreshSwatches();
		} finally {
			applyingTheme = false;
		}
	}

	private void refreshSwatches() {
		// Restore reporting color swatches
		btnBackground.setBackground(prefs.getBackground());
		btnDefault.setBackground(prefs.getDefaultText());
		btnNotice.setBackground(prefs.getNotice());
		btnHeading.setBackground(prefs.getHeading());
		btnContent.setBackground(prefs.getContent());
		btnKey.setBackground(prefs.getKey());
		btnValue.setBackground(prefs.getValue());
		btnWarning.setBackground(prefs.getWarning());
		btnSubsection.setBackground(prefs.getSubsection());
		btnHighlight.setBackground(prefs.getHighlight());
		btnRiskPass.setBackground(prefs.getRiskPass());
		btnRiskInconclusive.setBackground(prefs.getRiskInconclusive());
		btnRiskFail.setBackground(prefs.getRiskFail());
		btnRiskCritical.setBackground(prefs.getRiskCritical());
		btnRiskHigh.setBackground(prefs.getRiskHigh());
		btnRiskMedium.setBackground(prefs.getRiskMedium());
		btnRiskLow.setBackground(prefs.getRiskLow());
		btnRiskInfo.setBackground(prefs.getRiskInfo());
		// Card color swatches
		btnCardBg.setBackground(prefs.getCardBg());
		btnCardText.setBackground(prefs.getCardText());
		btnCardDim.setBackground(prefs.getCardDim());
		btnCardBorder.setBackground(prefs.getCardBorder());
		btnCardSelected.setBackground(prefs.getCardSelected());
		btnCardError.setBackground(prefs.getCardError());
		// Application color swatches
		btnAppBg.setBackground(prefs.getAppBackground());
		btnAppFg.setBackground(prefs.getAppForeground());
		btnAppButtonBg.setBackground(prefs.getAppButtonBg());
		btnAppButtonFg.setBackground(prefs.getAppButtonFg());
		// AI terminal color swatches
		btnAiTermBg.setBackground(prefs.getAiTerminalBg());
		btnAiTermUserPrefix.setBackground(prefs.getAiTerminalUserPrefix());
		btnAiTermUserText.setBackground(prefs.getAiTerminalUserText());
		btnAiTermAiPrefix.setBackground(prefs.getAiTerminalAiPrefix());
		btnAiTermAiText.setBackground(prefs.getAiTerminalAiText());
		btnAiTermError.setBackground(prefs.getAiTerminalError());
		btnAiTermSystem.setBackground(prefs.getAiTerminalSystem());
		btnAiTermSelectionBg.setBackground(prefs.getAiTerminalSelectionBg());
		btnAiTermSelectionFg.setBackground(prefs.getAiTerminalSelectionFg());
	}

	private JButton addColorRow(JPanel panel, GridBagConstraints c, int row,
			int colBase, String label, Color initial) {
		c.gridx = colBase;
		c.gridy = row;
		c.gridwidth = 1;
		c.fill = GridBagConstraints.NONE;
		c.weightx = 0;
		if (colBase > 0) {
			c.insets = new Insets(3, 18, 3, 6); // extra left gap between columns
		} else {
			c.insets = new Insets(3, 6, 3, 6);
		}
		panel.add(new JLabel(label), c);

		JButton btn = new JButton() {
			@Override
			protected void paintComponent(Graphics g) {
				g.setColor(getBackground());
				g.fillRect(0, 0, getWidth(), getHeight());
			}
		};
		btn.setPreferredSize(new Dimension(50, 22));
		btn.setBackground(initial);
		btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		c.gridx = colBase + 1;
		c.fill = GridBagConstraints.NONE;
		c.insets = new Insets(3, 6, 3, 6);
		panel.add(btn, c);
		return btn;
	}

	private void pickColor(JButton btn, String title) {
		Color chosen = JColorChooser.showDialog(this, title,
				btn.getBackground());
		if (chosen != null) {
			btn.setBackground(chosen);
			syncPrefsFromControls();
			updatePreview();
			updateAiTerminalPreview();
		}
	}

	private void pickAppColor(JButton btn, String title) {
		Color chosen = JColorChooser.showDialog(this, title,
				btn.getBackground());
		if (chosen != null) {
			btn.setBackground(chosen);
			prefs.setAppThemeCustom(true);
			syncPrefsFromControls();
			applyThemeAndRefresh();
		}
	}

	private void applyAppPreset(FontPreferences preset) {
		applyingTheme = true;
		try {
			prefs.setAppThemeCustom(preset.isAppThemeCustom());
			prefs.setAppFont(preset.getAppFont());
			prefs.setAppBackground(preset.getAppBackground());
			prefs.setAppForeground(preset.getAppForeground());
			prefs.setAppButtonBg(preset.getAppButtonBg());
			prefs.setAppButtonFg(preset.getAppButtonFg());

			// Update controls
			cmbAppFontFamily.setSelectedItem(preset.getAppFont().getFamily());
			cmbAppFontSize.setSelectedItem(preset.getAppFont().getSize());
			btnAppBg.setBackground(preset.getAppBackground());
			btnAppFg.setBackground(preset.getAppForeground());
			btnAppButtonBg.setBackground(preset.getAppButtonBg());
			btnAppButtonFg.setBackground(preset.getAppButtonFg());
		} finally {
			applyingTheme = false;
		}
		FontPreferences.applyAppTheme(prefs);
		refreshSwatches();
	}

	/** Check whether any settings have been modified from the original. */
	private boolean hasUnsavedChanges() {
		// Compare font
		if (!prefs.getFont().equals(originalPrefs.getFont())) return true;
		if (!prefs.getBackground().equals(originalPrefs.getBackground())) return true;
		if (!prefs.getDefaultText().equals(originalPrefs.getDefaultText())) return true;
		if (prefs.getRiskScale() != originalPrefs.getRiskScale()) return true;
		// Compare engine settings
		if (prefs.isSectionRiskAssessment() != originalPrefs.isSectionRiskAssessment()) return true;
		if (prefs.isSectionHost() != originalPrefs.isSectionHost()) return true;
		if (prefs.isProtocolTls12() != originalPrefs.isProtocolTls12()) return true;
		if (prefs.isProtocolTls13() != originalPrefs.isProtocolTls13()) return true;
		if (prefs.getWorkerThreads() != originalPrefs.getWorkerThreads()) return true;
		// Compare AI settings
		if (prefs.isAiReportEnabled() != originalPrefs.isAiReportEnabled()) return true;
		if (prefs.isAiChatEnabled() != originalPrefs.isAiChatEnabled()) return true;
		if (!prefs.getAiProvider().equals(originalPrefs.getAiProvider())) return true;
		// Compare app theme
		if (prefs.isAppThemeCustom() != originalPrefs.isAppThemeCustom()) return true;
		if (!prefs.getAppFont().equals(originalPrefs.getAppFont())) return true;
		if (!prefs.getAppBackground().equals(originalPrefs.getAppBackground())) return true;
		// Compare cipher map / risk rules
		if (prefs.isCustomCipherMapEnabled() != originalPrefs.isCustomCipherMapEnabled()) return true;
		if (prefs.isUserRiskRulesEnabled() != originalPrefs.isUserRiskRulesEnabled()) return true;
		return false;
	}

	private void syncPrefsFromControls() {
		// Reporting settings (read directly from controls)
		String family = (String) cmbFontFamily.getSelectedItem();
		int fontSize = 13;
		try {
			fontSize = Integer.parseInt(cmbFontSize.getSelectedItem().toString());
		} catch (NumberFormatException ignored) {
		}
		if (fontSize < 1) fontSize = 1;
		prefs.setFont(new Font(family, Font.PLAIN, fontSize));
		prefs.setBackground(btnBackground.getBackground());
		prefs.setDefaultText(btnDefault.getBackground());
		prefs.setNotice(btnNotice.getBackground());
		prefs.setHeading(btnHeading.getBackground());
		prefs.setContent(btnContent.getBackground());
		prefs.setKey(btnKey.getBackground());
		prefs.setValue(btnValue.getBackground());
		prefs.setWarning(btnWarning.getBackground());
		prefs.setSubsection(btnSubsection.getBackground());
		prefs.setHighlight(btnHighlight.getBackground());
		prefs.setRiskPass(btnRiskPass.getBackground());
		prefs.setRiskInconclusive(btnRiskInconclusive.getBackground());
		prefs.setRiskFail(btnRiskFail.getBackground());
		prefs.setRiskCritical(btnRiskCritical.getBackground());
		prefs.setRiskHigh(btnRiskHigh.getBackground());
		prefs.setRiskMedium(btnRiskMedium.getBackground());
		prefs.setRiskLow(btnRiskLow.getBackground());
		prefs.setRiskInfo(btnRiskInfo.getBackground());
		prefs.setHardwrapEnabled(chkHardwrap.isSelected());
		prefs.setHardwrapWidth((Integer) spnHardwrapWidth.getValue());

		// Card settings
		String cardFamily = (String) cmbCardFontFamily.getSelectedItem();
		int cardFontSize = 13;
		try {
			cardFontSize = Integer.parseInt(cmbCardFontSize.getSelectedItem().toString());
		} catch (NumberFormatException ignored) {
		}
		if (cardFontSize < 1) cardFontSize = 1;
		prefs.setCardFont(new Font(cardFamily, Font.PLAIN, cardFontSize));
		prefs.setCardBadgeSize((Integer) spnCardBadgeSize.getValue());
		prefs.setCardBg(btnCardBg.getBackground());
		prefs.setCardText(btnCardText.getBackground());
		prefs.setCardDim(btnCardDim.getBackground());
		prefs.setCardBorder(btnCardBorder.getBackground());
		prefs.setCardSelected(btnCardSelected.getBackground());
		prefs.setCardError(btnCardError.getBackground());
		if (cardGridEditor != null) {
			prefs.setCardLayout(cardGridEditor.getCardLayout().copy());
		}
		if (cardTrashPanel != null) {
			prefs.setCardSize(cardTrashPanel.getCardSize());
		}

		// Engine settings
		prefs.setSectionRiskAssessment(chkRiskAssessment.isSelected());
		prefs.setSectionAiEvaluation(chkAiEvaluation.isSelected());
		prefs.setSectionRuntimeEnvironment(chkRuntimeEnvironment.isSelected());
		prefs.setSectionHost(chkHost.isSelected());
		prefs.setSectionHttpResponse(chkHttpResponse.isSelected());
		prefs.setSectionSecurityHeaders(chkSecurityHeaders.isSelected());
		prefs.setSectionConnection(chkConnection.isSelected());
		prefs.setSectionCipherSuites(chkCipherSuites.isSelected());
		prefs.setSectionCertChain(chkCertChain.isSelected());
		prefs.setSectionRevocation(chkRevocation.isSelected());
		prefs.setSectionTlsFingerprint(chkTlsFingerprint.isSelected());
		prefs.setCipherConvention((String) cmbCipherConvention.getSelectedItem());
		prefs.setProtocolSslv3(chkSslv3.isSelected());
		prefs.setProtocolTls10(chkTls10.isSelected());
		prefs.setProtocolTls11(chkTls11.isSelected());
		prefs.setProtocolTls12(chkTls12.isSelected());
		prefs.setProtocolTls13(chkTls13.isSelected());
		prefs.setRiskScale((Integer) spnRiskScale.getValue());
		prefs.setWorkerThreads((Integer) spnWorkerThreads.getValue());
		prefs.setThrottleDelayMs((Integer) spnThrottleDelayMs.getValue());

		// General settings
		prefs.setSuppressSaveWarning(chkSuppressSaveWarning.isSelected());

		// Application theme
		String appFamily = (String) cmbAppFontFamily.getSelectedItem();
		int appSize = 13;
		try {
			appSize = Integer.parseInt(cmbAppFontSize.getSelectedItem().toString());
		} catch (NumberFormatException ignored) {
		}
		if (appSize < 1) appSize = 1;
		prefs.setAppFont(new Font(appFamily, Font.PLAIN, appSize));
		prefs.setAppBackground(btnAppBg.getBackground());
		prefs.setAppForeground(btnAppFg.getBackground());
		prefs.setAppButtonBg(btnAppButtonBg.getBackground());
		prefs.setAppButtonFg(btnAppButtonFg.getBackground());

		// AI terminal colors
		prefs.setAiTerminalBg(btnAiTermBg.getBackground());
		prefs.setAiTerminalUserPrefix(btnAiTermUserPrefix.getBackground());
		prefs.setAiTerminalUserText(btnAiTermUserText.getBackground());
		prefs.setAiTerminalAiPrefix(btnAiTermAiPrefix.getBackground());
		prefs.setAiTerminalAiText(btnAiTermAiText.getBackground());
		prefs.setAiTerminalError(btnAiTermError.getBackground());
		prefs.setAiTerminalSystem(btnAiTermSystem.getBackground());
		prefs.setAiTerminalSelectionBg(btnAiTermSelectionBg.getBackground());
		prefs.setAiTerminalSelectionFg(btnAiTermSelectionFg.getBackground());

		// Cipher map / user risk rules
		if (chkCipherMapEnabled != null) {
			prefs.setCustomCipherMapEnabled(chkCipherMapEnabled.isSelected());
		}
		if (chkUserRiskRulesEnabled != null) {
			prefs.setUserRiskRulesEnabled(chkUserRiskRulesEnabled.isSelected());
		}

		// AI chat settings
		prefs.setAiChatEnabled(chkAiChatEnabled.isSelected());
		prefs.setAiChatProvider((String) cmbAiChatProvider.getSelectedItem());
		prefs.setAiChatApiKey(new String(txtAiChatApiKey.getPassword()));
		prefs.setAiChatEndpointUrl(txtAiChatEndpointUrl.getText());
		prefs.setAiChatModel((String) cmbAiChatModel.getSelectedItem());
		prefs.setAiChatMaxTokens((Integer) spnAiChatMaxTokens.getValue());
		prefs.setAiChatTemperature((Double) spnAiChatTemperature.getValue());

		// AI report settings
		prefs.setAiReportEnabled(chkAiReportEnabled.isSelected());
		prefs.setAiProvider((String) cmbAiReportProvider.getSelectedItem());
		prefs.setAiApiKey(new String(txtAiReportApiKey.getPassword()));
		prefs.setAiEndpointUrl(txtAiReportEndpointUrl.getText());
		prefs.setAiModel((String) cmbAiReportModel.getSelectedItem());
		prefs.setAiMaxTokens((Integer) spnAiReportMaxTokens.getValue());
		prefs.setAiTemperature((Double) spnAiReportTemperature.getValue());

		// AI prompts
		prefs.setAiSystemPrompt(txtAiSystemPrompt.getText());
		prefs.setAiChatSystemPrompt(txtAiChatSystemPrompt.getText());
	}

	private void applyPreset(FontPreferences preset) {
		cmbFontFamily.setSelectedItem(preset.getFont().getFamily());
		cmbFontSize.setSelectedItem(preset.getFont().getSize());
		btnBackground.setBackground(preset.getBackground());
		btnDefault.setBackground(preset.getDefaultText());
		btnNotice.setBackground(preset.getNotice());
		btnHeading.setBackground(preset.getHeading());
		btnContent.setBackground(preset.getContent());
		btnKey.setBackground(preset.getKey());
		btnValue.setBackground(preset.getValue());
		btnWarning.setBackground(preset.getWarning());
		btnSubsection.setBackground(preset.getSubsection());
		btnHighlight.setBackground(preset.getHighlight());
		btnRiskPass.setBackground(preset.getRiskPass());
		btnRiskInconclusive.setBackground(preset.getRiskInconclusive());
		btnRiskFail.setBackground(preset.getRiskFail());
		btnRiskCritical.setBackground(preset.getRiskCritical());
		btnRiskHigh.setBackground(preset.getRiskHigh());
		btnRiskMedium.setBackground(preset.getRiskMedium());
		btnRiskLow.setBackground(preset.getRiskLow());
		btnRiskInfo.setBackground(preset.getRiskInfo());
		// Card presets
		cmbCardFontFamily.setSelectedItem(preset.getCardFont().getFamily());
		cmbCardFontSize.setSelectedItem(preset.getCardFont().getSize());
		spnCardBadgeSize.setValue(preset.getCardBadgeSize());
		btnCardBg.setBackground(preset.getCardBg());
		btnCardText.setBackground(preset.getCardText());
		btnCardDim.setBackground(preset.getCardDim());
		btnCardBorder.setBackground(preset.getCardBorder());
		btnCardSelected.setBackground(preset.getCardSelected());
		btnCardError.setBackground(preset.getCardError());
		if (cardGridEditor != null) {
			CardLayout defLayout = CardLayout.defaultLayout();
			cardGridEditor.setCardLayout(defLayout);
			cardTrashPanel.setCardLayout(defLayout);
			cardLayoutPreview.setCardLayout(defLayout);
			cardMetaPalette.updateVisibility(cardGridEditor.getCardLayout());
		}
		syncPrefsFromControls();
		updatePreview();
		updateCardPreview();
	}

	private void updatePreview() {
		StyledDocument doc = txtPreview.getStyledDocument();
		try {
			doc.remove(0, doc.getLength());
		} catch (BadLocationException ignored) {
		}

		txtPreview.setBackground(prefs.getBackground());
		Font font = prefs.getFont();

		appendStyled(doc, "***** NOTICE: SAMPLE BANNER *****\n", font,
				prefs.getNotice(), true);
		appendStyled(doc, "[Section Heading]\n", font,
				prefs.getHeading(), true);
		appendStyled(doc, "   Subsection Label:\n", font,
				prefs.getSubsection(), true);
		appendStyled(doc, "Section content line\n", font,
				prefs.getContent(), false);
		appendStyled(doc, "ExtendedKeyUsages", font,
				prefs.getKey(), false);
		appendStyled(doc, "=", font, prefs.getContent(), false);
		appendStyled(doc, "[serverAuth]\n", font,
				prefs.getValue(), false);
		appendStyled(doc, "Signature Algorithm", font,
				prefs.getKey(), false);
		appendStyled(doc, "=", font, prefs.getContent(), false);
		appendStyled(doc, "SHA256withRSA\n", font,
				prefs.getValue(), false);
		appendStyled(doc, ">>>WARNING<<<\n", font,
				prefs.getWarning(), true);
		appendStyled(doc, "Default text sample\n", font,
				prefs.getDefaultText(), false);
		appendStyled(doc, "   Risk: ", font,
				prefs.getContent(), false);
		appendStyled(doc, "\u2588\u2588\u2588\u2588\u2588", font,
				prefs.getRiskPass(), false);
		appendStyled(doc, "\u2588\u2588\u2588", font,
				prefs.getRiskInconclusive(), false);
		appendStyled(doc, "\u2588\u2588", font,
				prefs.getRiskFail(), false);
		appendStyled(doc, "  ", font, prefs.getContent(), false);
		appendStyled(doc, "\u2588", font, prefs.getRiskPass(), false);
		appendStyled(doc, "Pass ", font, prefs.getContent(), false);
		appendStyled(doc, "\u2588", font, prefs.getRiskInconclusive(), false);
		appendStyled(doc, "Inconclusive ", font, prefs.getContent(), false);
		appendStyled(doc, "\u2588", font, prefs.getRiskFail(), false);
		appendStyled(doc, "Fail\n", font, prefs.getContent(), false);
		appendStyled(doc, "CIPHER_WEAK [CRITICAL] Sample critical finding (score: 25.00)\n",
				font, prefs.getRiskCritical(), true);
		appendStyled(doc, "PROTO_OLD [HIGH] Sample high finding (score: 15.00)\n",
				font, prefs.getRiskHigh(), true);
		appendStyled(doc, "HEADER_MISS [MEDIUM] Sample medium finding (score: 8.00)\n",
				font, prefs.getRiskMedium(), true);
		appendStyled(doc, "CERT_LONG [LOW] Sample low finding (score: 3.00)\n",
				font, prefs.getRiskLow(), true);
		appendStyled(doc, "META_NOTE [INFO] Sample informational finding (score: 0.00)\n",
				font, prefs.getRiskInfo(), true);
	}

	private void pickCardColor(JButton btn, String title) {
		Color chosen = JColorChooser.showDialog(this, title, btn.getBackground());
		if (chosen != null) {
			btn.setBackground(chosen);
			syncPrefsFromControls();
			updateCardPreview();
		}
	}

	private void updateCardPreview() {
		if (cardLayoutPreview != null) {
			cardLayoutPreview.setPrefs(prefs);
			cardLayoutPreview.setCardLayout(cardGridEditor != null
					? cardGridEditor.getCardLayout() : prefs.getCardLayout());
			cardLayoutPreview.repaint();
		}
		if (cardGridEditor != null) {
			cardGridEditor.setPrefs(prefs);
			cardGridEditor.repaint();
		}
	}


	private void appendStyled(StyledDocument doc, String text, Font font,
			Color fg, boolean bold) {
		SimpleAttributeSet attrs = new SimpleAttributeSet();
		StyleConstants.setFontFamily(attrs, font.getFamily());
		StyleConstants.setFontSize(attrs, font.getSize());
		StyleConstants.setForeground(attrs, fg);
		StyleConstants.setBold(attrs, bold);
		try {
			doc.insertString(doc.getLength(), text, attrs);
		} catch (BadLocationException ignored) {
		}
	}

	private void updateAiTerminalPreview() {
		if (aiPreviewTerminal == null) return;
		syncPrefsFromControls();
		aiPreviewTerminal.setBackground(prefs.getAiTerminalBg());
		aiPreviewTerminal.setSelectionColor(prefs.getAiTerminalSelectionBg());
		aiPreviewTerminal.setSelectedTextColor(prefs.getAiTerminalSelectionFg());
		aiPreviewTerminal.clear();

		String sys = "{fg:" + hex(prefs.getAiTerminalSystem()) + "}";
		String up = "{fg:" + hex(prefs.getAiTerminalUserPrefix()) + "}{+bold}";
		String ut = "{fg:" + hex(prefs.getAiTerminalUserText()) + "}";
		String ap = "{fg:" + hex(prefs.getAiTerminalAiPrefix()) + "}{+bold}";
		String at = "{fg:" + hex(prefs.getAiTerminalAiText()) + "}";
		String er = "{fg:" + hex(prefs.getAiTerminalError()) + "}";
		String r = "{-bold}{reset}";

		aiPreviewTerminal.write(sys + "Welcome to DeepViolet AI Assistant." + r + "\n");
		aiPreviewTerminal.write(sys + "Ready for questions about: example.com" + r + "\n\n");
		aiPreviewTerminal.write(up + "User> " + r + ut + "Is TLS 1.3 supported?" + r + "\n");
		aiPreviewTerminal.write(ap + "AI> " + r + at + "Yes, TLS 1.3 is supported and negotiated." + r + "\n\n");
		aiPreviewTerminal.write(er + "Error: sample error message." + r + "\n");
	}

	private String hex(Color c) {
		return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue());
	}

	/**
	 * Check whether the user confirmed the dialog with OK.
	 *
	 * @return true if the user clicked OK, false if cancelled
	 */
	public boolean isApproved() {
		return approved;
	}

	/**
	 * Get the edited theme preferences.
	 *
	 * @return the current preferences (reflects user edits)
	 */
	public FontPreferences getPreferences() {
		return prefs;
	}

	private static FontPreferences copyPrefs(FontPreferences src) {
		FontPreferences copy = FontPreferences.defaults();
		copy.setFont(src.getFont());
		copy.setBackground(src.getBackground());
		copy.setDefaultText(src.getDefaultText());
		copy.setNotice(src.getNotice());
		copy.setHeading(src.getHeading());
		copy.setContent(src.getContent());
		copy.setKey(src.getKey());
		copy.setValue(src.getValue());
		copy.setWarning(src.getWarning());
		copy.setSubsection(src.getSubsection());
		copy.setRiskPass(src.getRiskPass());
		copy.setRiskInconclusive(src.getRiskInconclusive());
		copy.setRiskFail(src.getRiskFail());
		copy.setRiskCritical(src.getRiskCritical());
		copy.setRiskHigh(src.getRiskHigh());
		copy.setRiskMedium(src.getRiskMedium());
		copy.setRiskLow(src.getRiskLow());
		copy.setRiskInfo(src.getRiskInfo());
		copy.setHardwrapEnabled(src.isHardwrapEnabled());
		copy.setHardwrapWidth(src.getHardwrapWidth());
		// Engine settings
		copy.setSectionRiskAssessment(src.isSectionRiskAssessment());
		copy.setSectionAiEvaluation(src.isSectionAiEvaluation());
		copy.setSectionRuntimeEnvironment(src.isSectionRuntimeEnvironment());
		copy.setSectionHost(src.isSectionHost());
		copy.setSectionHttpResponse(src.isSectionHttpResponse());
		copy.setSectionSecurityHeaders(src.isSectionSecurityHeaders());
		copy.setSectionConnection(src.isSectionConnection());
		copy.setSectionCipherSuites(src.isSectionCipherSuites());
		copy.setSectionCertChain(src.isSectionCertChain());
		copy.setSectionRevocation(src.isSectionRevocation());
		copy.setSectionTlsFingerprint(src.isSectionTlsFingerprint());
		copy.setCipherConvention(src.getCipherConvention());
		copy.setProtocolSslv3(src.isProtocolSslv3());
		copy.setProtocolTls10(src.isProtocolTls10());
		copy.setProtocolTls11(src.isProtocolTls11());
		copy.setProtocolTls12(src.isProtocolTls12());
		copy.setProtocolTls13(src.isProtocolTls13());
		copy.setRiskScale(src.getRiskScale());
		copy.setScanScale(src.getScanScale());
		copy.setWorkerThreads(src.getWorkerThreads());
		copy.setThrottleDelayMs(src.getThrottleDelayMs());
		// Application theme
		copy.setAppThemeCustom(src.isAppThemeCustom());
		copy.setAppFont(src.getAppFont());
		copy.setAppBackground(src.getAppBackground());
		copy.setAppForeground(src.getAppForeground());
		copy.setAppButtonBg(src.getAppButtonBg());
		copy.setAppButtonFg(src.getAppButtonFg());
		// AI report settings
		copy.setAiReportEnabled(src.isAiReportEnabled());
		copy.setAiProvider(src.getAiProvider());
		copy.setAiApiKey(src.getAiApiKey());
		copy.setAiEndpointUrl(src.getAiEndpointUrl());
		copy.setAiModel(src.getAiModel());
		copy.setAiMaxTokens(src.getAiMaxTokens());
		copy.setAiTemperature(src.getAiTemperature());
		copy.setAiSystemPrompt(src.getAiSystemPrompt());
		copy.setAiChatSystemPrompt(src.getAiChatSystemPrompt());
		// AI chat settings
		copy.setAiChatEnabled(src.isAiChatEnabled());
		copy.setAiChatProvider(src.getAiChatProvider());
		copy.setAiChatApiKey(src.getAiChatApiKey());
		copy.setAiChatEndpointUrl(src.getAiChatEndpointUrl());
		copy.setAiChatModel(src.getAiChatModel());
		copy.setAiChatMaxTokens(src.getAiChatMaxTokens());
		copy.setAiChatTemperature(src.getAiChatTemperature());
		// AI terminal colors
		copy.setAiTerminalBg(src.getAiTerminalBg());
		copy.setAiTerminalUserPrefix(src.getAiTerminalUserPrefix());
		copy.setAiTerminalUserText(src.getAiTerminalUserText());
		copy.setAiTerminalAiPrefix(src.getAiTerminalAiPrefix());
		copy.setAiTerminalAiText(src.getAiTerminalAiText());
		copy.setAiTerminalError(src.getAiTerminalError());
		copy.setAiTerminalSystem(src.getAiTerminalSystem());
		// Card display
		copy.setCardFont(src.getCardFont());
		copy.setCardBg(src.getCardBg());
		copy.setCardText(src.getCardText());
		copy.setCardDim(src.getCardDim());
		copy.setCardBorder(src.getCardBorder());
		copy.setCardSelected(src.getCardSelected());
		copy.setCardError(src.getCardError());
		copy.setCardLayout(src.getCardLayout().copy());
		copy.setCardSize(src.getCardSize());
		copy.setWorkbenchMode(src.isWorkbenchMode());
		return copy;
	}

	/**
	 * Create a cell renderer that appends "[mono]" to monospaced font names.
	 */
	private DefaultListCellRenderer createMonoTagRenderer() {
		return new DefaultListCellRenderer() {
			@Override
			public Component getListCellRendererComponent(JList<?> list, Object value,
					int index, boolean isSelected, boolean cellHasFocus) {
				String display = (value != null && MONO_FONTS.contains(value.toString()))
						? value + "  [mono]" : String.valueOf(value);
				return super.getListCellRendererComponent(list, display,
						index, isSelected, cellHasFocus);
			}
		};
	}
}
