package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;
import javax.swing.event.HyperlinkEvent;

import com.mps.deepviolettools.util.FontPreferences;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-modal help dialog that displays documentation about DeepViolet
 * scan report output. Users can keep this open while scanning.
 *
 * @author Milton Smith
 */
public class InterfaceHelpDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.ui.InterfaceHelpDialog");

	public InterfaceHelpDialog(JFrame parent) {
		super(parent, "DeepViolet Interface Help", false);

		JEditorPane editorPane = new JEditorPane("text/html", buildHtml());
		editorPane.setEditable(false);
		editorPane.setCaretPosition(0);
		editorPane.addHyperlinkListener(e -> {
			if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
				try {
					Desktop.getDesktop().browse(e.getURL().toURI());
				} catch (Exception ex) {
					logger.warn("Unable to open browser: {}", ex.getMessage());
				}
			}
		});

		JScrollPane scrollPane = new JScrollPane(editorPane);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton closeButton = new JButton("Close");
		closeButton.addActionListener(e -> dispose());
		buttonPanel.add(closeButton);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(scrollPane, BorderLayout.CENTER);
		getContentPane().add(buttonPanel, BorderLayout.SOUTH);

		setSize((int) (parent.getWidth() * 0.75),
				(int) (parent.getHeight() * 0.75));
		setMinimumSize(new Dimension(400, 300));
		setLocationRelativeTo(parent);
	}

	private static String colorToHex(Color c) {
		return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue());
	}

	private static Color blend(Color c1, Color c2, double ratio) {
		int r = (int) (c1.getRed() * (1 - ratio) + c2.getRed() * ratio);
		int g = (int) (c1.getGreen() * (1 - ratio) + c2.getGreen() * ratio);
		int b = (int) (c1.getBlue() * (1 - ratio) + c2.getBlue() * ratio);
		return new Color(
				Math.max(0, Math.min(255, r)),
				Math.max(0, Math.min(255, g)),
				Math.max(0, Math.min(255, b)));
	}

	private String buildHtml() {
		Color bg = UIManager.getColor("Panel.background");
		Color fg = UIManager.getColor("Label.foreground");
		if (bg == null) bg = new Color(0xEE, 0xEE, 0xEE);
		if (fg == null) fg = Color.BLACK;

		FontPreferences prefs = FontPreferences.load();
		java.awt.Font appFont = prefs.getAppFont();
		String fontFamily = (appFont != null) ? appFont.getFamily() : "SansSerif";
		int fontSize = (appFont != null) ? appFont.getSize() : 13;

		Color borderColor = blend(bg, fg, 0.25);
		Color thBg = blend(bg, fg, 0.10);
		Color codeBg = blend(bg, fg, 0.08);
		Color linkColor = UIManager.getColor("Component.linkColor");
		if (linkColor == null) linkColor = blend(fg, new Color(0x55, 0x88, 0xFF), 0.5);

		String template;
		try (InputStream is = getClass().getResourceAsStream("/interface-help.html")) {
			if (is == null) {
				logger.error("interface-help.html resource not found");
				return "<html><body><p>Error: help content could not be loaded.</p></body></html>";
			}
			template = new String(is.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			logger.error("Failed to load interface-help.html: {}", e.getMessage());
			return "<html><body><p>Error: help content could not be loaded.</p></body></html>";
		}

		return template
				.replace("{{BODY_BG}}", colorToHex(bg))
				.replace("{{BODY_FG}}", colorToHex(fg))
				.replace("{{FONT_FAMILY}}", fontFamily)
				.replace("{{FONT_SIZE}}", String.valueOf(fontSize))
				.replace("{{BORDER_COLOR}}", colorToHex(borderColor))
				.replace("{{TH_BG}}", colorToHex(thBg))
				.replace("{{CODE_BG}}", colorToHex(codeBg))
				.replace("{{LINK_COLOR}}", colorToHex(linkColor));
	}
}
