package com.mps.deepviolettools.ui;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import javax.swing.JPanel;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.model.CardMetaElement;
import com.mps.deepviolettools.model.CardSize;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * Read-only card preview panel that shows a live preview of the card
 * using sample data and the current layout configuration.
 */
public class CardLayoutPreview extends JPanel {

	private CardLayout cardLayout;
	private FontPreferences prefs;

	/** Sample data provider for the preview card. */
	private static final CardRenderer.ElementDataProvider SAMPLE_DATA =
			new CardRenderer.ElementDataProvider() {
		@Override
		public String getText(CardMetaElement element) {
			switch (element) {
				case GRADE: return "A";
				case SCORE: return "92/100";
				case HOSTNAME: return "example.com";
				case IP: return "93.184.216.34";
				case TLS_VERSION: return "TLSv1.3";
				case CIPHERS: return "STRONG";
				case HEADERS: return "5/7";
				case CERT: return "TRUSTED";
				case CERT_EXPIRY: return "247 days";
				case KEY_INFO: return "EC-256 (secp256r1)";
				case ISSUER: return "Let's Encrypt";
				case SAN_COUNT: return "3";
				case REVOCATION: return "GOOD";
				case RISK_BARS: return "";
				default: return "";
			}
		}

		@Override
		public String getGrade() { return "A"; }

		@Override
		public int[][] getCategoryBars() {
			return new int[][] {
				{8, 1, 1}, {10, 0, 0}, {9, 1, 0}, {7, 2, 1}
			};
		}

		@Override
		public String[] getCategoryNames() {
			return new String[] {"Protocol", "Key Exchange", "Cipher", "Certificate"};
		}
	};

	public CardLayoutPreview(FontPreferences prefs) {
		this.prefs = prefs;
		this.cardLayout = prefs.getCardLayout().copy();
		updateSizeHints();
	}

	private void updateSizeHints() {
		CardSize cs = prefs.getCardSize();
		setPreferredSize(new Dimension(cs.getWidth() + 20, cs.getHeight() + 20));
		setMinimumSize(new Dimension(cs.getWidth() + 20, cs.getHeight() + 20));
	}

	public CardLayout getCardLayout() {
		return cardLayout;
	}

	public void setCardLayout(CardLayout layout) {
		this.cardLayout = layout.copy();
		repaint();
	}

	public void setPrefs(FontPreferences prefs) {
		this.prefs = prefs;
		updateSizeHints();
		revalidate();
		repaint();
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		Graphics2D g2 = (Graphics2D) g;
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);
		g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
				RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

		// Center the fixed-size card within the available panel area
		CardSize cs = prefs.getCardSize();
		int cw = cs.getWidth();
		int ch = cs.getHeight();
		int ox = (getWidth() - cw) / 2;
		int oy = (getHeight() - ch) / 2;
		g2.translate(ox, oy);
		g2.setClip(0, 0, cw, ch);

		CardRenderer.paintCard(g2, cw, ch, prefs,
				cardLayout, SAMPLE_DATA, true, false, -1, -1);

		g2.translate(-ox, -oy);
	}
}
