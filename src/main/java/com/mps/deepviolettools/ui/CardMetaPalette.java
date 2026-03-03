package com.mps.deepviolettools.ui;

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.TransferHandler;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.model.CardMetaElement;

/**
 * A vertical palette of colored tiles, one per {@link CardMetaElement}.
 * Each tile can be dragged onto the {@link CardLayoutPreview}.  Tiles
 * for elements already visible on the card are shown dimmed; unplaced
 * elements are shown at full brightness.
 */
public class CardMetaPalette extends JPanel {

	private static final int TILE_HEIGHT = 22;

	/** Distinct tile colors keyed by element. */
	private static final Map<CardMetaElement, Color> TILE_COLORS = new EnumMap<>(CardMetaElement.class);

	static {
		TILE_COLORS.put(CardMetaElement.GRADE,       new Color(0x4C, 0xAF, 0x50));
		TILE_COLORS.put(CardMetaElement.SCORE,       new Color(0x21, 0x96, 0xF3));
		TILE_COLORS.put(CardMetaElement.HOSTNAME,    new Color(0xFF, 0x98, 0x00));
		TILE_COLORS.put(CardMetaElement.IP,          new Color(0x9C, 0x27, 0xB0));
		TILE_COLORS.put(CardMetaElement.TLS_VERSION, new Color(0x00, 0x96, 0x88));
		TILE_COLORS.put(CardMetaElement.CIPHERS,     new Color(0xF4, 0x43, 0x36));
		TILE_COLORS.put(CardMetaElement.HEADERS,     new Color(0x60, 0x7D, 0x8B));
		TILE_COLORS.put(CardMetaElement.CERT,        new Color(0x79, 0x55, 0x48));
		TILE_COLORS.put(CardMetaElement.RISK_BARS,   new Color(0xFF, 0x57, 0x22));
		TILE_COLORS.put(CardMetaElement.CERT_EXPIRY, new Color(0xE9, 0x1E, 0x63));
		TILE_COLORS.put(CardMetaElement.KEY_INFO,    new Color(0x3F, 0x51, 0xB5));
		TILE_COLORS.put(CardMetaElement.ISSUER,      new Color(0x8B, 0xC3, 0x4A));
		TILE_COLORS.put(CardMetaElement.SAN_COUNT,   new Color(0x00, 0xBC, 0xD4));
		TILE_COLORS.put(CardMetaElement.REVOCATION,  new Color(0xFF, 0xC1, 0x07));
	}

	private final Map<CardMetaElement, TilePanel> tiles = new EnumMap<>(CardMetaElement.class);

	public CardMetaPalette() {
		setLayout(new GridLayout(CardMetaElement.values().length, 1, 0, 2));

		for (CardMetaElement elem : CardMetaElement.values()) {
			TilePanel tile = new TilePanel(elem);
			tiles.put(elem, tile);
			add(tile);
		}
	}

	/**
	 * Update tile dimming based on which elements are currently visible
	 * on the card layout.
	 */
	public void updateVisibility(CardLayout layout) {
		Set<CardMetaElement> visible = layout.getVisibleElements();
		for (Map.Entry<CardMetaElement, TilePanel> e : tiles.entrySet()) {
			e.getValue().setDimmed(visible.contains(e.getKey()));
		}
		repaint();
	}

	/**
	 * A single draggable tile representing one CardMetaElement.
	 */
	private static class TilePanel extends JPanel {

		private final CardMetaElement element;
		private boolean dimmed;

		TilePanel(CardMetaElement element) {
			this.element = element;
			setPreferredSize(new Dimension(120, TILE_HEIGHT));
			setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));

			setTransferHandler(new TransferHandler() {
				@Override
				public int getSourceActions(JComponent c) {
					return TransferHandler.MOVE;
				}

				@Override
				protected java.awt.datatransfer.Transferable createTransferable(JComponent c) {
					return new CardMetaTransferable(element);
				}
			});

			addMouseListener(new java.awt.event.MouseAdapter() {
				@Override
				public void mousePressed(java.awt.event.MouseEvent e) {
					JComponent c = (JComponent) e.getSource();
					c.getTransferHandler().exportAsDrag(c, e, TransferHandler.MOVE);
				}
			});
		}

		void setDimmed(boolean dimmed) {
			this.dimmed = dimmed;
		}

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2 = (Graphics2D) g;
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);
			g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
					RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

			Color base = TILE_COLORS.getOrDefault(element, Color.GRAY);
			if (dimmed) {
				base = new Color(base.getRed(), base.getGreen(), base.getBlue(), 90);
			}

			g2.setColor(base);
			g2.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);

			g2.setColor(Color.WHITE);
			g2.setFont(getFont().deriveFont(Font.BOLD, 11f));
			FontMetrics fm = g2.getFontMetrics();
			String label = element.getDisplayName();
			int tx = (getWidth() - fm.stringWidth(label)) / 2;
			int ty = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
			g2.drawString(label, tx, ty);
		}
	}
}
