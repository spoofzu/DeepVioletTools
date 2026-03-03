package com.mps.deepviolettools.ui;

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.EnumMap;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.TransferHandler;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.model.CardMetaElement;
import com.mps.deepviolettools.model.CardSlotConfig;
import com.mps.deepviolettools.model.CardSlotConfig.HAlign;
import com.mps.deepviolettools.model.CardSlotConfig.VAlign;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * Grid-based card layout editor.  Paints a visible grid where elements
 * can be dropped into cells, clicked to change alignment, dragged to
 * span multiple cells, and grid lines can be dragged to resize cell
 * proportions.  Right-click removes elements.
 */
public class CardGridEditor extends JPanel {

	private static final int GRID_LINE_HIT = 6;
	private static final int MIN_PREF_W = 300;
	private static final int MIN_PREF_H = 250;
	private static final int CLICK_THRESHOLD = 5;

	/** Tile colors matching the palette. */
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
	}

	private CardLayout cardLayout;
	private FontPreferences prefs;
	private Runnable onLayoutChanged;

	// Drag-over highlight (palette drops)
	private int highlightRow = -1;
	private int highlightCol = -1;

	// Grid line dragging state
	private boolean draggingColLine;
	private boolean draggingRowLine;
	private int dragLineIndex = -1;

	// Mouse press state for click vs drag detection
	private int pressX, pressY;
	private CardSlotConfig pressedSlot;
	private boolean spanDragging;

	// Span drag live preview
	private int spanPreviewColSpan = 1;
	private int spanPreviewRowSpan = 1;

	public CardGridEditor(FontPreferences prefs) {
		this.prefs = prefs;
		this.cardLayout = prefs.getCardLayout().copy();

		setPreferredSize(new Dimension(MIN_PREF_W, MIN_PREF_H));
		setMinimumSize(new Dimension(200, 180));

		setupTransferHandler();
		setupMouseHandlers();
	}

	public CardLayout getCardLayout() { return cardLayout; }

	public void setCardLayout(CardLayout layout) {
		this.cardLayout = layout.copy();
		repaint();
	}

	public void setPrefs(FontPreferences prefs) {
		this.prefs = prefs;
	}

	public void setOnLayoutChanged(Runnable callback) {
		this.onLayoutChanged = callback;
	}

	private void fireLayoutChanged() {
		if (onLayoutChanged != null) {
			onLayoutChanged.run();
		}
	}

	private void setupTransferHandler() {
		setTransferHandler(new TransferHandler() {
			@Override
			public boolean canImport(TransferSupport support) {
				if (!support.isDataFlavorSupported(CardMetaTransferable.FLAVOR)) {
					return false;
				}
				if (support.isDrop()) {
					int[] cell = pixelToCell(
							support.getDropLocation().getDropPoint().x,
							support.getDropLocation().getDropPoint().y);
					if (cell[0] != highlightRow || cell[1] != highlightCol) {
						highlightRow = cell[0];
						highlightCol = cell[1];
						repaint();
					}
				}
				return true;
			}

			@Override
			public boolean importData(TransferSupport support) {
				highlightRow = -1;
				highlightCol = -1;
				if (!support.isDataFlavorSupported(CardMetaTransferable.FLAVOR)) {
					return false;
				}
				try {
					Transferable t = support.getTransferable();
					CardMetaElement elem = (CardMetaElement) t.getTransferData(
							CardMetaTransferable.FLAVOR);
					int[] cell = pixelToCell(
							support.getDropLocation().getDropPoint().x,
							support.getDropLocation().getDropPoint().y);
					int r = cell[0];
					int c = cell[1];

					// If cell is occupied by a different element, displace it
					CardSlotConfig existing = cardLayout.getSlotAt(r, c);
					if (existing != null && existing.getElement() != elem) {
						cardLayout.setConfig(existing.withVisible(false));
					}

					CardSlotConfig config = new CardSlotConfig(
							elem, r, c, HAlign.CENTER, VAlign.CENTER, true);
					cardLayout.setConfig(config);
					fireLayoutChanged();
					repaint();
					return true;
				} catch (UnsupportedFlavorException | IOException e) {
					return false;
				}
			}
		});
	}

	private void setupMouseHandlers() {
		MouseAdapter handler = new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showContextMenu(e);
					return;
				}

				pressX = e.getX();
				pressY = e.getY();
				pressedSlot = null;
				spanDragging = false;

				// Shift+click on an element = alignment adjustment
				if (e.isShiftDown()) {
					int[] cell = pixelToCell(e.getX(), e.getY());
					CardSlotConfig slot = cardLayout.getSlotAt(cell[0], cell[1]);
					if (slot != null) {
						handleClickToAlign(e, slot);
					}
					return;
				}

				// Check for grid line drag
				int[] colLine = findColLine(e.getX());
				int[] rowLine = findRowLine(e.getY());

				if (colLine != null) {
					draggingColLine = true;
					dragLineIndex = colLine[0];
					return;
				}
				if (rowLine != null) {
					draggingRowLine = true;
					dragLineIndex = rowLine[0];
					return;
				}

				// Record element at press point for potential span drag
				int[] cell = pixelToCell(e.getX(), e.getY());
				pressedSlot = cardLayout.getSlotAt(cell[0], cell[1]);
			}

			@Override
			public void mouseDragged(MouseEvent e) {
				if (draggingColLine && dragLineIndex >= 0) {
					adjustColWeight(dragLineIndex, e.getX());
					repaint();
					fireLayoutChanged();
				} else if (draggingRowLine && dragLineIndex >= 0) {
					adjustRowWeight(dragLineIndex, e.getY());
					repaint();
					fireLayoutChanged();
				} else if (pressedSlot != null) {
					int dx = Math.abs(e.getX() - pressX);
					int dy = Math.abs(e.getY() - pressY);
					if (dx > CLICK_THRESHOLD || dy > CLICK_THRESHOLD) {
						spanDragging = true;
						updateSpanPreview(e.getX(), e.getY());
						repaint();
						fireLayoutChanged();
					}
				}
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showContextMenu(e);
					pressedSlot = null;
					return;
				}

				if (draggingColLine || draggingRowLine) {
					draggingColLine = false;
					draggingRowLine = false;
					dragLineIndex = -1;
					setCursor(Cursor.getDefaultCursor());
					fireLayoutChanged();
				} else if (spanDragging && pressedSlot != null) {
					// Span already committed live during drag
					spanDragging = false;
					spanPreviewColSpan = 1;
					spanPreviewRowSpan = 1;
					pressedSlot = null;
					fireLayoutChanged();
					repaint();
				} else {
					pressedSlot = null;
				}
			}

			@Override
			public void mouseMoved(MouseEvent e) {
				int[] colLine = findColLine(e.getX());
				int[] rowLine = findRowLine(e.getY());
				if (colLine != null) {
					setCursor(Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR));
				} else if (rowLine != null) {
					setCursor(Cursor.getPredefinedCursor(Cursor.N_RESIZE_CURSOR));
				} else {
					setCursor(Cursor.getDefaultCursor());
				}
			}
		};
		addMouseListener(handler);
		addMouseMotionListener(handler);
	}

	private void showContextMenu(MouseEvent e) {
		int[] cell = pixelToCell(e.getX(), e.getY());
		CardSlotConfig slot = cardLayout.getSlotAt(cell[0], cell[1]);
		if (slot == null) return;

		JPopupMenu popup = new JPopupMenu();
		JMenuItem removeItem = new JMenuItem("Remove from card");
		removeItem.addActionListener(ev -> {
			cardLayout.setConfig(slot.withVisible(false));
			fireLayoutChanged();
			repaint();
		});
		popup.add(removeItem);

		// Reset span if element spans multiple cells
		if (slot.getColSpan() > 1 || slot.getRowSpan() > 1) {
			JMenuItem resetSpan = new JMenuItem("Reset span to 1\u00d71");
			resetSpan.addActionListener(ev -> {
				cardLayout.setConfig(slot.withColSpan(1).withRowSpan(1));
				fireLayoutChanged();
				repaint();
			});
			popup.add(resetSpan);
		}

		// Rename display label
		JMenuItem renameItem = new JMenuItem("Rename label\u2026");
		renameItem.addActionListener(ev -> {
			String current = slot.getEffectiveDisplayLabel();
			String input = (String) JOptionPane.showInputDialog(
					this, "Display label for " + slot.getElement().getDisplayName() + ":",
					"Rename Label", JOptionPane.PLAIN_MESSAGE,
					null, null, current);
			if (input != null) {
				String trimmed = input.trim();
				// Default name → null (use default); blank → "" (no label prefix)
				String label;
				if (trimmed.equals(slot.getElement().getDisplayName())) {
					label = null;
				} else {
					label = trimmed;
				}
				cardLayout.setConfig(slot.withDisplayLabel(label));
				fireLayoutChanged();
				repaint();
			}
		});
		popup.add(renameItem);

		popup.show(this, e.getX(), e.getY());
	}

	private void handleClickToAlign(MouseEvent e, CardSlotConfig slot) {
		int[] colEdges = computeColEdges();
		int[] rowEdges = computeRowEdges();
		int c = slot.getCol();
		int r = slot.getRow();

		int cx = colEdges[c];
		int cw = colEdges[Math.min(c + slot.getColSpan(), cardLayout.getCols())] - cx;
		int cy = rowEdges[r];
		int ch = rowEdges[Math.min(r + slot.getRowSpan(), cardLayout.getRows())] - cy;

		// X thirds
		int relX = e.getX() - cx;
		HAlign newH;
		if (relX < cw / 3) newH = HAlign.LEFT;
		else if (relX > cw * 2 / 3) newH = HAlign.RIGHT;
		else newH = HAlign.CENTER;

		// Y thirds
		int relY = e.getY() - cy;
		VAlign newV;
		if (relY < ch / 3) newV = VAlign.TOP;
		else if (relY > ch * 2 / 3) newV = VAlign.BOTTOM;
		else newV = VAlign.CENTER;

		if (newH != slot.getHAlign() || newV != slot.getVAlign()) {
			cardLayout.setConfig(slot.withHAlign(newH).withVAlign(newV));
			fireLayoutChanged();
			repaint();
		}
	}

	private void updateSpanPreview(int mouseX, int mouseY) {
		if (pressedSlot == null) return;
		int[] targetCell = pixelToCell(mouseX, mouseY);
		int originRow = pressedSlot.getRow();
		int originCol = pressedSlot.getCol();

		int newCS = Math.max(1, targetCell[1] - originCol + 1);
		int newRS = Math.max(1, targetCell[0] - originRow + 1);

		// Clamp to grid bounds
		newCS = Math.min(newCS, cardLayout.getCols() - originCol);
		newRS = Math.min(newRS, cardLayout.getRows() - originRow);

		// Check for overlap with other elements
		newCS = clampSpanForOverlap(pressedSlot, newCS, newRS)[0];
		newRS = clampSpanForOverlap(pressedSlot, newCS, newRS)[1];

		spanPreviewColSpan = newCS;
		spanPreviewRowSpan = newRS;

		// Commit span to layout so preview and other listeners see it live
		cardLayout.setConfig(pressedSlot.withColSpan(newCS).withRowSpan(newRS));
	}

	/**
	 * Clamp proposed span so it doesn't overlap other visible elements.
	 * Returns {clampedColSpan, clampedRowSpan}.
	 */
	private int[] clampSpanForOverlap(CardSlotConfig origin, int cs, int rs) {
		int oRow = origin.getRow();
		int oCol = origin.getCol();
		for (CardSlotConfig s : cardLayout.getVisibleSlots()) {
			if (s.getElement() == origin.getElement()) continue;
			int sRow = s.getRow();
			int sCol = s.getCol();
			int sEndCol = sCol + s.getColSpan();
			int sEndRow = sRow + s.getRowSpan();
			// Check if proposed rectangle [oRow..oRow+rs, oCol..oCol+cs] overlaps [sRow..sEndRow, sCol..sEndCol]
			if (oCol < sEndCol && oCol + cs > sCol && oRow < sEndRow && oRow + rs > sRow) {
				// Overlap found — clamp
				if (sCol >= oCol && sCol < oCol + cs) {
					// Other element is to the right; clamp col span
					cs = Math.min(cs, sCol - oCol);
				}
				if (sRow >= oRow && sRow < oRow + rs) {
					// Other element is below; clamp row span
					rs = Math.min(rs, sRow - oRow);
				}
			}
		}
		return new int[] { Math.max(1, cs), Math.max(1, rs) };
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		Graphics2D g2 = (Graphics2D) g;
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);
		g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
				RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

		int[] colEdges = computeColEdges();
		int[] rowEdges = computeRowEdges();

		Color gridLineColor = new Color(128, 128, 128, 100);
		Font labelFont = getFont().deriveFont(Font.BOLD, 11f);

		// Draw grid lines
		g2.setColor(gridLineColor);
		for (int i = 0; i <= cardLayout.getCols(); i++) {
			g2.drawLine(colEdges[i], rowEdges[0], colEdges[i], rowEdges[cardLayout.getRows()]);
		}
		for (int i = 0; i <= cardLayout.getRows(); i++) {
			g2.drawLine(colEdges[0], rowEdges[i], colEdges[cardLayout.getCols()], rowEdges[i]);
		}

		// Draw highlight on target cell during palette drag-over
		if (highlightRow >= 0 && highlightCol >= 0
				&& highlightRow < cardLayout.getRows() && highlightCol < cardLayout.getCols()) {
			int cx = colEdges[highlightCol];
			int cy = rowEdges[highlightRow];
			int cw = colEdges[highlightCol + 1] - cx;
			int ch = rowEdges[highlightRow + 1] - cy;
			g2.setColor(new Color(33, 150, 243, 50));
			g2.fillRect(cx + 1, cy + 1, cw - 1, ch - 1);
		}

		// Draw occupied cells
		for (CardSlotConfig slot : cardLayout.getVisibleSlots()) {
			int r = slot.getRow();
			int c = slot.getCol();
			if (r >= cardLayout.getRows() || c >= cardLayout.getCols()) continue;

			// Compute span-aware cell bounds
			int spanCols = Math.min(slot.getColSpan(), cardLayout.getCols() - c);
			int spanRows = Math.min(slot.getRowSpan(), cardLayout.getRows() - r);

			// During span drag, show preview span for the dragged element
			if (spanDragging && pressedSlot != null
					&& slot.getElement() == pressedSlot.getElement()) {
				spanCols = Math.min(spanPreviewColSpan, cardLayout.getCols() - c);
				spanRows = Math.min(spanPreviewRowSpan, cardLayout.getRows() - r);
			}

			int cx = colEdges[c];
			int cy = rowEdges[r];
			int cw = colEdges[c + spanCols] - cx;
			int ch = rowEdges[r + spanRows] - cy;

			// Semi-transparent tile fill
			Color tileColor = TILE_COLORS.getOrDefault(slot.getElement(), Color.GRAY);
			g2.setColor(new Color(tileColor.getRed(), tileColor.getGreen(),
					tileColor.getBlue(), 60));
			g2.fillRect(cx + 1, cy + 1, cw - 1, ch - 1);

			// Element display name centered in cell
			g2.setFont(labelFont);
			g2.setColor(tileColor);
			FontMetrics fm = g2.getFontMetrics();
			String name = slot.getElement().getDisplayName();
			int textW = fm.stringWidth(name);
			int tx = cx + (cw - textW) / 2;
			int ty = cy + (ch + fm.getAscent() - fm.getDescent()) / 2;
			g2.drawString(name, tx, ty);

			// Small alignment indicator dot
			paintAlignmentDot(g2, cx, cy, cw, ch, slot.getHAlign(), slot.getVAlign(), tileColor);
		}

		// Span drag overlay
		if (spanDragging && pressedSlot != null) {
			int r = pressedSlot.getRow();
			int c = pressedSlot.getCol();
			int spanCols = Math.min(spanPreviewColSpan, cardLayout.getCols() - c);
			int spanRows = Math.min(spanPreviewRowSpan, cardLayout.getRows() - r);
			int cx = colEdges[c];
			int cy = rowEdges[r];
			int cw = colEdges[c + spanCols] - cx;
			int ch = rowEdges[r + spanRows] - cy;

			g2.setColor(new Color(33, 150, 243, 30));
			g2.fillRect(cx + 1, cy + 1, cw - 1, ch - 1);
			g2.setColor(new Color(33, 150, 243, 120));
			g2.drawRect(cx, cy, cw, ch);
		}
	}

	private void paintAlignmentDot(Graphics2D g2, int cx, int cy, int cw, int ch,
			HAlign hAlign, VAlign vAlign, Color color) {
		int dotSize = 5;
		int margin = 3;
		int dx;
		switch (hAlign) {
			case LEFT: dx = cx + margin; break;
			case RIGHT: dx = cx + cw - dotSize - margin; break;
			default: dx = cx + (cw - dotSize) / 2; break;
		}
		int dy;
		switch (vAlign) {
			case TOP: dy = cy + margin; break;
			case BOTTOM: dy = cy + ch - dotSize - margin; break;
			default: dy = cy + (ch - dotSize) / 2; break;
		}
		g2.setColor(color);
		g2.fillOval(dx, dy, dotSize, dotSize);
	}

	// ---- coordinate helpers ----

	private int[] computeColEdges() {
		int padding = 8;
		int contentW = getWidth() - 2 * padding;
		return CardRenderer.computeEdges(cardLayout.getColWeights(), contentW, padding);
	}

	private int[] computeRowEdges() {
		int padding = 8;
		int contentH = getHeight() - 2 * padding;
		return CardRenderer.computeEdges(cardLayout.getRowWeights(), contentH, padding);
	}

	private int[] pixelToCell(int px, int py) {
		int[] colEdges = computeColEdges();
		int[] rowEdges = computeRowEdges();

		int c = cardLayout.getCols() - 1;
		for (int i = 0; i < cardLayout.getCols(); i++) {
			if (px < colEdges[i + 1]) { c = i; break; }
		}
		int r = cardLayout.getRows() - 1;
		for (int i = 0; i < cardLayout.getRows(); i++) {
			if (py < rowEdges[i + 1]) { r = i; break; }
		}
		return new int[] { r, c };
	}

	/** Find column grid line near x. Returns {lineIndex} or null. */
	private int[] findColLine(int x) {
		int[] colEdges = computeColEdges();
		// Only interior lines (indices 1..cols-1) are draggable
		for (int i = 1; i < cardLayout.getCols(); i++) {
			if (Math.abs(x - colEdges[i]) <= GRID_LINE_HIT) {
				return new int[] { i };
			}
		}
		return null;
	}

	/** Find row grid line near y. Returns {lineIndex} or null. */
	private int[] findRowLine(int y) {
		int[] rowEdges = computeRowEdges();
		for (int i = 1; i < cardLayout.getRows(); i++) {
			if (Math.abs(y - rowEdges[i]) <= GRID_LINE_HIT) {
				return new int[] { i };
			}
		}
		return null;
	}

	private void adjustColWeight(int lineIndex, int mouseX) {
		int padding = 8;
		int contentW = getWidth() - 2 * padding;
		double[] weights = cardLayout.getColWeights();
		// lineIndex is between col[lineIndex-1] and col[lineIndex]
		double target = (mouseX - padding) / (double) contentW;
		// Compute cumulative up to lineIndex-1
		double cumBefore = 0;
		for (int i = 0; i < lineIndex - 1; i++) cumBefore += weights[i];
		// Compute cumulative up to lineIndex
		double cumAfter = cumBefore + weights[lineIndex - 1] + weights[lineIndex];

		double newLeft = target - cumBefore;
		double newRight = cumAfter - target;
		if (newLeft < CardLayout.MIN_WEIGHT) newLeft = CardLayout.MIN_WEIGHT;
		if (newRight < CardLayout.MIN_WEIGHT) newRight = CardLayout.MIN_WEIGHT;

		weights[lineIndex - 1] = newLeft;
		weights[lineIndex] = newRight;
		cardLayout.setColWeights(weights);
	}

	private void adjustRowWeight(int lineIndex, int mouseY) {
		int padding = 8;
		int contentH = getHeight() - 2 * padding;
		double[] weights = cardLayout.getRowWeights();
		double target = (mouseY - padding) / (double) contentH;
		double cumBefore = 0;
		for (int i = 0; i < lineIndex - 1; i++) cumBefore += weights[i];
		double cumAfter = cumBefore + weights[lineIndex - 1] + weights[lineIndex];

		double newTop = target - cumBefore;
		double newBottom = cumAfter - target;
		if (newTop < CardLayout.MIN_WEIGHT) newTop = CardLayout.MIN_WEIGHT;
		if (newBottom < CardLayout.MIN_WEIGHT) newBottom = CardLayout.MIN_WEIGHT;

		weights[lineIndex - 1] = newTop;
		weights[lineIndex] = newBottom;
		cardLayout.setRowWeights(weights);
	}
}
