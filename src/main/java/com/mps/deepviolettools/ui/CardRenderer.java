package com.mps.deepviolettools.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.BasicStroke;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.model.CardMetaElement;
import com.mps.deepviolettools.model.CardSlotConfig;
import com.mps.deepviolettools.model.CardSlotConfig.HAlign;
import com.mps.deepviolettools.model.CardSlotConfig.VAlign;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * Shared card rendering logic used by both {@link HostCard} (live data)
 * and {@link CardLayoutPreview} (sample data in the settings dialog).
 *
 * <p>Rendering is grid-cell-based: each visible element occupies a cell
 * defined by the layout's column/row weights.  Elements are positioned
 * within their cell according to their HAlign/VAlign settings.</p>
 */
public final class CardRenderer {

	private static final int ARC = 10;
	private static final int PADDING = 12;
	private static final int CELL_INSET = 4;
	private static final int MINI_BAR_BLOCKS = 10;
	private static final int MINI_BAR_HEIGHT = 4;
	private static final int MINI_BAR_GAP = 2;

	/** Provides the text/data for each card meta element. */
	public interface ElementDataProvider {
		String getText(CardMetaElement element);
		String getGrade();
		int[][] getCategoryBars();
		String[] getCategoryNames();
	}

	private CardRenderer() {}

	/** Gray used for badge and risk bars when rendering placeholder cards. */
	private static final Color PLACEHOLDER_GRAY = new Color(0x9E9E9E);

	/**
	 * Paint a complete card using the configured grid layout.
	 *
	 * @param g2           graphics context
	 * @param w            card width
	 * @param h            card height
	 * @param prefs        font/color preferences
	 * @param layout       the card layout configuration
	 * @param data         element data provider
	 * @param selected     whether the card is currently selected
	 * @param hovered      whether the card is currently hovered
	 * @param highlightRow row to highlight for drag-over, or -1
	 * @param highlightCol col to highlight for drag-over, or -1
	 */
	public static void paintCard(Graphics2D g2, int w, int h,
			FontPreferences prefs, CardLayout layout,
			ElementDataProvider data, boolean selected, boolean hovered,
			int highlightRow, int highlightCol) {
		paintCard(g2, w, h, prefs, layout, data, selected, hovered,
				highlightRow, highlightCol, false);
	}

	/**
	 * Paint a complete card using the configured grid layout.
	 *
	 * @param g2           graphics context
	 * @param w            card width
	 * @param h            card height
	 * @param prefs        font/color preferences
	 * @param layout       the card layout configuration
	 * @param data         element data provider
	 * @param selected     whether the card is currently selected
	 * @param hovered      whether the card is currently hovered
	 * @param highlightRow row to highlight for drag-over, or -1
	 * @param highlightCol col to highlight for drag-over, or -1
	 * @param placeholder  true to render in gray (ghosted) style
	 */
	public static void paintCard(Graphics2D g2, int w, int h,
			FontPreferences prefs, CardLayout layout,
			ElementDataProvider data, boolean selected, boolean hovered,
			int highlightRow, int highlightCol, boolean placeholder) {

		Color bgColor = prefs.getCardBg();
		Color fgColor = prefs.getCardText();

		// Card background
		g2.setColor(bgColor);
		g2.fillRoundRect(0, 0, w, h, ARC, ARC);

		// Border
		if (selected) {
			g2.setColor(prefs.getCardSelected());
			g2.setStroke(new BasicStroke(3f));
			g2.drawRoundRect(1, 1, w - 3, h - 3, ARC, ARC);
			g2.setStroke(new BasicStroke(1f));
		} else if (hovered) {
			g2.setColor(fgColor);
			g2.drawRoundRect(0, 0, w - 1, h - 1, ARC, ARC);
		} else {
			g2.setColor(prefs.getCardBorder());
			g2.drawRoundRect(0, 0, w - 1, h - 1, ARC, ARC);
		}

		// Compute cell edges
		int contentW = w - 2 * PADDING;
		int contentH = h - 2 * PADDING;
		int[] colX = computeEdges(layout.getColWeights(), contentW, PADDING);
		int[] rowY = computeEdges(layout.getRowWeights(), contentH, PADDING);

		// Highlight drop target cell
		if (highlightRow >= 0 && highlightCol >= 0
				&& highlightRow < layout.getRows() && highlightCol < layout.getCols()) {
			int cx = colX[highlightCol];
			int cy = rowY[highlightRow];
			int cw = colX[highlightCol + 1] - cx;
			int ch = rowY[highlightRow + 1] - cy;
			g2.setColor(new Color(prefs.getCardSelected().getRed(),
					prefs.getCardSelected().getGreen(),
					prefs.getCardSelected().getBlue(), 40));
			g2.fillRect(cx, cy, cw, ch);
		}

		Font cardFont = prefs.getCardFont();
		int badgeSize = prefs.getCardBadgeSize();

		// Paint each visible element in its cell (span-aware)
		for (CardSlotConfig slot : layout.getVisibleSlots()) {
			int r = slot.getRow();
			int c = slot.getCol();
			if (r >= layout.getRows() || c >= layout.getCols()) continue;

			int spanCols = Math.min(slot.getColSpan(), layout.getCols() - c);
			int spanRows = Math.min(slot.getRowSpan(), layout.getRows() - r);
			int cx = colX[c] + CELL_INSET;
			int cw = colX[c + spanCols] - colX[c] - 2 * CELL_INSET;
			int cy = rowY[r] + CELL_INSET;
			int ch = rowY[r + spanRows] - rowY[r] - 2 * CELL_INSET;

			if (cw <= 0 || ch <= 0) continue;

			CardMetaElement elem = slot.getElement();

			if (elem == CardMetaElement.GRADE) {
				int size = Math.min(Math.min(cw, ch), badgeSize);
				int[] pos = computeAlignedPosition(cx, cy, cw, ch,
						size, size, slot.getHAlign(), slot.getVAlign());
				paintGradeBadge(g2, pos[0], pos[1], size, cardFont, data, placeholder);
			} else if (elem == CardMetaElement.RISK_BARS) {
				paintRiskBarsInCell(g2, cx, cy, cw, ch, slot, prefs, data, placeholder);
			} else {
				paintTextInCell(g2, elem, slot, cx, cy, cw, ch, cardFont, prefs, data);
			}
		}
	}

	/**
	 * Compute pixel edges from proportional weights.
	 * Returns array of length (count+1) with edge positions.
	 */
	public static int[] computeEdges(double[] weights, int totalSize, int offset) {
		int[] edges = new int[weights.length + 1];
		edges[0] = offset;
		double cumulative = 0;
		for (int i = 0; i < weights.length; i++) {
			cumulative += weights[i];
			edges[i + 1] = offset + (int) Math.round(cumulative * totalSize);
		}
		// Ensure last edge exactly matches
		edges[weights.length] = offset + totalSize;
		return edges;
	}

	/**
	 * Compute top-left position for content of given size within a cell,
	 * respecting horizontal and vertical alignment.
	 */
	static int[] computeAlignedPosition(int cx, int cy, int cw, int ch,
			int contentW, int contentH, HAlign hAlign, VAlign vAlign) {
		int x;
		switch (hAlign) {
			case LEFT: x = cx; break;
			case RIGHT: x = cx + cw - contentW; break;
			default: x = cx + (cw - contentW) / 2; break;
		}
		int y;
		switch (vAlign) {
			case TOP: y = cy; break;
			case BOTTOM: y = cy + ch - contentH; break;
			default: y = cy + (ch - contentH) / 2; break;
		}
		return new int[] { x, y };
	}

	private static void paintGradeBadge(Graphics2D g2, int x, int y,
			int badgeSize, Font cardFont, ElementDataProvider data,
			boolean placeholder) {
		String grade = data.getGrade();
		Color badgeColor = placeholder ? PLACEHOLDER_GRAY
				: GradeDistributionBar.colorForGrade(grade);
		g2.setColor(badgeColor);
		g2.fillOval(x, y, badgeSize, badgeSize);
		g2.setColor(Color.WHITE);
		Font badgeFont = cardFont.deriveFont(Font.BOLD, cardFont.getSize2D());
		g2.setFont(badgeFont);
		FontMetrics bfm = g2.getFontMetrics();
		int bx = x + (badgeSize - bfm.stringWidth(grade)) / 2;
		int by = y + (badgeSize + bfm.getAscent() - bfm.getDescent()) / 2;
		g2.drawString(grade, bx, by);
	}

	private static void paintTextInCell(Graphics2D g2, CardMetaElement elem,
			CardSlotConfig slot, int cx, int cy, int cw, int ch,
			Font cardFont, FontPreferences prefs, ElementDataProvider data) {
		String text = data.getText(elem);
		if (text == null || text.isEmpty()) return;

		Font dataFont = cardFont.deriveFont(Font.PLAIN, cardFont.getSize2D() - 1f);
		g2.setFont(dataFont);
		FontMetrics dfm = g2.getFontMetrics();

		String effectiveLabel = slot.getEffectiveDisplayLabel();
		String label = effectiveLabel.isEmpty() ? text : effectiveLabel + ": " + text;
		String clipped = clipText(g2, label, cw);
		int textW = dfm.stringWidth(clipped);
		int textH = dfm.getAscent() + dfm.getDescent();

		int[] pos = computeAlignedPosition(cx, cy, cw, ch,
				textW, textH, slot.getHAlign(), slot.getVAlign());

		g2.setColor(prefs.getCardDim());
		g2.drawString(clipped, pos[0], pos[1] + dfm.getAscent());
	}

	private static void paintRiskBarsInCell(Graphics2D g2, int cx, int cy,
			int cw, int ch, CardSlotConfig slot,
			FontPreferences prefs, ElementDataProvider data,
			boolean placeholder) {
		int[][] categoryBars = data.getCategoryBars();
		if (categoryBars == null || categoryBars.length == 0) return;

		Color passColor = placeholder ? new Color(0xB0B0B0) : prefs.getRiskPass();
		Color incColor = placeholder ? new Color(0x8A8A8A) : prefs.getRiskInconclusive();
		Color failColor = placeholder ? new Color(0x666666) : prefs.getRiskFail();

		int barCount = categoryBars.length;

		// Scale bar height and gap to fill the available cell height
		int barH = Math.max(MINI_BAR_HEIGHT, (ch - (barCount - 1) * MINI_BAR_GAP) / barCount);
		int barGap = Math.max(1, barH / 3);
		int totalH = barCount * barH + (barCount - 1) * barGap;
		// Clamp so bars don't exceed cell
		if (totalH > ch) {
			barH = Math.max(2, (ch - (barCount - 1)) / barCount);
			barGap = 1;
			totalH = barCount * barH + (barCount - 1) * barGap;
		}

		// Vertical alignment
		int startY;
		switch (slot.getVAlign()) {
			case TOP: startY = cy; break;
			case BOTTOM: startY = cy + ch - totalH; break;
			default: startY = cy + (ch - totalH) / 2; break;
		}

		int gaps = MINI_BAR_BLOCKS - 1;
		int availW = cw - gaps;
		int blockW = availW / MINI_BAR_BLOCKS;
		int extraPx = availW % MINI_BAR_BLOCKS;

		for (int i = 0; i < barCount; i++) {
			int barY = startY + i * (barH + barGap);
			int bx = cx;
			int[] bar = categoryBars[i];

			for (int b = 0; b < MINI_BAR_BLOCKS; b++) {
				int bw = blockW + (b < extraPx ? 1 : 0);
				if (b < bar[0]) {
					g2.setColor(passColor);
				} else if (b < bar[0] + bar[1]) {
					g2.setColor(incColor);
				} else {
					g2.setColor(failColor);
				}
				g2.fillRect(bx, barY, bw, barH);
				bx += bw + 1;
			}
		}
	}

	static String clipText(Graphics2D g2, String text, int maxWidth) {
		FontMetrics fm = g2.getFontMetrics();
		if (fm.stringWidth(text) <= maxWidth) return text;
		String ellipsis = "...";
		int ellipsisW = fm.stringWidth(ellipsis);
		for (int i = text.length() - 1; i > 0; i--) {
			if (fm.stringWidth(text.substring(0, i)) + ellipsisW <= maxWidth) {
				return text.substring(0, i) + ellipsis;
			}
		}
		return ellipsis;
	}
}
