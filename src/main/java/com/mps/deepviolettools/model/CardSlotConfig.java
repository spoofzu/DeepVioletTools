package com.mps.deepviolettools.model;

/**
 * Describes one element's placement on a host card grid: which cell
 * (row, col), horizontal/vertical alignment within the cell, visibility,
 * how many columns/rows the element spans, and an optional custom
 * display label.
 *
 * <p>Instances are effectively value objects.  Mutation methods return
 * new copies to support immutable-style updates.</p>
 */
public class CardSlotConfig {

	/** Horizontal alignment within a grid cell. */
	public enum HAlign { LEFT, CENTER, RIGHT }

	/** Vertical alignment within a grid cell. */
	public enum VAlign { TOP, CENTER, BOTTOM }

	private final CardMetaElement element;
	private final int row;
	private final int col;
	private final HAlign hAlign;
	private final VAlign vAlign;
	private final boolean visible;
	private final int colSpan;
	private final int rowSpan;
	private final String displayLabel;

	public CardSlotConfig(CardMetaElement element, int row, int col,
			HAlign hAlign, VAlign vAlign, boolean visible,
			int colSpan, int rowSpan, String displayLabel) {
		this.element = element;
		this.row = row;
		this.col = col;
		this.hAlign = hAlign;
		this.vAlign = vAlign;
		this.visible = visible;
		this.colSpan = Math.max(1, colSpan);
		this.rowSpan = Math.max(1, rowSpan);
		this.displayLabel = displayLabel;
	}

	/** Constructor with default display label (null = use element name). */
	public CardSlotConfig(CardMetaElement element, int row, int col,
			HAlign hAlign, VAlign vAlign, boolean visible,
			int colSpan, int rowSpan) {
		this(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, null);
	}

	/** Convenience constructor with colSpan=1, rowSpan=1. */
	public CardSlotConfig(CardMetaElement element, int row, int col,
			HAlign hAlign, VAlign vAlign, boolean visible) {
		this(element, row, col, hAlign, vAlign, visible, 1, 1, null);
	}

	public CardMetaElement getElement() { return element; }
	public int getRow() { return row; }
	public int getCol() { return col; }
	public HAlign getHAlign() { return hAlign; }
	public VAlign getVAlign() { return vAlign; }
	public boolean isVisible() { return visible; }
	public int getColSpan() { return colSpan; }
	public int getRowSpan() { return rowSpan; }

	/**
	 * Return the custom display label, or null if using the default
	 * element name.
	 */
	public String getDisplayLabel() { return displayLabel; }

	/**
	 * Return the label to show on rendered cards: the custom display
	 * label if set, otherwise the element's default display name.
	 */
	public String getEffectiveDisplayLabel() {
		return displayLabel != null ? displayLabel : element.getDisplayName();
	}

	/** Return a copy with a different row. */
	public CardSlotConfig withRow(int row) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different column. */
	public CardSlotConfig withCol(int col) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different horizontal alignment. */
	public CardSlotConfig withHAlign(HAlign hAlign) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different vertical alignment. */
	public CardSlotConfig withVAlign(VAlign vAlign) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different visibility. */
	public CardSlotConfig withVisible(boolean visible) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different column span. */
	public CardSlotConfig withColSpan(int colSpan) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different row span. */
	public CardSlotConfig withRowSpan(int rowSpan) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/** Return a copy with a different display label (null = use default). */
	public CardSlotConfig withDisplayLabel(String displayLabel) {
		return new CardSlotConfig(element, row, col, hAlign, vAlign, visible, colSpan, rowSpan, displayLabel);
	}

	/**
	 * Serialize to the property-file format.  If a custom display label is
	 * set, writes 8 fields; otherwise writes 7 fields for backward
	 * compatibility.
	 */
	public String toPropertyValue() {
		String base = row + "," + col + "," + hAlign + "," + vAlign + "," + visible
				+ "," + colSpan + "," + rowSpan;
		if (displayLabel != null) {
			return base + "," + displayLabel;
		}
		return base;
	}

	/**
	 * Deserialize from the property-file format.  Supports four formats:
	 * <ul>
	 *   <li>8+ field: {@code row,col,HAlign,VAlign,visible,colSpan,rowSpan,displayLabel}</li>
	 *   <li>7-field: {@code row,col,HAlign,VAlign,visible,colSpan,rowSpan}</li>
	 *   <li>5-field: {@code row,col,HAlign,VAlign,visible} (span defaults to 1)</li>
	 *   <li>4-field legacy: {@code slotIndex,HAlign,VAnchor,visible}</li>
	 * </ul>
	 *
	 * @param element the element this config belongs to
	 * @param value   the property value
	 * @return parsed config, or null if the format is invalid
	 */
	public static CardSlotConfig fromPropertyValue(CardMetaElement element, String value) {
		if (value == null) return null;
		// Split into at most 8 parts so that display labels containing
		// commas are preserved in the 8th part.
		String[] parts = value.split(",", 8);
		if (parts.length >= 8) {
			// 8-field format: row,col,HAlign,VAlign,visible,colSpan,rowSpan,displayLabel
			try {
				int r = Integer.parseInt(parts[0].trim());
				int c = Integer.parseInt(parts[1].trim());
				HAlign ha = HAlign.valueOf(parts[2].trim());
				VAlign va = VAlign.valueOf(parts[3].trim());
				boolean vis = Boolean.parseBoolean(parts[4].trim());
				int cs = Integer.parseInt(parts[5].trim());
				int rs = Integer.parseInt(parts[6].trim());
				String label = parts[7].trim();
				return new CardSlotConfig(element, r, c, ha, va, vis, cs, rs, label);
			} catch (IllegalArgumentException e) {
				return null;
			}
		} else if (parts.length == 7) {
			// 7-field format: row,col,HAlign,VAlign,visible,colSpan,rowSpan
			try {
				int r = Integer.parseInt(parts[0].trim());
				int c = Integer.parseInt(parts[1].trim());
				HAlign ha = HAlign.valueOf(parts[2].trim());
				VAlign va = VAlign.valueOf(parts[3].trim());
				boolean vis = Boolean.parseBoolean(parts[4].trim());
				int cs = Integer.parseInt(parts[5].trim());
				int rs = Integer.parseInt(parts[6].trim());
				return new CardSlotConfig(element, r, c, ha, va, vis, cs, rs);
			} catch (IllegalArgumentException e) {
				return null;
			}
		} else if (parts.length == 5) {
			// 5-field grid format: row,col,HAlign,VAlign,visible (span=1)
			try {
				int r = Integer.parseInt(parts[0].trim());
				int c = Integer.parseInt(parts[1].trim());
				HAlign ha = HAlign.valueOf(parts[2].trim());
				VAlign va = VAlign.valueOf(parts[3].trim());
				boolean vis = Boolean.parseBoolean(parts[4].trim());
				return new CardSlotConfig(element, r, c, ha, va, vis);
			} catch (IllegalArgumentException e) {
				return null;
			}
		} else if (parts.length == 4) {
			// Legacy slot format: slotIndex,HAlign,VAnchor,visible
			// Migrate: slotIndex -> row, LEFT->col0 / CENTER->col1 / RIGHT->col2,
			//          VAnchor TOP->VAlign.CENTER, VAnchor BOTTOM->VAlign.BOTTOM
			try {
				int slotIndex = Integer.parseInt(parts[0].trim());
				HAlign ha = HAlign.valueOf(parts[1].trim());
				String anchorStr = parts[2].trim();
				boolean vis = Boolean.parseBoolean(parts[3].trim());

				int r = slotIndex;
				int c;
				switch (ha) {
					case LEFT: c = 0; break;
					case RIGHT: c = 2; break;
					default: c = 1; break;
				}
				VAlign va = "BOTTOM".equals(anchorStr) ? VAlign.BOTTOM : VAlign.CENTER;
				return new CardSlotConfig(element, r, c, HAlign.CENTER, va, vis);
			} catch (IllegalArgumentException e) {
				return null;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return element.getPropertyKey() + "=" + toPropertyValue();
	}
}
