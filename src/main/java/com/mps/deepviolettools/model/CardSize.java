package com.mps.deepviolettools.model;

/**
 * Predefined card sizes for host cards in the scan results view.
 */
public enum CardSize {

	SMALL(240, 180),
	MEDIUM(300, 220),
	LARGE(380, 280);

	private final int width;
	private final int height;

	CardSize(int width, int height) {
		this.width = width;
		this.height = height;
	}

	public int getWidth() { return width; }
	public int getHeight() { return height; }

	/**
	 * Look up a CardSize by name, returning SMALL if not found.
	 */
	public static CardSize fromString(String name) {
		if (name != null) {
			try {
				return valueOf(name.toUpperCase());
			} catch (IllegalArgumentException ignored) {
			}
		}
		return SMALL;
	}
}
