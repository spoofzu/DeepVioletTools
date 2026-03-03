package com.mps.deepviolettools.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.mps.deepviolettools.model.CardSlotConfig.HAlign;
import com.mps.deepviolettools.model.CardSlotConfig.VAlign;

/**
 * Complete card layout configuration — holds one {@link CardSlotConfig}
 * per {@link CardMetaElement} on a configurable grid.  The layout determines
 * which metadata elements appear on a host card, their cell positions,
 * alignment, and visibility.
 *
 * <p>Grid dimensions are configurable: cols (1-5, default 3) and rows
 * (2-9, default 5).  Cell proportions are controlled by column and row
 * weights that sum to 1.0.  One element per cell max.</p>
 */
public class CardLayout {

	public static final int MIN_COLS = 1;
	public static final int MAX_COLS = 5;
	public static final int DEFAULT_COLS = 3;

	public static final int MIN_ROWS = 2;
	public static final int MAX_ROWS = 9;
	public static final int DEFAULT_ROWS = 5;

	public static final double MIN_WEIGHT = 0.05;

	private final Map<CardMetaElement, CardSlotConfig> configs;
	private int cols;
	private int rows;
	private double[] colWeights;
	private double[] rowWeights;

	public CardLayout(List<CardSlotConfig> slots, int cols, int rows,
			double[] colWeights, double[] rowWeights) {
		configs = new EnumMap<>(CardMetaElement.class);
		for (CardSlotConfig s : slots) {
			configs.put(s.getElement(), s);
		}
		this.cols = Math.max(MIN_COLS, Math.min(MAX_COLS, cols));
		this.rows = Math.max(MIN_ROWS, Math.min(MAX_ROWS, rows));
		this.colWeights = normalizeWeights(colWeights, this.cols);
		this.rowWeights = normalizeWeights(rowWeights, this.rows);
	}

	/** Convenience constructor using default 3x5 grid with uniform weights. */
	public CardLayout(List<CardSlotConfig> slots) {
		this(slots, DEFAULT_COLS, DEFAULT_ROWS,
				uniformWeights(DEFAULT_COLS), uniformWeights(DEFAULT_ROWS));
	}

	public int getCols() { return cols; }
	public int getRows() { return rows; }
	public double[] getColWeights() { return Arrays.copyOf(colWeights, colWeights.length); }
	public double[] getRowWeights() { return Arrays.copyOf(rowWeights, rowWeights.length); }

	public void setColWeights(double[] weights) {
		this.colWeights = normalizeWeights(weights, cols);
	}

	public void setRowWeights(double[] weights) {
		this.rowWeights = normalizeWeights(weights, rows);
	}

	/** Return all slot configs as a list. */
	public List<CardSlotConfig> getSlots() {
		return new ArrayList<>(configs.values());
	}

	/** Return visible slots sorted by row then col. */
	public List<CardSlotConfig> getVisibleSlots() {
		return configs.values().stream()
				.filter(CardSlotConfig::isVisible)
				.sorted(Comparator.comparingInt(CardSlotConfig::getRow)
						.thenComparingInt(CardSlotConfig::getCol))
				.collect(Collectors.toList());
	}

	/** Return the config for a specific element. */
	public CardSlotConfig getConfig(CardMetaElement element) {
		return configs.get(element);
	}

	/** Replace or add the config for a specific element. */
	public void setConfig(CardSlotConfig config) {
		configs.put(config.getElement(), config);
	}

	/**
	 * Return the slot at a given cell, or null if empty/invisible.
	 * Span-aware: returns the element whose span rectangle covers (row, col).
	 */
	public CardSlotConfig getSlotAt(int row, int col) {
		for (CardSlotConfig s : configs.values()) {
			if (s.isVisible()
					&& row >= s.getRow() && row < s.getRow() + s.getRowSpan()
					&& col >= s.getCol() && col < s.getCol() + s.getColSpan()) {
				return s;
			}
		}
		return null;
	}

	/** Check if a cell is occupied by a visible element. */
	public boolean isCellOccupied(int row, int col) {
		return getSlotAt(row, col) != null;
	}

	/** Return the set of visible elements. */
	public Set<CardMetaElement> getVisibleElements() {
		return configs.values().stream()
				.filter(CardSlotConfig::isVisible)
				.map(CardSlotConfig::getElement)
				.collect(Collectors.toSet());
	}

	/**
	 * Resize the grid.  Elements outside the new bounds become invisible.
	 */
	public void resizeGrid(int newCols, int newRows) {
		newCols = Math.max(MIN_COLS, Math.min(MAX_COLS, newCols));
		newRows = Math.max(MIN_ROWS, Math.min(MAX_ROWS, newRows));

		// Hide elements that fall outside the new grid or whose span exceeds bounds
		for (CardMetaElement elem : CardMetaElement.values()) {
			CardSlotConfig s = configs.get(elem);
			if (s != null && s.isVisible()) {
				if (s.getRow() >= newRows || s.getCol() >= newCols) {
					configs.put(elem, s.withVisible(false));
				} else if (s.getCol() + s.getColSpan() > newCols
						|| s.getRow() + s.getRowSpan() > newRows) {
					// Clamp span to fit within new bounds
					int clampedCS = Math.min(s.getColSpan(), newCols - s.getCol());
					int clampedRS = Math.min(s.getRowSpan(), newRows - s.getRow());
					configs.put(elem, s.withColSpan(clampedCS).withRowSpan(clampedRS));
				}
			}
		}

		// Adjust weights
		this.colWeights = resizeWeights(colWeights, cols, newCols);
		this.rowWeights = resizeWeights(rowWeights, rows, newRows);
		this.cols = newCols;
		this.rows = newRows;
	}

	/**
	 * Create the default layout that matches a 3x5 grid.
	 */
	public static CardLayout defaultLayout() {
		List<CardSlotConfig> slots = new ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.GRADE, 0, 0, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.HOSTNAME, 0, 1, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.SCORE, 1, 0, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.TLS_VERSION, 1, 1, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.CIPHERS, 2, 0, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.HEADERS, 2, 1, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.CERT, 3, 0, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.IP, 3, 1, HAlign.CENTER, VAlign.CENTER, false));
		slots.add(new CardSlotConfig(CardMetaElement.RISK_BARS, 4, 0, HAlign.CENTER, VAlign.CENTER, true));
		slots.add(new CardSlotConfig(CardMetaElement.CERT_EXPIRY, 3, 2, HAlign.CENTER, VAlign.CENTER, false));
		slots.add(new CardSlotConfig(CardMetaElement.KEY_INFO, 4, 1, HAlign.CENTER, VAlign.CENTER, false));
		slots.add(new CardSlotConfig(CardMetaElement.ISSUER, 4, 2, HAlign.CENTER, VAlign.CENTER, false));
		slots.add(new CardSlotConfig(CardMetaElement.SAN_COUNT, 0, 2, HAlign.CENTER, VAlign.CENTER, false));
		slots.add(new CardSlotConfig(CardMetaElement.REVOCATION, 1, 2, HAlign.CENTER, VAlign.CENTER, false));
		return new CardLayout(slots, DEFAULT_COLS, DEFAULT_ROWS,
				uniformWeights(DEFAULT_COLS), uniformWeights(DEFAULT_ROWS));
	}

	/**
	 * Create a deep copy of this layout.
	 */
	public CardLayout copy() {
		List<CardSlotConfig> copies = new ArrayList<>();
		for (CardSlotConfig s : configs.values()) {
			copies.add(new CardSlotConfig(
					s.getElement(), s.getRow(), s.getCol(),
					s.getHAlign(), s.getVAlign(), s.isVisible(),
					s.getColSpan(), s.getRowSpan(), s.getDisplayLabel()));
		}
		return new CardLayout(copies, cols, rows,
				Arrays.copyOf(colWeights, colWeights.length),
				Arrays.copyOf(rowWeights, rowWeights.length));
	}

	/** Create uniform weights for n divisions. */
	public static double[] uniformWeights(int n) {
		double[] w = new double[n];
		Arrays.fill(w, 1.0 / n);
		return w;
	}

	/** Normalize weights: ensure min weight, correct length, sum to 1.0. */
	static double[] normalizeWeights(double[] weights, int size) {
		double[] result = new double[size];
		if (weights == null || weights.length == 0) {
			Arrays.fill(result, 1.0 / size);
			return result;
		}
		// Copy available values, enforce minimum
		for (int i = 0; i < size; i++) {
			result[i] = i < weights.length ? Math.max(MIN_WEIGHT, weights[i]) : MIN_WEIGHT;
		}
		// Normalize: distribute proportionally so all stay >= MIN_WEIGHT
		// First, compute how much total "above-minimum" weight we have
		double minTotal = size * MIN_WEIGHT;
		double available = 1.0 - minTotal;
		if (available < 0) available = 0;
		double aboveMinSum = 0;
		for (int i = 0; i < size; i++) {
			aboveMinSum += result[i] - MIN_WEIGHT;
		}
		if (aboveMinSum > 0 && available > 0) {
			for (int i = 0; i < size; i++) {
				result[i] = MIN_WEIGHT + (result[i] - MIN_WEIGHT) / aboveMinSum * available;
			}
		} else {
			// All at minimum — uniform
			Arrays.fill(result, 1.0 / size);
		}
		return result;
	}

	/** Resize a weight array, distributing new columns uniformly. */
	private static double[] resizeWeights(double[] old, int oldSize, int newSize) {
		if (newSize == oldSize) return Arrays.copyOf(old, old.length);
		double[] result = new double[newSize];
		if (newSize < oldSize) {
			// Shrink: take first newSize weights, re-normalize
			System.arraycopy(old, 0, result, 0, newSize);
		} else {
			// Grow: keep old weights, fill new ones uniformly
			System.arraycopy(old, 0, result, 0, oldSize);
			double newWeight = 1.0 / newSize;
			for (int i = oldSize; i < newSize; i++) {
				result[i] = newWeight;
			}
		}
		return normalizeWeights(result, newSize);
	}
}
