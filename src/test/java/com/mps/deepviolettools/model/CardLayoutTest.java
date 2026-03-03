package com.mps.deepviolettools.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.mps.deepviolettools.model.CardSlotConfig.HAlign;
import com.mps.deepviolettools.model.CardSlotConfig.VAlign;

/**
 * Unit tests for {@link CardLayout}, {@link CardSlotConfig}, and
 * {@link CardMetaElement} with grid-based model.
 */
class CardLayoutTest {

	@Test
	void defaultLayoutContainsAllElements() {
		CardLayout layout = CardLayout.defaultLayout();
		List<CardSlotConfig> slots = layout.getSlots();
		assertEquals(CardMetaElement.values().length, slots.size(),
				"Default layout should have one config per element");
	}

	@Test
	void defaultLayoutGridDimensions() {
		CardLayout layout = CardLayout.defaultLayout();
		assertEquals(3, layout.getCols());
		assertEquals(5, layout.getRows());
	}

	@Test
	void defaultLayoutVisibleElements() {
		CardLayout layout = CardLayout.defaultLayout();
		Set<CardMetaElement> visible = layout.getVisibleElements();
		assertTrue(visible.contains(CardMetaElement.GRADE));
		assertTrue(visible.contains(CardMetaElement.HOSTNAME));
		assertTrue(visible.contains(CardMetaElement.SCORE));
		assertTrue(visible.contains(CardMetaElement.TLS_VERSION));
		assertTrue(visible.contains(CardMetaElement.CIPHERS));
		assertTrue(visible.contains(CardMetaElement.HEADERS));
		assertTrue(visible.contains(CardMetaElement.CERT));
		assertTrue(visible.contains(CardMetaElement.RISK_BARS));
		assertFalse(visible.contains(CardMetaElement.IP));
		// New elements default to invisible
		assertFalse(visible.contains(CardMetaElement.CERT_EXPIRY));
		assertFalse(visible.contains(CardMetaElement.KEY_INFO));
		assertFalse(visible.contains(CardMetaElement.ISSUER));
		assertFalse(visible.contains(CardMetaElement.SAN_COUNT));
		assertFalse(visible.contains(CardMetaElement.REVOCATION));
	}

	@Test
	void visibleSlotsSortedByRowThenCol() {
		CardLayout layout = CardLayout.defaultLayout();
		List<CardSlotConfig> visible = layout.getVisibleSlots();
		for (int i = 1; i < visible.size(); i++) {
			CardSlotConfig prev = visible.get(i - 1);
			CardSlotConfig curr = visible.get(i);
			assertTrue(prev.getRow() < curr.getRow()
					|| (prev.getRow() == curr.getRow() && prev.getCol() <= curr.getCol()),
					"Visible slots must be sorted by row then col");
		}
	}

	@Test
	void slotConfigSerialization() {
		CardSlotConfig config = new CardSlotConfig(
				CardMetaElement.SCORE, 1, 2, HAlign.RIGHT, VAlign.TOP, true);
		String serialized = config.toPropertyValue();
		assertEquals("1,2,RIGHT,TOP,true,1,1", serialized);

		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.SCORE, serialized);
		assertNotNull(parsed);
		assertEquals(CardMetaElement.SCORE, parsed.getElement());
		assertEquals(1, parsed.getRow());
		assertEquals(2, parsed.getCol());
		assertEquals(HAlign.RIGHT, parsed.getHAlign());
		assertEquals(VAlign.TOP, parsed.getVAlign());
		assertTrue(parsed.isVisible());
		assertEquals(1, parsed.getColSpan());
		assertEquals(1, parsed.getRowSpan());
	}

	@Test
	void slotConfigSerializationInvisible() {
		CardSlotConfig config = new CardSlotConfig(
				CardMetaElement.IP, 3, 1, HAlign.CENTER, VAlign.CENTER, false);
		String serialized = config.toPropertyValue();
		assertEquals("3,1,CENTER,CENTER,false,1,1", serialized);

		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.IP, serialized);
		assertNotNull(parsed);
		assertFalse(parsed.isVisible());
	}

	@Test
	void slotConfigFromPropertyValueInvalid() {
		assertNull(CardSlotConfig.fromPropertyValue(CardMetaElement.GRADE, null));
		assertNull(CardSlotConfig.fromPropertyValue(CardMetaElement.GRADE, ""));
		assertNull(CardSlotConfig.fromPropertyValue(CardMetaElement.GRADE, "abc"));
		assertNull(CardSlotConfig.fromPropertyValue(CardMetaElement.GRADE, "0,1,INVALID,TOP,true"));
	}

	@Test
	void legacyFourFieldMigration() {
		// Legacy format: slotIndex,HAlign,VAnchor,visible
		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.GRADE, "0,LEFT,TOP,true");
		assertNotNull(parsed);
		assertEquals(0, parsed.getRow());
		assertEquals(0, parsed.getCol()); // LEFT -> col 0
		assertEquals(VAlign.CENTER, parsed.getVAlign()); // TOP -> CENTER
		assertTrue(parsed.isVisible());
		assertEquals(1, parsed.getColSpan());
		assertEquals(1, parsed.getRowSpan());
	}

	@Test
	void legacyFourFieldMigrationRight() {
		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.TLS_VERSION, "1,RIGHT,TOP,true");
		assertNotNull(parsed);
		assertEquals(1, parsed.getRow());
		assertEquals(2, parsed.getCol()); // RIGHT -> col 2
	}

	@Test
	void legacyFourFieldMigrationCenter() {
		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.SCORE, "2,CENTER,TOP,true");
		assertNotNull(parsed);
		assertEquals(2, parsed.getRow());
		assertEquals(1, parsed.getCol()); // CENTER -> col 1
	}

	@Test
	void legacyFourFieldMigrationBottom() {
		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.RISK_BARS, "6,LEFT,BOTTOM,true");
		assertNotNull(parsed);
		assertEquals(6, parsed.getRow());
		assertEquals(0, parsed.getCol());
		assertEquals(VAlign.BOTTOM, parsed.getVAlign()); // BOTTOM -> BOTTOM
	}

	@Test
	void slotConfigWithMethods() {
		CardSlotConfig original = new CardSlotConfig(
				CardMetaElement.CERT, 3, 0, HAlign.LEFT, VAlign.TOP, true);

		CardSlotConfig movedRow = original.withRow(5);
		assertEquals(5, movedRow.getRow());
		assertEquals(3, original.getRow());

		CardSlotConfig movedCol = original.withCol(2);
		assertEquals(2, movedCol.getCol());
		assertEquals(0, original.getCol());

		CardSlotConfig aligned = original.withHAlign(HAlign.CENTER);
		assertEquals(HAlign.CENTER, aligned.getHAlign());
		assertEquals(HAlign.LEFT, original.getHAlign());

		CardSlotConfig valigned = original.withVAlign(VAlign.BOTTOM);
		assertEquals(VAlign.BOTTOM, valigned.getVAlign());
		assertEquals(VAlign.TOP, original.getVAlign());

		CardSlotConfig hidden = original.withVisible(false);
		assertFalse(hidden.isVisible());
		assertTrue(original.isVisible());
	}

	@Test
	void cardMetaElementFromPropertyKey() {
		assertEquals(CardMetaElement.GRADE, CardMetaElement.fromPropertyKey("grade"));
		assertEquals(CardMetaElement.TLS_VERSION, CardMetaElement.fromPropertyKey("tlsVersion"));
		assertEquals(CardMetaElement.RISK_BARS, CardMetaElement.fromPropertyKey("riskBars"));
		assertEquals(CardMetaElement.CERT_EXPIRY, CardMetaElement.fromPropertyKey("certExpiry"));
		assertEquals(CardMetaElement.KEY_INFO, CardMetaElement.fromPropertyKey("keyInfo"));
		assertEquals(CardMetaElement.ISSUER, CardMetaElement.fromPropertyKey("issuer"));
		assertEquals(CardMetaElement.SAN_COUNT, CardMetaElement.fromPropertyKey("sanCount"));
		assertEquals(CardMetaElement.REVOCATION, CardMetaElement.fromPropertyKey("revocation"));
		assertNull(CardMetaElement.fromPropertyKey("nonexistent"));
	}

	@Test
	void layoutCopyIsIndependent() {
		CardLayout original = CardLayout.defaultLayout();
		CardLayout copy = original.copy();

		CardSlotConfig newConfig = new CardSlotConfig(
				CardMetaElement.GRADE, 4, 2, HAlign.CENTER, VAlign.BOTTOM, false);
		copy.setConfig(newConfig);

		CardSlotConfig origGrade = original.getConfig(CardMetaElement.GRADE);
		assertEquals(0, origGrade.getRow());
		assertEquals(0, origGrade.getCol());
		assertTrue(origGrade.isVisible());
	}

	@Test
	void layoutCopyCopiesGridDimensions() {
		CardLayout original = CardLayout.defaultLayout();
		original.resizeGrid(4, 7);
		CardLayout copy = original.copy();
		assertEquals(4, copy.getCols());
		assertEquals(7, copy.getRows());
	}

	@Test
	void setConfigReplacesExisting() {
		CardLayout layout = CardLayout.defaultLayout();
		CardSlotConfig replacement = new CardSlotConfig(
				CardMetaElement.SCORE, 4, 2, HAlign.CENTER, VAlign.BOTTOM, false);
		layout.setConfig(replacement);

		CardSlotConfig result = layout.getConfig(CardMetaElement.SCORE);
		assertEquals(4, result.getRow());
		assertEquals(2, result.getCol());
		assertEquals(HAlign.CENTER, result.getHAlign());
		assertEquals(VAlign.BOTTOM, result.getVAlign());
		assertFalse(result.isVisible());
	}

	@Test
	void getSlotAtFindsOccupiedCell() {
		CardLayout layout = CardLayout.defaultLayout();
		CardSlotConfig slot = layout.getSlotAt(0, 0);
		assertNotNull(slot);
		assertEquals(CardMetaElement.GRADE, slot.getElement());
	}

	@Test
	void getSlotAtReturnsNullForEmptyCell() {
		CardLayout layout = CardLayout.defaultLayout();
		assertNull(layout.getSlotAt(0, 2)); // col 2 row 0 is empty in default
	}

	@Test
	void isCellOccupied() {
		CardLayout layout = CardLayout.defaultLayout();
		assertTrue(layout.isCellOccupied(0, 0)); // GRADE
		assertFalse(layout.isCellOccupied(0, 2)); // empty
		assertFalse(layout.isCellOccupied(3, 1)); // IP is invisible
	}

	@Test
	void resizeGridHidesOutOfBoundsElements() {
		CardLayout layout = CardLayout.defaultLayout();
		// HOSTNAME is at (0,1), TLS_VERSION at (1,1), HEADERS at (2,1)
		layout.resizeGrid(1, 5); // shrink to 1 column
		// Anything in col >= 1 should be hidden
		assertFalse(layout.getConfig(CardMetaElement.HOSTNAME).isVisible());
		assertFalse(layout.getConfig(CardMetaElement.TLS_VERSION).isVisible());
		assertFalse(layout.getConfig(CardMetaElement.HEADERS).isVisible());
		// col 0 elements should still be visible
		assertTrue(layout.getConfig(CardMetaElement.GRADE).isVisible());
		assertTrue(layout.getConfig(CardMetaElement.SCORE).isVisible());
	}

	@Test
	void resizeGridHidesOutOfBoundsRows() {
		CardLayout layout = CardLayout.defaultLayout();
		layout.resizeGrid(3, 3); // shrink to 3 rows
		// CERT at (3,0) and RISK_BARS at (4,0) should be hidden
		assertFalse(layout.getConfig(CardMetaElement.CERT).isVisible());
		assertFalse(layout.getConfig(CardMetaElement.RISK_BARS).isVisible());
		// Row 0-2 elements should still be visible
		assertTrue(layout.getConfig(CardMetaElement.GRADE).isVisible());
		assertTrue(layout.getConfig(CardMetaElement.CIPHERS).isVisible());
	}

	@Test
	void resizeGridUpdatesColsAndRows() {
		CardLayout layout = CardLayout.defaultLayout();
		layout.resizeGrid(4, 7);
		assertEquals(4, layout.getCols());
		assertEquals(7, layout.getRows());
	}

	@Test
	void uniformWeights() {
		double[] w = CardLayout.uniformWeights(3);
		assertEquals(3, w.length);
		double sum = 0;
		for (double v : w) sum += v;
		assertEquals(1.0, sum, 0.001);
	}

	@Test
	void normalizeWeightsEnforcesMinimum() {
		double[] weights = { 0.01, 0.99 };
		double[] result = CardLayout.normalizeWeights(weights, 2);
		assertTrue(result[0] >= CardLayout.MIN_WEIGHT);
		double sum = result[0] + result[1];
		assertEquals(1.0, sum, 0.001);
	}

	@Test
	void colAndRowWeightsAreCopied() {
		CardLayout layout = CardLayout.defaultLayout();
		double[] colW = layout.getColWeights();
		colW[0] = 999.0; // modifying the returned copy
		assertNotEquals(999.0, layout.getColWeights()[0]);
	}

	// ---- Span tests ----

	@Test
	void sevenFieldSerializationRoundTrip() {
		CardSlotConfig config = new CardSlotConfig(
				CardMetaElement.RISK_BARS, 4, 0, HAlign.CENTER, VAlign.CENTER, true, 3, 1);
		String serialized = config.toPropertyValue();
		assertEquals("4,0,CENTER,CENTER,true,3,1", serialized);

		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.RISK_BARS, serialized);
		assertNotNull(parsed);
		assertEquals(4, parsed.getRow());
		assertEquals(0, parsed.getCol());
		assertEquals(3, parsed.getColSpan());
		assertEquals(1, parsed.getRowSpan());
		assertTrue(parsed.isVisible());
	}

	@Test
	void fiveFieldBackwardCompatDefaultsSpanToOne() {
		// 5-field format should default colSpan/rowSpan to 1
		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.SCORE, "1,2,RIGHT,TOP,true");
		assertNotNull(parsed);
		assertEquals(1, parsed.getColSpan());
		assertEquals(1, parsed.getRowSpan());
	}

	@Test
	void getSlotAtWithSpanFindsAcrossCells() {
		// Place element at (0,0) with colSpan=3
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.RISK_BARS, 0, 0,
				HAlign.CENTER, VAlign.CENTER, true, 3, 1));
		CardLayout layout = new CardLayout(slots, 3, 3, null, null);

		// Should be found at (0,0), (0,1), (0,2)
		assertNotNull(layout.getSlotAt(0, 0));
		assertEquals(CardMetaElement.RISK_BARS, layout.getSlotAt(0, 0).getElement());
		assertNotNull(layout.getSlotAt(0, 1));
		assertEquals(CardMetaElement.RISK_BARS, layout.getSlotAt(0, 1).getElement());
		assertNotNull(layout.getSlotAt(0, 2));
		assertEquals(CardMetaElement.RISK_BARS, layout.getSlotAt(0, 2).getElement());
		// Row 1 should be empty
		assertNull(layout.getSlotAt(1, 0));
	}

	@Test
	void isCellOccupiedWithSpan() {
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.GRADE, 1, 1,
				HAlign.CENTER, VAlign.CENTER, true, 2, 2));
		CardLayout layout = new CardLayout(slots, 4, 4, null, null);

		// Spanned cells
		assertTrue(layout.isCellOccupied(1, 1));
		assertTrue(layout.isCellOccupied(1, 2));
		assertTrue(layout.isCellOccupied(2, 1));
		assertTrue(layout.isCellOccupied(2, 2));
		// Outside span
		assertFalse(layout.isCellOccupied(0, 0));
		assertFalse(layout.isCellOccupied(1, 0));
		assertFalse(layout.isCellOccupied(3, 3));
	}

	@Test
	void resizeGridClampsSpan() {
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.RISK_BARS, 0, 0,
				HAlign.CENTER, VAlign.CENTER, true, 3, 1));
		CardLayout layout = new CardLayout(slots, 3, 3, null, null);

		// Shrink to 2 cols — span should be clamped to 2
		layout.resizeGrid(2, 3);
		CardSlotConfig slot = layout.getConfig(CardMetaElement.RISK_BARS);
		assertTrue(slot.isVisible());
		assertEquals(2, slot.getColSpan());
	}

	@Test
	void withColSpanAndWithRowSpan() {
		CardSlotConfig original = new CardSlotConfig(
				CardMetaElement.RISK_BARS, 0, 0, HAlign.CENTER, VAlign.CENTER, true);
		assertEquals(1, original.getColSpan());
		assertEquals(1, original.getRowSpan());

		CardSlotConfig spanned = original.withColSpan(3).withRowSpan(2);
		assertEquals(3, spanned.getColSpan());
		assertEquals(2, spanned.getRowSpan());
		// Original unchanged
		assertEquals(1, original.getColSpan());
		assertEquals(1, original.getRowSpan());
	}

	@Test
	void copyPreservesSpan() {
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.RISK_BARS, 0, 0,
				HAlign.CENTER, VAlign.CENTER, true, 3, 2));
		CardLayout layout = new CardLayout(slots, 3, 3, null, null);
		CardLayout copy = layout.copy();

		CardSlotConfig copySlot = copy.getConfig(CardMetaElement.RISK_BARS);
		assertEquals(3, copySlot.getColSpan());
		assertEquals(2, copySlot.getRowSpan());
	}

	@Test
	void defaultLayoutSpanIsOne() {
		CardLayout layout = CardLayout.defaultLayout();
		for (CardSlotConfig slot : layout.getSlots()) {
			assertEquals(1, slot.getColSpan(),
					slot.getElement() + " should have colSpan=1 in default");
			assertEquals(1, slot.getRowSpan(),
					slot.getElement() + " should have rowSpan=1 in default");
		}
	}

	@Test
	void spanMinimumIsOne() {
		// Attempting span of 0 or negative should clamp to 1
		CardSlotConfig slot = new CardSlotConfig(
				CardMetaElement.GRADE, 0, 0, HAlign.CENTER, VAlign.CENTER, true, 0, -1);
		assertEquals(1, slot.getColSpan());
		assertEquals(1, slot.getRowSpan());
	}

	// ---- Display label tests ----

	@Test
	void defaultDisplayLabelIsNull() {
		CardSlotConfig slot = new CardSlotConfig(
				CardMetaElement.HOSTNAME, 0, 1, HAlign.CENTER, VAlign.CENTER, true);
		assertNull(slot.getDisplayLabel());
		assertEquals("Host Name", slot.getEffectiveDisplayLabel());
	}

	@Test
	void customDisplayLabel() {
		CardSlotConfig slot = new CardSlotConfig(
				CardMetaElement.HOSTNAME, 0, 1, HAlign.CENTER, VAlign.CENTER, true,
				1, 1, "Server");
		assertEquals("Server", slot.getDisplayLabel());
		assertEquals("Server", slot.getEffectiveDisplayLabel());
	}

	@Test
	void withDisplayLabel() {
		CardSlotConfig original = new CardSlotConfig(
				CardMetaElement.CERT, 3, 0, HAlign.LEFT, VAlign.TOP, true);
		assertNull(original.getDisplayLabel());

		CardSlotConfig renamed = original.withDisplayLabel("Certificate");
		assertEquals("Certificate", renamed.getDisplayLabel());
		assertEquals("Certificate", renamed.getEffectiveDisplayLabel());
		// Original unchanged
		assertNull(original.getDisplayLabel());
	}

	@Test
	void eightFieldSerializationRoundTrip() {
		CardSlotConfig config = new CardSlotConfig(
				CardMetaElement.HOSTNAME, 0, 1, HAlign.CENTER, VAlign.CENTER, true,
				1, 1, "Server");
		String serialized = config.toPropertyValue();
		assertEquals("0,1,CENTER,CENTER,true,1,1,Server", serialized);

		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.HOSTNAME, serialized);
		assertNotNull(parsed);
		assertEquals("Server", parsed.getDisplayLabel());
		assertEquals("Server", parsed.getEffectiveDisplayLabel());
		assertEquals(0, parsed.getRow());
		assertEquals(1, parsed.getCol());
	}

	@Test
	void sevenFieldSerializationOmitsNullLabel() {
		CardSlotConfig config = new CardSlotConfig(
				CardMetaElement.GRADE, 0, 0, HAlign.CENTER, VAlign.CENTER, true, 1, 1);
		String serialized = config.toPropertyValue();
		assertEquals("0,0,CENTER,CENTER,true,1,1", serialized);
		// 7 fields — no label appended
		assertEquals(7, serialized.split(",").length);
	}

	@Test
	void copyPreservesDisplayLabel() {
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.HOSTNAME, 0, 1,
				HAlign.CENTER, VAlign.CENTER, true, 1, 1, "Server"));
		CardLayout layout = new CardLayout(slots, 3, 3, null, null);
		CardLayout copy = layout.copy();

		CardSlotConfig copySlot = copy.getConfig(CardMetaElement.HOSTNAME);
		assertEquals("Server", copySlot.getDisplayLabel());
	}

	@Test
	void blankDisplayLabel() {
		CardSlotConfig slot = new CardSlotConfig(
				CardMetaElement.HOSTNAME, 0, 1, HAlign.CENTER, VAlign.CENTER, true,
				1, 1, "");
		assertEquals("", slot.getDisplayLabel());
		assertEquals("", slot.getEffectiveDisplayLabel());
	}

	@Test
	void blankDisplayLabelSerializationRoundTrip() {
		CardSlotConfig config = new CardSlotConfig(
				CardMetaElement.HOSTNAME, 0, 1, HAlign.CENTER, VAlign.CENTER, true,
				1, 1, "");
		String serialized = config.toPropertyValue();
		assertEquals("0,1,CENTER,CENTER,true,1,1,", serialized);

		CardSlotConfig parsed = CardSlotConfig.fromPropertyValue(
				CardMetaElement.HOSTNAME, serialized);
		assertNotNull(parsed);
		assertEquals("", parsed.getDisplayLabel());
		assertEquals("", parsed.getEffectiveDisplayLabel());
	}

	@Test
	void copyPreservesBlankDisplayLabel() {
		java.util.List<CardSlotConfig> slots = new java.util.ArrayList<>();
		slots.add(new CardSlotConfig(CardMetaElement.HOSTNAME, 0, 1,
				HAlign.CENTER, VAlign.CENTER, true, 1, 1, ""));
		CardLayout layout = new CardLayout(slots, 3, 3, null, null);
		CardLayout copy = layout.copy();

		CardSlotConfig copySlot = copy.getConfig(CardMetaElement.HOSTNAME);
		assertEquals("", copySlot.getDisplayLabel());
	}

	@Test
	void withDisplayLabelPreservesOtherFields() {
		CardSlotConfig original = new CardSlotConfig(
				CardMetaElement.RISK_BARS, 4, 0, HAlign.LEFT, VAlign.BOTTOM, true, 3, 1);
		CardSlotConfig renamed = original.withDisplayLabel("Bars");
		assertEquals(4, renamed.getRow());
		assertEquals(0, renamed.getCol());
		assertEquals(HAlign.LEFT, renamed.getHAlign());
		assertEquals(VAlign.BOTTOM, renamed.getVAlign());
		assertTrue(renamed.isVisible());
		assertEquals(3, renamed.getColSpan());
		assertEquals(1, renamed.getRowSpan());
		assertEquals("Bars", renamed.getDisplayLabel());
	}
}
