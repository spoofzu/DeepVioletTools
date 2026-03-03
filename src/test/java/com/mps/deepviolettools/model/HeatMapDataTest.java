package com.mps.deepviolettools.model;

import static org.junit.jupiter.api.Assertions.*;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.mps.deepviolettools.model.HeatMapData.HeatMapCell;
import com.mps.deepviolettools.model.HeatMapData.HeatMapRow;
import com.mps.deepviolettools.model.HeatMapData.MapType;

/**
 * Unit tests for {@link HeatMapData} and its nested classes
 * {@link HeatMapCell} and {@link HeatMapRow}.
 */
class HeatMapDataTest {

    // -----------------------------------------------------------------------
    // Helper factories
    // -----------------------------------------------------------------------

    private static HeatMapCell emptyCell() {
        return new HeatMapCell(0, 0, 0, "", new ArrayList<>());
    }

    private static HeatMapCell cellWith(int pass, int fail, int inconclusive) {
        return new HeatMapCell(pass, fail, inconclusive, "value", new ArrayList<>());
    }

    private static HeatMapRow rowWithCells(HeatMapCell... cells) {
        return new HeatMapRow("cat", "id1", "desc", "qualifier", cells);
    }

    private static HeatMapData dataWithSingleCell(HeatMapCell cell) {
        HeatMapRow row = rowWithCells(cell);
        return new HeatMapData(MapType.RISK, List.of(row), 1, 1);
    }

    // -----------------------------------------------------------------------
    // HeatMapCell — addPass / addFail / addInconclusive
    // -----------------------------------------------------------------------

    @Test
    void addPass_incrementsPassCount() {
        HeatMapCell cell = emptyCell();
        cell.addPass();
        assertEquals(1, cell.getPassCount());
        cell.addPass();
        assertEquals(2, cell.getPassCount());
    }

    @Test
    void addFail_incrementsFailCount() {
        HeatMapCell cell = emptyCell();
        cell.addFail();
        assertEquals(1, cell.getFailCount());
        cell.addFail();
        assertEquals(2, cell.getFailCount());
    }

    @Test
    void addInconclusive_incrementsInconclusiveCount() {
        HeatMapCell cell = emptyCell();
        cell.addInconclusive();
        assertEquals(1, cell.getInconclusiveCount());
        cell.addInconclusive();
        assertEquals(2, cell.getInconclusiveCount());
    }

    @Test
    void addHostName_appendsToList() {
        HeatMapCell cell = emptyCell();
        cell.addHostName("host1.example.com");
        cell.addHostName("host2.example.com");
        assertEquals(2, cell.getHostNames().size());
        assertEquals("host1.example.com", cell.getHostNames().get(0));
        assertEquals("host2.example.com", cell.getHostNames().get(1));
    }

    // -----------------------------------------------------------------------
    // HeatMapCell — totalCount
    // -----------------------------------------------------------------------

    @Test
    void totalCount_isZeroForEmptyCell() {
        assertEquals(0, emptyCell().totalCount());
    }

    @Test
    void totalCount_sumOfAllCounts() {
        HeatMapCell cell = cellWith(3, 2, 1);
        assertEquals(6, cell.totalCount());
    }

    @Test
    void totalCount_afterMutations() {
        HeatMapCell cell = emptyCell();
        cell.addPass();
        cell.addFail();
        cell.addInconclusive();
        assertEquals(3, cell.totalCount());
    }

    // -----------------------------------------------------------------------
    // HeatMapCell — passRatio / failRatio / inconclusiveRatio with zero total
    // -----------------------------------------------------------------------

    @Test
    void ratios_areZeroWhenTotalIsZero() {
        HeatMapCell cell = emptyCell();
        assertEquals(0.0, cell.passRatio());
        assertEquals(0.0, cell.failRatio());
        assertEquals(0.0, cell.inconclusiveRatio());
    }

    @Test
    void passRatio_allPass() {
        HeatMapCell cell = cellWith(4, 0, 0);
        assertEquals(1.0, cell.passRatio(), 1e-9);
        assertEquals(0.0, cell.failRatio(), 1e-9);
        assertEquals(0.0, cell.inconclusiveRatio(), 1e-9);
    }

    @Test
    void failRatio_allFail() {
        HeatMapCell cell = cellWith(0, 4, 0);
        assertEquals(0.0, cell.passRatio(), 1e-9);
        assertEquals(1.0, cell.failRatio(), 1e-9);
        assertEquals(0.0, cell.inconclusiveRatio(), 1e-9);
    }

    @Test
    void inconclusiveRatio_allInconclusive() {
        HeatMapCell cell = cellWith(0, 0, 4);
        assertEquals(0.0, cell.passRatio(), 1e-9);
        assertEquals(0.0, cell.failRatio(), 1e-9);
        assertEquals(1.0, cell.inconclusiveRatio(), 1e-9);
    }

    @Test
    void ratios_mixedCounts_sumToOne() {
        HeatMapCell cell = cellWith(2, 2, 2);
        double sum = cell.passRatio() + cell.failRatio() + cell.inconclusiveRatio();
        assertEquals(1.0, sum, 1e-9);
        assertEquals(1.0 / 3.0, cell.passRatio(), 1e-9);
        assertEquals(1.0 / 3.0, cell.failRatio(), 1e-9);
        assertEquals(1.0 / 3.0, cell.inconclusiveRatio(), 1e-9);
    }

    @Test
    void ratios_unevenMix() {
        // 3 pass, 1 fail, 0 inconclusive — total 4
        HeatMapCell cell = cellWith(3, 1, 0);
        assertEquals(0.75, cell.passRatio(), 1e-9);
        assertEquals(0.25, cell.failRatio(), 1e-9);
        assertEquals(0.0,  cell.inconclusiveRatio(), 1e-9);
    }

    // -----------------------------------------------------------------------
    // HeatMapCell — getters from constructor
    // -----------------------------------------------------------------------

    @Test
    void cell_constructorGetters() {
        List<String> hosts = new ArrayList<>(Arrays.asList("a.com", "b.com"));
        HeatMapCell cell = new HeatMapCell(5, 3, 1, "TLSv1.3", hosts);
        assertEquals(5, cell.getPassCount());
        assertEquals(3, cell.getFailCount());
        assertEquals(1, cell.getInconclusiveCount());
        assertEquals("TLSv1.3", cell.getMajorityValue());
        assertEquals(2, cell.getHostNames().size());
    }

    // -----------------------------------------------------------------------
    // HeatMapRow — constructor and getters
    // -----------------------------------------------------------------------

    @Test
    void row_constructorGetters() {
        HeatMapCell[] cells = { emptyCell(), cellWith(1, 0, 0) };
        HeatMapRow row = new HeatMapRow("CIPHER", "RC4", "RC4 cipher", "weak", cells);
        assertEquals("CIPHER", row.getCategory());
        assertEquals("RC4", row.getId());
        assertEquals("RC4 cipher", row.getDescription());
        assertEquals("weak", row.getQualifier());
        assertSame(cells, row.getCells());
        assertEquals(2, row.getCells().length);
    }

    @Test
    void row_cellsArrayIsReturnedDirectly() {
        HeatMapCell c = emptyCell();
        HeatMapRow row = rowWithCells(c);
        assertSame(c, row.getCells()[0]);
    }

    // -----------------------------------------------------------------------
    // HeatMapData — getters / getPreferredSize equivalents
    // -----------------------------------------------------------------------

    @Test
    void heatMapData_constructorGetters() {
        HeatMapRow row1 = rowWithCells(emptyCell());
        HeatMapRow row2 = rowWithCells(emptyCell());
        List<HeatMapRow> rows = List.of(row1, row2);
        HeatMapData data = new HeatMapData(MapType.CIPHER, rows, 10, 5);

        assertEquals(MapType.CIPHER, data.getMapType());
        assertEquals(2, data.getRows().size());
        assertEquals(10, data.getNBlocks());
        assertEquals(5, data.getHostsPerBlock());
    }

    @Test
    void getRows_returnsAllRows() {
        List<HeatMapRow> rows = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            rows.add(rowWithCells(emptyCell()));
        }
        HeatMapData data = new HeatMapData(MapType.RISK, rows, 5, 2);
        assertEquals(5, data.getRows().size());
    }

    @Test
    void getRows_emptyList() {
        HeatMapData data = new HeatMapData(MapType.FINGERPRINT, new ArrayList<>(), 0, 0);
        assertTrue(data.getRows().isEmpty());
    }

    @Test
    void mapType_allValues() {
        for (MapType type : MapType.values()) {
            HeatMapData data = new HeatMapData(type, new ArrayList<>(), 1, 1);
            assertEquals(type, data.getMapType());
        }
    }

    // -----------------------------------------------------------------------
    // assignBlock — correct assignment
    // -----------------------------------------------------------------------

    @Test
    void assignBlock_firstHost_goesToBlockZero() {
        // hostIndex=0, totalHosts=10, nBlocks=5 => 0*5/10 = 0
        assertEquals(0, HeatMapData.assignBlock(0, 10, 5));
    }

    @Test
    void assignBlock_lastHost_goesToLastBlock() {
        // hostIndex=9, totalHosts=10, nBlocks=5 => 9*5/10 = 4 (integer div)
        assertEquals(4, HeatMapData.assignBlock(9, 10, 5));
    }

    @Test
    void assignBlock_middleHost() {
        // hostIndex=5, totalHosts=10, nBlocks=5 => 5*5/10 = 2
        assertEquals(2, HeatMapData.assignBlock(5, 10, 5));
    }

    @Test
    void assignBlock_singleHost_singleBlock() {
        assertEquals(0, HeatMapData.assignBlock(0, 1, 1));
    }

    @Test
    void assignBlock_clampsToBoundary() {
        // hostIndex == totalHosts-1 should never exceed nBlocks-1
        for (int totalHosts = 1; totalHosts <= 20; totalHosts++) {
            for (int nBlocks = 1; nBlocks <= 10; nBlocks++) {
                int block = HeatMapData.assignBlock(totalHosts - 1, totalHosts, nBlocks);
                assertTrue(block <= nBlocks - 1,
                        "block " + block + " exceeds nBlocks-1=" + (nBlocks - 1)
                                + " for totalHosts=" + totalHosts + ", nBlocks=" + nBlocks);
            }
        }
    }

    @Test
    void assignBlock_hostIndexZeroAlwaysZero() {
        // First host always lands in block 0 regardless of configuration
        for (int totalHosts = 1; totalHosts <= 20; totalHosts++) {
            for (int nBlocks = 1; nBlocks <= 10; nBlocks++) {
                assertEquals(0, HeatMapData.assignBlock(0, totalHosts, nBlocks),
                        "Expected block 0 for hostIndex=0, totalHosts=" + totalHosts
                                + ", nBlocks=" + nBlocks);
            }
        }
    }

    @Test
    void assignBlock_evenDistribution() {
        // 10 hosts, 10 blocks: each host should map to its own block
        for (int i = 0; i < 10; i++) {
            assertEquals(i, HeatMapData.assignBlock(i, 10, 10));
        }
    }

    @Test
    void assignBlock_fewerBlocksThanHosts() {
        // 100 hosts, 4 blocks: verify monotone, non-decreasing, all in [0, 3]
        int prev = 0;
        for (int i = 0; i < 100; i++) {
            int block = HeatMapData.assignBlock(i, 100, 4);
            assertTrue(block >= 0 && block <= 3,
                    "Block " + block + " out of [0,3] range for hostIndex=" + i);
            assertTrue(block >= prev,
                    "Block assignment is not monotone at hostIndex=" + i);
            prev = block;
        }
    }

    // -----------------------------------------------------------------------
    // assignBlockRange — proportional distribution
    // -----------------------------------------------------------------------

    @Test
    void assignBlockRange_twoHosts_twentyBlocks_tenEach() {
        int[] range0 = HeatMapData.assignBlockRange(0, 2, 20);
        int[] range1 = HeatMapData.assignBlockRange(1, 2, 20);
        assertEquals(0, range0[0]);
        assertEquals(9, range0[1]);
        assertEquals(10, range1[0]);
        assertEquals(19, range1[1]);
    }

    @Test
    void assignBlockRange_oneHost_allBlocks() {
        int[] range = HeatMapData.assignBlockRange(0, 1, 20);
        assertEquals(0, range[0]);
        assertEquals(19, range[1]);
    }

    @Test
    void assignBlockRange_moreHostsThanBlocks_singleBlock() {
        // 100 hosts, 20 blocks: each host maps to a single block
        for (int i = 0; i < 100; i++) {
            int[] range = HeatMapData.assignBlockRange(i, 100, 20);
            assertEquals(range[0], range[1],
                    "Expected single block for hostIndex=" + i);
        }
    }

    @Test
    void assignBlockRange_equalHostsAndBlocks_oneBlockEach() {
        // 20 hosts, 20 blocks: each host gets exactly 1 block
        for (int i = 0; i < 20; i++) {
            int[] range = HeatMapData.assignBlockRange(i, 20, 20);
            assertEquals(i, range[0]);
            assertEquals(i, range[1]);
        }
    }

    @Test
    void assignBlockRange_coversAllBlocks() {
        // 5 hosts, 20 blocks: blocks should be contiguous and cover all 20
        boolean[] covered = new boolean[20];
        for (int i = 0; i < 5; i++) {
            int[] range = HeatMapData.assignBlockRange(i, 5, 20);
            for (int b = range[0]; b <= range[1]; b++) {
                covered[b] = true;
            }
        }
        for (int b = 0; b < 20; b++) {
            assertTrue(covered[b], "Block " + b + " not covered");
        }
    }

    @Test
    void assignBlockRange_noOverlap() {
        // 3 hosts, 20 blocks: ranges should not overlap
        int lastEnd = -1;
        for (int i = 0; i < 3; i++) {
            int[] range = HeatMapData.assignBlockRange(i, 3, 20);
            assertTrue(range[0] > lastEnd,
                    "Range overlap at host " + i + ": start=" + range[0] + " lastEnd=" + lastEnd);
            lastEnd = range[1];
        }
    }

    // -----------------------------------------------------------------------
    // getCellColor — all pass
    // -----------------------------------------------------------------------

    @Test
    void getCellColor_allPass_returnsPassColor() {
        HeatMapCell cell = cellWith(4, 0, 0);
        HeatMapData data = dataWithSingleCell(cell);

        Color pass = new Color(0, 255, 0);
        Color fail = new Color(255, 0, 0);
        Color inc  = new Color(0, 0, 255);

        Color result = data.getCellColor(0, 0, pass, fail, inc);
        assertEquals(pass, result);
    }

    // -----------------------------------------------------------------------
    // getCellColor — all fail
    // -----------------------------------------------------------------------

    @Test
    void getCellColor_allFail_returnsFailColor() {
        HeatMapCell cell = cellWith(0, 4, 0);
        HeatMapData data = dataWithSingleCell(cell);

        Color pass = new Color(0, 255, 0);
        Color fail = new Color(255, 0, 0);
        Color inc  = new Color(0, 0, 255);

        Color result = data.getCellColor(0, 0, pass, fail, inc);
        assertEquals(fail, result);
    }

    // -----------------------------------------------------------------------
    // getCellColor — all inconclusive
    // -----------------------------------------------------------------------

    @Test
    void getCellColor_allInconclusive_returnsInconclusiveColor() {
        HeatMapCell cell = cellWith(0, 0, 4);
        HeatMapData data = dataWithSingleCell(cell);

        Color pass = new Color(0, 255, 0);
        Color fail = new Color(255, 0, 0);
        Color inc  = new Color(0, 0, 255);

        Color result = data.getCellColor(0, 0, pass, fail, inc);
        assertEquals(inc, result);
    }

    // -----------------------------------------------------------------------
    // getCellColor — empty cell returns gray
    // -----------------------------------------------------------------------

    @Test
    void getCellColor_emptyCell_returnsGray() {
        HeatMapData data = dataWithSingleCell(emptyCell());

        Color pass = new Color(0, 255, 0);
        Color fail = new Color(255, 0, 0);
        Color inc  = new Color(0, 0, 255);

        Color result = data.getCellColor(0, 0, pass, fail, inc);
        assertEquals(new Color(128, 128, 128), result);
    }

    // -----------------------------------------------------------------------
    // getCellColor — mixed (interpolated)
    // -----------------------------------------------------------------------

    @Test
    void getCellColor_halfPassHalfFail_interpolatesCorrectly() {
        // 2 pass, 2 fail, 0 inconclusive => passRatio=0.5, failRatio=0.5
        HeatMapCell cell = cellWith(2, 2, 0);
        HeatMapData data = dataWithSingleCell(cell);

        // pass=white(255,255,255), fail=black(0,0,0), inc=unused
        Color pass = new Color(255, 255, 255);
        Color fail = new Color(0, 0, 0);
        Color inc  = new Color(128, 128, 128);

        Color result = data.getCellColor(0, 0, pass, fail, inc);
        // expected: 0.5*255 + 0.5*0 = 127 (truncated from double cast)
        assertEquals(127, result.getRed());
        assertEquals(127, result.getGreen());
        assertEquals(127, result.getBlue());
    }

    @Test
    void getCellColor_threeWayMix_interpolatesCorrectly() {
        // 1 pass, 1 fail, 1 inconclusive => each ratio = 1/3
        HeatMapCell cell = cellWith(1, 1, 1);
        HeatMapData data = dataWithSingleCell(cell);

        // Use pure primary colors: pass=red, fail=green, inc=blue
        // Each ratio=1/3: r=1/3*255, g=1/3*255, b=1/3*255
        Color passC = new Color(255, 0, 0);
        Color failC = new Color(0, 255, 0);
        Color incC  = new Color(0, 0, 255);
        Color result = data.getCellColor(0, 0, passC, failC, incC);

        int expectedR = (int)(1.0/3.0 * 255 + 1.0/3.0 * 0   + 1.0/3.0 * 0  );
        int expectedG = (int)(1.0/3.0 * 0   + 1.0/3.0 * 255 + 1.0/3.0 * 0  );
        int expectedB = (int)(1.0/3.0 * 0   + 1.0/3.0 * 0   + 1.0/3.0 * 255);
        assertEquals(expectedR, result.getRed());
        assertEquals(expectedG, result.getGreen());
        assertEquals(expectedB, result.getBlue());
    }

    @Test
    void getCellColor_resultClampsToValidRange() {
        // Use extreme colors and check the result never exceeds 0-255
        HeatMapCell cell = cellWith(10, 10, 10);
        HeatMapData data = dataWithSingleCell(cell);

        Color pass = new Color(255, 255, 255);
        Color fail = new Color(255, 255, 255);
        Color inc  = new Color(255, 255, 255);

        Color result = data.getCellColor(0, 0, pass, fail, inc);
        assertTrue(result.getRed()   >= 0 && result.getRed()   <= 255);
        assertTrue(result.getGreen() >= 0 && result.getGreen() <= 255);
        assertTrue(result.getBlue()  >= 0 && result.getBlue()  <= 255);
    }

    @Test
    void getCellColor_correctRowAndColLookup() {
        // Two rows, two columns; only cell (1,1) has data -- others are empty
        HeatMapCell data11 = cellWith(3, 0, 0);

        HeatMapRow row0 = new HeatMapRow("cat", "r0", "row0", "q", new HeatMapCell[]{ emptyCell(), emptyCell() });
        HeatMapRow row1 = new HeatMapRow("cat", "r1", "row1", "q", new HeatMapCell[]{ emptyCell(), data11 });

        HeatMapData hmd = new HeatMapData(MapType.RISK, List.of(row0, row1), 2, 1);

        Color pass = new Color(0, 200, 0);
        Color fail = new Color(200, 0, 0);
        Color inc  = new Color(0, 0, 200);
        Color gray = new Color(128, 128, 128);

        assertEquals(gray, hmd.getCellColor(0, 0, pass, fail, inc));
        assertEquals(gray, hmd.getCellColor(0, 1, pass, fail, inc));
        assertEquals(gray, hmd.getCellColor(1, 0, pass, fail, inc));
        assertEquals(pass, hmd.getCellColor(1, 1, pass, fail, inc));
    }

    // -----------------------------------------------------------------------
    // HeatMapCell — score()
    // -----------------------------------------------------------------------

    @Test
    void score_emptyCell_returnsZero() {
        assertEquals(0, emptyCell().score());
    }

    @Test
    void score_allInconclusive_returnsZero() {
        assertEquals(0, cellWith(0, 0, 5).score());
    }

    @Test
    void score_allPass_returnsOne() {
        assertEquals(1, cellWith(10, 0, 0).score());
    }

    @Test
    void score_allFail_returnsTen() {
        assertEquals(10, cellWith(0, 10, 0).score());
    }

    @Test
    void score_halfAndHalf_returnsSix() {
        // failRatio = 5/10 = 0.5 -> 1 + 0.5*9 = 5.5 -> rounds to 6
        assertEquals(6, cellWith(5, 5, 0).score());
    }

    @Test
    void score_mostlyPass_returnsLow() {
        // failRatio = 1/10 = 0.1 -> 1 + 0.9 = 1.9 -> rounds to 2
        assertEquals(2, cellWith(9, 1, 0).score());
    }

    @Test
    void score_mostlyFail_returnsHigh() {
        // failRatio = 9/10 = 0.9 -> 1 + 8.1 = 9.1 -> rounds to 9
        assertEquals(9, cellWith(1, 9, 0).score());
    }

    @Test
    void score_inconclusiveIgnoredInRatio() {
        // passCount=3, failCount=1, inconclusiveCount=100
        // decisive = 4, failRatio = 0.25 -> 1 + 2.25 = 3.25 -> rounds to 3
        assertEquals(3, cellWith(3, 1, 100).score());
    }

    // -----------------------------------------------------------------------
    // HeatMapData — scoreColor()
    // -----------------------------------------------------------------------

    @Test
    void scoreColor_zero_returnsGray() {
        Color c = HeatMapData.scoreColor(0);
        assertEquals(new Color(128, 128, 128), c);
    }

    @Test
    void scoreColor_one_returnsGreen() {
        Color c = HeatMapData.scoreColor(1);
        assertEquals(new Color(76, 175, 80), c);
    }

    @Test
    void scoreColor_ten_returnsRed() {
        Color c = HeatMapData.scoreColor(10);
        assertEquals(new Color(244, 67, 54), c);
    }

    @Test
    void scoreColor_five_returnsIntermediate() {
        Color c = HeatMapData.scoreColor(5);
        // t = (5-1)/9 = 4/9
        int expectedR = (int) (76 + (4.0 / 9.0) * (244 - 76));
        int expectedG = (int) (175 + (4.0 / 9.0) * (67 - 175));
        int expectedB = (int) (80 + (4.0 / 9.0) * (54 - 80));
        assertEquals(expectedR, c.getRed());
        assertEquals(expectedG, c.getGreen());
        assertEquals(expectedB, c.getBlue());
    }

    @Test
    void scoreColor_allValues_validRgb() {
        for (int score = 0; score <= 10; score++) {
            Color c = HeatMapData.scoreColor(score);
            assertTrue(c.getRed() >= 0 && c.getRed() <= 255,
                    "Invalid red for score=" + score);
            assertTrue(c.getGreen() >= 0 && c.getGreen() <= 255,
                    "Invalid green for score=" + score);
            assertTrue(c.getBlue() >= 0 && c.getBlue() <= 255,
                    "Invalid blue for score=" + score);
        }
    }

    @Test
    void scoreColor_negative_treatedAsZero() {
        assertEquals(HeatMapData.scoreColor(0), HeatMapData.scoreColor(-1));
    }

    @Test
    void scoreColor_aboveTen_treatedAsTen() {
        assertEquals(HeatMapData.scoreColor(10), HeatMapData.scoreColor(11));
    }

    // -----------------------------------------------------------------------
    // cellPercentageText — RISK type (uses failCount)
    // -----------------------------------------------------------------------

    @Test
    void cellPercentageText_risk_allFail_returns100Percent() {
        HeatMapCell cell = cellWith(0, 10, 0);
        assertEquals("100%", HeatMapData.cellPercentageText(cell, MapType.RISK, false));
    }

    @Test
    void cellPercentageText_risk_allPass_returns0Percent() {
        HeatMapCell cell = cellWith(10, 0, 0);
        assertEquals("0%", HeatMapData.cellPercentageText(cell, MapType.RISK, false));
    }

    @Test
    void cellPercentageText_risk_halfAndHalf_returns50Percent() {
        HeatMapCell cell = cellWith(5, 5, 0);
        assertEquals("50%", HeatMapData.cellPercentageText(cell, MapType.RISK, false));
    }

    // -----------------------------------------------------------------------
    // cellPercentageText — non-RISK type (uses passCount)
    // -----------------------------------------------------------------------

    @Test
    void cellPercentageText_cipher_allPass_returns100Percent() {
        HeatMapCell cell = cellWith(10, 0, 0);
        assertEquals("100%", HeatMapData.cellPercentageText(cell, MapType.CIPHER, false));
    }

    @Test
    void cellPercentageText_cipher_allFail_returns0Percent() {
        HeatMapCell cell = cellWith(0, 10, 0);
        assertEquals("0%", HeatMapData.cellPercentageText(cell, MapType.CIPHER, false));
    }

    // -----------------------------------------------------------------------
    // cellPercentageText — error column suffix
    // -----------------------------------------------------------------------

    @Test
    void cellPercentageText_withErrorColumn_appendsE() {
        HeatMapCell cell = cellWith(5, 5, 0);
        String text = HeatMapData.cellPercentageText(cell, MapType.RISK, true);
        assertTrue(text.contains("E"), "Expected E suffix: " + text);
        assertEquals("50%E", text);
    }

    // -----------------------------------------------------------------------
    // cellPercentageText — inconclusive suffix
    // -----------------------------------------------------------------------

    @Test
    void cellPercentageText_withInconclusive_appendsI() {
        HeatMapCell cell = cellWith(5, 3, 2);
        String text = HeatMapData.cellPercentageText(cell, MapType.CIPHER, false);
        assertTrue(text.contains("I"), "Expected I suffix: " + text);
        assertEquals("50%I", text);
    }

    @Test
    void cellPercentageText_withErrorAndInconclusive_appendsEI() {
        HeatMapCell cell = cellWith(5, 3, 2);
        String text = HeatMapData.cellPercentageText(cell, MapType.CIPHER, true);
        assertTrue(text.endsWith("EI"), "Expected EI suffix: " + text);
    }

    // -----------------------------------------------------------------------
    // cellPercentageText — empty cell
    // -----------------------------------------------------------------------

    @Test
    void cellPercentageText_emptyCell_returns0Percent() {
        assertEquals("0%", HeatMapData.cellPercentageText(emptyCell(), MapType.RISK, false));
    }

    @Test
    void cellPercentageText_emptyCell_errorColumn_returns0PercentE() {
        assertEquals("0%E", HeatMapData.cellPercentageText(emptyCell(), MapType.RISK, true));
    }

    // -----------------------------------------------------------------------
    // legendText — per MapType
    // -----------------------------------------------------------------------

    @Test
    void legendText_risk_containsIncorporatesRisk() {
        String legend = HeatMapData.legendText(MapType.RISK, 5, 20, 1, 4);
        assertTrue(legend.contains("N%=incorporates risk"), legend);
    }

    @Test
    void legendText_cipher_containsCipherAvailable() {
        String legend = HeatMapData.legendText(MapType.CIPHER, 5, 20, 1, 4);
        assertTrue(legend.contains("N%=cipher available"), legend);
    }

    @Test
    void legendText_securityHeaders_containsHeaderFound() {
        String legend = HeatMapData.legendText(MapType.SECURITY_HEADERS, 5, 20, 1, 4);
        assertTrue(legend.contains("N%=header found"), legend);
    }

    @Test
    void legendText_connection_containsCharacteristicFound() {
        String legend = HeatMapData.legendText(MapType.CONNECTION, 5, 20, 1, 4);
        assertTrue(legend.contains("N%=characteristic found"), legend);
    }

    @Test
    void legendText_revocation_containsRevocationOperable() {
        String legend = HeatMapData.legendText(MapType.REVOCATION, 5, 20, 1, 4);
        assertTrue(legend.contains("N%=revocation operable"), legend);
    }

    @Test
    void legendText_fingerprint_containsSimilar() {
        String legend = HeatMapData.legendText(MapType.FINGERPRINT, 5, 20, 1, 4);
        assertTrue(legend.contains("N%=similar"), legend);
    }

    @Test
    void legendText_containsErrorAndInconclusiveSuffixes() {
        String legend = HeatMapData.legendText(MapType.RISK, 5, 20, 1, 4);
        assertTrue(legend.contains("E=error"), legend);
        assertTrue(legend.contains("I=inconclusive"), legend);
        assertTrue(legend.contains(".=repeated"), legend);
    }

    @Test
    void legendText_manyHosts_containsHostsPerBlock() {
        String legend = HeatMapData.legendText(MapType.RISK, 100, 20, 5, 1);
        assertTrue(legend.contains("100 hosts, 5 hosts/block"), legend);
    }

    @Test
    void legendText_fewHosts_containsBlocksPerHost() {
        String legend = HeatMapData.legendText(MapType.RISK, 3, 20, 1, 6);
        assertTrue(legend.contains("3 hosts, 6 blocks/host"), legend);
    }

    // -----------------------------------------------------------------------
    // hasErrorColumn
    // -----------------------------------------------------------------------

    @Test
    void hasErrorColumn_withErrorColumns_returnsTrue() {
        boolean[] ec = { false, true, false };
        HeatMapData data = new HeatMapData(MapType.RISK, new ArrayList<>(), 3, 1, 3, ec);
        assertFalse(data.hasErrorColumn(0));
        assertTrue(data.hasErrorColumn(1));
        assertFalse(data.hasErrorColumn(2));
    }

    @Test
    void hasErrorColumn_withoutErrorColumns_returnsFalse() {
        HeatMapData data = new HeatMapData(MapType.RISK, new ArrayList<>(), 3, 1);
        assertFalse(data.hasErrorColumn(0));
        assertFalse(data.hasErrorColumn(1));
    }

    @Test
    void hasErrorColumn_outOfBounds_returnsFalse() {
        boolean[] ec = { true };
        HeatMapData data = new HeatMapData(MapType.RISK, new ArrayList<>(), 1, 1, 1, ec);
        assertFalse(data.hasErrorColumn(5));
        assertFalse(data.hasErrorColumn(-1));
    }

    // -----------------------------------------------------------------------
    // percentageColor — basic checks
    // -----------------------------------------------------------------------

    @Test
    void percentageColor_riskZero_isGreen() {
        Color c = HeatMapData.percentageColor(0, false, MapType.RISK);
        // 0% risk = green area
        assertEquals(76, c.getRed());
        assertEquals(175, c.getGreen());
        assertEquals(80, c.getBlue());
    }

    @Test
    void percentageColor_riskHundred_isRed() {
        Color c = HeatMapData.percentageColor(100, false, MapType.RISK);
        assertEquals(244, c.getRed());
        assertEquals(67, c.getGreen());
        assertEquals(54, c.getBlue());
    }

    @Test
    void percentageColor_cipherHundred_isGreen() {
        // For non-RISK, 100% = green (good: all hosts have it)
        Color c = HeatMapData.percentageColor(100, false, MapType.CIPHER);
        assertEquals(76, c.getRed());
        assertEquals(175, c.getGreen());
        assertEquals(80, c.getBlue());
    }

    @Test
    void percentageColor_cipherZero_isRed() {
        Color c = HeatMapData.percentageColor(0, false, MapType.CIPHER);
        assertEquals(244, c.getRed());
        assertEquals(67, c.getGreen());
        assertEquals(54, c.getBlue());
    }

    @Test
    void percentageColor_withInconclusive_blendsTowardYellow() {
        Color without = HeatMapData.percentageColor(50, false, MapType.RISK);
        Color with = HeatMapData.percentageColor(50, true, MapType.RISK);
        // With inconclusive, green channel should be higher due to yellow blend
        assertTrue(with.getGreen() > without.getGreen() || with.getRed() > without.getRed(),
                "Expected yellow blend effect");
    }
}
