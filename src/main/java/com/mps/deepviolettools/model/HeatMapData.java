package com.mps.deepviolettools.model;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

/**
 * Model class for heat map tables used in the scanning feature.
 * Each heat map contains rows of categorized data with cells that track
 * pass/fail/inconclusive counts and support color interpolation for rendering.
 * Cells are displayed as percentage text (e.g. "50%", "100%E", "75%I").
 */
public class HeatMapData {

    public enum MapType {
        RISK, CIPHER, SECURITY_HEADERS, CONNECTION, HTTP_RESPONSE,
        REVOCATION, FINGERPRINT
    }

    private final MapType mapType;
    private final List<HeatMapRow> rows;
    private final int nBlocks;
    private final int hostsPerBlock;
    private final int totalHosts;
    private final boolean[] errorColumns;

    public HeatMapData(MapType mapType, List<HeatMapRow> rows, int nBlocks, int hostsPerBlock) {
        this(mapType, rows, nBlocks, hostsPerBlock, 0, null);
    }

    public HeatMapData(MapType mapType, List<HeatMapRow> rows, int nBlocks, int hostsPerBlock, int totalHosts) {
        this(mapType, rows, nBlocks, hostsPerBlock, totalHosts, null);
    }

    public HeatMapData(MapType mapType, List<HeatMapRow> rows, int nBlocks, int hostsPerBlock,
                        int totalHosts, boolean[] errorColumns) {
        this.mapType = mapType;
        this.rows = rows;
        this.nBlocks = nBlocks;
        this.hostsPerBlock = hostsPerBlock;
        this.totalHosts = totalHosts;
        this.errorColumns = errorColumns;
    }

    public MapType getMapType() {
        return mapType;
    }

    public List<HeatMapRow> getRows() {
        return rows;
    }

    public int getNBlocks() {
        return nBlocks;
    }

    public int getHostsPerBlock() {
        return hostsPerBlock;
    }

    public int getTotalHosts() {
        return totalHosts;
    }

    /**
     * Returns true if the given column contains at least one host that
     * produced an error during scanning.
     */
    public boolean hasErrorColumn(int col) {
        return errorColumns != null && col >= 0 && col < errorColumns.length && errorColumns[col];
    }

    /**
     * Returns the number of blocks each host spans. When there are fewer
     * hosts than blocks, each host spans multiple columns.
     */
    public int getBlocksPerHost() {
        return totalHosts > 0 ? Math.max(1, nBlocks / totalHosts) : nBlocks;
    }

    /**
     * Returns an interpolated color for the cell at the given row and column.
     * The color is a linear RGB interpolation based on the pass, fail, and
     * inconclusive ratios of the cell. Returns gray (128, 128, 128) if the
     * cell has no data.
     *
     * @param row              the row index
     * @param col              the column index
     * @param passColor        the color representing a fully passing cell
     * @param failColor        the color representing a fully failing cell
     * @param inconclusiveColor the color representing a fully inconclusive cell
     * @return the interpolated Color for the cell
     */
    public Color getCellColor(int row, int col, Color passColor, Color failColor, Color inconclusiveColor) {
        HeatMapCell cell = rows.get(row).getCells()[col];

        if (cell.totalCount() == 0) {
            return new Color(128, 128, 128);
        }

        double passRatio = cell.passRatio();
        double failRatio = cell.failRatio();
        double inconclusiveRatio = cell.inconclusiveRatio();

        int r = (int) (passRatio * passColor.getRed() + failRatio * failColor.getRed() + inconclusiveRatio * inconclusiveColor.getRed());
        int g = (int) (passRatio * passColor.getGreen() + failRatio * failColor.getGreen() + inconclusiveRatio * inconclusiveColor.getGreen());
        int b = (int) (passRatio * passColor.getBlue() + failRatio * failColor.getBlue() + inconclusiveRatio * inconclusiveColor.getBlue());

        r = Math.max(0, Math.min(255, r));
        g = Math.max(0, Math.min(255, g));
        b = Math.max(0, Math.min(255, b));

        return new Color(r, g, b);
    }

    /**
     * Returns a color for a numeric score on the 0-10 scale.
     * 0 (no data/inconclusive) returns gray (128,128,128).
     * 1 (all pass) returns green (76,175,80).
     * 10 (all fail) returns red (244,67,54).
     * Values 2-9 are linearly interpolated between green and red.
     *
     * @param score the score value (0-10)
     * @return the Color corresponding to the score
     */
    public static Color scoreColor(int score) {
        if (score <= 0) {
            return new Color(128, 128, 128); // gray -- no data/inconclusive
        }
        if (score >= 10) {
            return new Color(244, 67, 54);   // red -- all fail
        }
        if (score == 1) {
            return new Color(76, 175, 80);   // green -- all pass
        }
        // Linear interpolation from green (score=1) to red (score=10)
        double t = (score - 1.0) / 9.0; // 0.0 at score=1, 1.0 at score=10
        int r = (int) (76 + t * (244 - 76));
        int g = (int) (175 + t * (67 - 175));
        int b = (int) (80 + t * (54 - 80));
        return new Color(r, g, b);
    }

    /**
     * Computes a percentage-based display string for a heat map cell.
     * For RISK: percentage = failCount / totalCount * 100 (% of hosts with risk).
     * For all others: percentage = passCount / totalCount * 100 (% with characteristic).
     * Appends "E" if the column is an error column, "I" if the cell has inconclusive results.
     *
     * @param cell          the cell to compute text for
     * @param mapType       the map type (affects whether pass or fail is the primary metric)
     * @param isErrorColumn true if this column contains error hosts
     * @return formatted string like "50%", "100%EI", "0%E"
     */
    public static String cellPercentageText(HeatMapCell cell, MapType mapType, boolean isErrorColumn) {
        if (cell.totalCount() == 0) {
            return isErrorColumn ? "0%E" : "0%";
        }
        int pct;
        if (mapType == MapType.RISK) {
            pct = (int) Math.round((double) cell.getFailCount() / cell.totalCount() * 100);
        } else {
            pct = (int) Math.round((double) cell.getPassCount() / cell.totalCount() * 100);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(pct).append('%');
        if (isErrorColumn) sb.append('E');
        if (cell.getInconclusiveCount() > 0) sb.append('I');
        return sb.toString();
    }

    /**
     * Returns the legend text for a given map type, describing the meaning of
     * the percentage values and suffixes.
     *
     * @param mapType       the map type
     * @param totalHosts    total number of hosts scanned
     * @param nBlocks       number of columns in the heat map
     * @param hostsPerBlock hosts per block (when totalHosts > nBlocks)
     * @param blocksPerHost blocks per host (when totalHosts <= nBlocks)
     * @return legend description string
     */
    public static String legendText(MapType mapType, int totalHosts, int nBlocks,
                                     int hostsPerBlock, int blocksPerHost) {
        String scaleInfo;
        if (totalHosts > 0 && totalHosts <= nBlocks) {
            scaleInfo = totalHosts + " hosts, " + blocksPerHost + " blocks/host";
        } else if (totalHosts > nBlocks) {
            scaleInfo = totalHosts + " hosts, " + hostsPerBlock + " hosts/block";
        } else {
            scaleInfo = nBlocks + " blocks";
        }

        String pctMeaning;
        switch (mapType) {
            case RISK:
                pctMeaning = "N%=incorporates risk";
                break;
            case SECURITY_HEADERS:
            case HTTP_RESPONSE:
                pctMeaning = "N%=header found";
                break;
            case CONNECTION:
                pctMeaning = "N%=characteristic found";
                break;
            case CIPHER:
                pctMeaning = "N%=cipher available";
                break;
            case REVOCATION:
                pctMeaning = "N%=revocation operable";
                break;
            case FINGERPRINT:
                pctMeaning = "N%=similar";
                break;
            default:
                pctMeaning = "N%=present";
                break;
        }

        return "  " + pctMeaning + "  .=repeated  E=error  I=inconclusive  (" + scaleInfo + ")";
    }

    /**
     * Returns a color for a percentage value (0-100).
     * 0% returns green, 100% returns red, with linear interpolation between.
     * If the cell has inconclusive results, blends toward yellow.
     *
     * @param percentage       the percentage value (0-100)
     * @param hasInconclusive  true if the cell has inconclusive data
     * @param mapType          the map type (RISK uses fail-based coloring, others pass-based)
     * @return the computed color
     */
    public static Color percentageColor(int percentage, boolean hasInconclusive, MapType mapType) {
        Color green = new Color(76, 175, 80);
        Color red = new Color(244, 67, 54);
        Color yellow = new Color(255, 193, 7);

        // For RISK, high percentage = bad (more red). For others, high percentage = good (more green).
        double t;
        if (mapType == MapType.RISK) {
            t = percentage / 100.0; // 0% = green, 100% = red
        } else {
            t = 1.0 - percentage / 100.0; // 100% = green, 0% = red
        }

        int r = (int) (green.getRed() + t * (red.getRed() - green.getRed()));
        int g = (int) (green.getGreen() + t * (red.getGreen() - green.getGreen()));
        int b = (int) (green.getBlue() + t * (red.getBlue() - green.getBlue()));

        if (hasInconclusive) {
            // Blend 30% toward yellow
            r = (int) (r * 0.7 + yellow.getRed() * 0.3);
            g = (int) (g * 0.7 + yellow.getGreen() * 0.3);
            b = (int) (b * 0.7 + yellow.getBlue() * 0.3);
        }

        r = Math.max(0, Math.min(255, r));
        g = Math.max(0, Math.min(255, g));
        b = Math.max(0, Math.min(255, b));

        return new Color(r, g, b);
    }

    /**
     * Assigns a host to a block index based on its position among all hosts.
     *
     * @param hostIndex  the zero-based index of the host
     * @param totalHosts the total number of hosts
     * @param nBlocks    the number of blocks to distribute hosts across
     * @return the block index (clamped to nBlocks - 1 max)
     */
    public static int assignBlock(int hostIndex, int totalHosts, int nBlocks) {
        int block = hostIndex * nBlocks / totalHosts;
        return Math.min(block, nBlocks - 1);
    }

    /**
     * Returns the inclusive block range [startBlock, endBlock] that a host
     * should be assigned to. When totalHosts &lt;= nBlocks, each host spans
     * multiple blocks proportionally. When totalHosts &gt; nBlocks, each host
     * maps to a single block (startBlock == endBlock).
     *
     * @param hostIndex  the zero-based index of the host
     * @param totalHosts the total number of hosts
     * @param nBlocks    the number of blocks in the heat map
     * @return int[]{startBlock, endBlock} (inclusive)
     */
    public static int[] assignBlockRange(int hostIndex, int totalHosts, int nBlocks) {
        if (totalHosts >= nBlocks) {
            int block = assignBlock(hostIndex, totalHosts, nBlocks);
            return new int[]{ block, block };
        }
        // Proportional: each host spans nBlocks/totalHosts blocks
        int start = hostIndex * nBlocks / totalHosts;
        int end = (hostIndex + 1) * nBlocks / totalHosts - 1;
        end = Math.max(start, Math.min(end, nBlocks - 1));
        return new int[]{ start, end };
    }

    /**
     * Represents a single row in a heat map table.
     */
    public static class HeatMapRow {

        private final String category;
        private final String id;
        private final String description;
        private final String qualifier;
        private final HeatMapCell[] cells;

        public HeatMapRow(String category, String id, String description, String qualifier, HeatMapCell[] cells) {
            this.category = category;
            this.id = id;
            this.description = description;
            this.qualifier = qualifier;
            this.cells = cells;
        }

        public String getCategory() {
            return category;
        }

        public String getId() {
            return id;
        }

        public String getDescription() {
            return description;
        }

        public String getQualifier() {
            return qualifier;
        }

        public HeatMapCell[] getCells() {
            return cells;
        }
    }

    /**
     * Represents a single cell in a heat map table. Tracks pass, fail, and
     * inconclusive counts along with the majority value and associated host names.
     */
    public static class HeatMapCell {

        private int passCount;
        private int failCount;
        private int inconclusiveCount;
        private String majorityValue;
        private final List<String> hostNames;

        public HeatMapCell(int passCount, int failCount, int inconclusiveCount, String majorityValue, List<String> hostNames) {
            this.passCount = passCount;
            this.failCount = failCount;
            this.inconclusiveCount = inconclusiveCount;
            this.majorityValue = majorityValue;
            this.hostNames = hostNames;
        }

        public int getPassCount() {
            return passCount;
        }

        public int getFailCount() {
            return failCount;
        }

        public int getInconclusiveCount() {
            return inconclusiveCount;
        }

        public String getMajorityValue() {
            return majorityValue;
        }

        public List<String> getHostNames() {
            return hostNames;
        }

        /**
         * Returns the total count of pass, fail, and inconclusive results.
         */
        public int totalCount() {
            return passCount + failCount + inconclusiveCount;
        }

        /**
         * Returns the ratio of pass count to total count, or 0.0 if total is 0.
         */
        public double passRatio() {
            int total = totalCount();
            return total == 0 ? 0.0 : (double) passCount / total;
        }

        /**
         * Returns the ratio of fail count to total count, or 0.0 if total is 0.
         */
        public double failRatio() {
            int total = totalCount();
            return total == 0 ? 0.0 : (double) failCount / total;
        }

        /**
         * Returns the ratio of inconclusive count to total count, or 0.0 if total is 0.
         */
        public double inconclusiveRatio() {
            int total = totalCount();
            return total == 0 ? 0.0 : (double) inconclusiveCount / total;
        }

        /**
         * Returns a score on the 0-10 scale based on pass/fail ratio.
         * Returns 0 if total count is zero or if all results are inconclusive.
         * Otherwise maps failCount/(passCount+failCount) to the 1-10 range,
         * ignoring inconclusive results in the ratio.
         *
         * @return score from 0 (no data) through 1 (all pass) to 10 (all fail)
         */
        public int score() {
            if (totalCount() == 0) {
                return 0;
            }
            int decisive = passCount + failCount;
            if (decisive == 0) {
                return 0; // all inconclusive
            }
            double failRatio = (double) failCount / decisive;
            // Map 0.0 -> 1, 1.0 -> 10
            return (int) Math.round(1 + failRatio * 9);
        }

        /**
         * Increments the pass count by one.
         */
        public void addPass() {
            passCount++;
        }

        /**
         * Increments the fail count by one.
         */
        public void addFail() {
            failCount++;
        }

        /**
         * Increments the inconclusive count by one.
         */
        public void addInconclusive() {
            inconclusiveCount++;
        }

        /**
         * Adds a host name to this cell's list of associated hosts.
         *
         * @param host the host name to add
         */
        public void addHostName(String host) {
            hostNames.add(host);
        }
    }
}
