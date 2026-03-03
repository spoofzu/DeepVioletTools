package com.mps.deepviolettools.ui;

import com.mps.deepviolettools.model.HeatMapData;
import com.mps.deepviolettools.model.HeatMapData.HeatMapCell;
import com.mps.deepviolettools.model.HeatMapData.HeatMapRow;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.List;

/**
 * A custom JPanel that renders heat map data as a colored grid.
 * Each row represents a data item (cipher suite, connection property, etc.)
 * and each column represents a block of hosts. Cell colors are interpolated
 * based on pass/fail/inconclusive ratios.
 *
 * <p>This panel is designed to be placed inside a JScrollPane. It calculates
 * its own preferred size based on the data dimensions so scrolling works
 * correctly.</p>
 */
public class HeatMapPanel extends JPanel {

    private static final int CELL_WIDTH = 20;
    private static final int CELL_HEIGHT = 18;
    private static final int LABEL_WIDTH = 300;
    private static final int HEADER_HEIGHT = 24;
    private static final int TOP_MARGIN = 30;

    private static final Font LABEL_FONT = new Font("SansSerif", Font.PLAIN, 11);
    private static final Font CATEGORY_FONT = new Font("SansSerif", Font.BOLD, 12);
    private static final Font LEGEND_FONT = new Font("SansSerif", Font.PLAIN, 11);

    private HeatMapData data;
    private Color passColor = new Color(76, 175, 80);
    private Color failColor = new Color(244, 67, 54);
    private Color inconclusiveColor = new Color(255, 193, 7);

    // Theme-aware text and header colors (defaults are backward-compatible)
    private Color textColor = Color.BLACK;
    private Color headerBgColor = new Color(220, 220, 220);
    private Color headerTextColor = Color.BLACK;

    /**
     * Creates a new HeatMapPanel with no data. Call {@link #setData(HeatMapData)}
     * to populate the panel.
     */
    public HeatMapPanel() {
        setToolTipText(""); // enables ToolTipManager for this component
        setBackground(Color.WHITE);
    }

    /**
     * Sets the heat map data to render.
     *
     * @param data the heat map data, or null to clear the panel
     */
    public void setData(HeatMapData data) {
        this.data = data;
        revalidate();
        repaint();
    }

    /**
     * Sets the colors used for pass, fail, and inconclusive cell rendering.
     *
     * @param pass          color for fully passing cells
     * @param fail          color for fully failing cells
     * @param inconclusive  color for fully inconclusive cells
     */
    public void setColors(Color pass, Color fail, Color inconclusive) {
        this.passColor = pass;
        this.failColor = fail;
        this.inconclusiveColor = inconclusive;
        repaint();
    }

    /**
     * Sets the theme-aware colors for text, category headers, and labels.
     * Call this when applying a dark or light theme to ensure readability.
     *
     * @param text       color for row labels, column numbers, legend text, and "No data" message
     * @param headerBg   background color for category header rows
     * @param headerText text color for category header labels
     */
    public void setThemeColors(Color text, Color headerBg, Color headerText) {
        this.textColor = text;
        this.headerBgColor = headerBg;
        this.headerTextColor = headerText;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        // Clear background
        g2.setColor(getBackground());
        g2.fillRect(0, 0, getWidth(), getHeight());

        // No data state
        if (data == null || data.getRows().isEmpty()) {
            g2.setColor(textColor);
            g2.setFont(LABEL_FONT);
            String msg = "No data";
            FontMetrics fm = g2.getFontMetrics();
            int x = (getWidth() - fm.stringWidth(msg)) / 2;
            int y = (getHeight() + fm.getAscent()) / 2;
            g2.drawString(msg, x, y);
            return;
        }

        List<HeatMapRow> rows = data.getRows();
        int nBlocks = data.getNBlocks();

        // Draw column numbers along the top
        g2.setFont(LABEL_FONT);
        g2.setColor(textColor);
        FontMetrics labelFm = g2.getFontMetrics();
        for (int col = 0; col < nBlocks; col++) {
            String colLabel = String.valueOf(col + 1);
            int colX = LABEL_WIDTH + col * CELL_WIDTH;
            int textX = colX + (CELL_WIDTH - labelFm.stringWidth(colLabel)) / 2;
            g2.drawString(colLabel, textX, TOP_MARGIN - 6);
        }

        // Draw rows with category headers
        int currentY = TOP_MARGIN;
        String lastCategory = null;

        for (int rowIdx = 0; rowIdx < rows.size(); rowIdx++) {
            HeatMapRow row = rows.get(rowIdx);
            String category = row.getCategory();

            // Draw category header if category changed
            if (category != null && !category.equals(lastCategory)) {
                g2.setFont(CATEGORY_FONT);
                FontMetrics catFm = g2.getFontMetrics();
                int totalWidth = LABEL_WIDTH + nBlocks * CELL_WIDTH + 20;

                // Category header background
                g2.setColor(headerBgColor);
                g2.fillRect(0, currentY, totalWidth, HEADER_HEIGHT);

                // Category header text
                g2.setColor(headerTextColor);
                int textY = currentY + (HEADER_HEIGHT + catFm.getAscent() - catFm.getDescent()) / 2;
                g2.drawString(category, 4, textY);

                currentY += HEADER_HEIGHT;
                lastCategory = category;
            }

            // Draw row label
            g2.setFont(LABEL_FONT);
            FontMetrics rowFm = g2.getFontMetrics();
            g2.setColor(textColor);

            String label = (row.getDescription() != null && !row.getDescription().isEmpty())
                    ? row.getDescription() : row.getId();
            if (row.getQualifier() != null && !row.getQualifier().isEmpty()) {
                label = label + " (" + row.getQualifier() + ")";
            }

            // Clip label text to fit within LABEL_WIDTH
            String displayLabel = label;
            while (rowFm.stringWidth(displayLabel) > LABEL_WIDTH - 10 && displayLabel.length() > 1) {
                displayLabel = displayLabel.substring(0, displayLabel.length() - 1);
            }
            if (!displayLabel.equals(label) && displayLabel.length() > 3) {
                displayLabel = displayLabel.substring(0, displayLabel.length() - 3) + "...";
            }

            int textY = currentY + (CELL_HEIGHT + rowFm.getAscent() - rowFm.getDescent()) / 2;
            g2.drawString(displayLabel, 4, textY);

            // Draw cells
            HeatMapCell[] cells = row.getCells();
            for (int colIdx = 0; colIdx < nBlocks && colIdx < cells.length; colIdx++) {
                Color cellColor = data.getCellColor(rowIdx, colIdx, passColor, failColor, inconclusiveColor);
                int cellX = LABEL_WIDTH + colIdx * CELL_WIDTH;
                g2.setColor(cellColor);
                g2.fillRect(cellX, currentY, CELL_WIDTH - 1, CELL_HEIGHT - 1);
            }

            currentY += CELL_HEIGHT;
        }

        // Draw legend at the bottom
        currentY += 10;
        g2.setFont(LEGEND_FONT);
        FontMetrics legendFm = g2.getFontMetrics();
        int legendX = 4;

        // Pass legend
        g2.setColor(passColor);
        g2.fillRect(legendX, currentY, 12, 12);
        legendX += 14;
        g2.setColor(textColor);
        g2.drawString("=pass", legendX, currentY + 11);
        legendX += legendFm.stringWidth("=pass") + 12;

        // Fail legend
        g2.setColor(failColor);
        g2.fillRect(legendX, currentY, 12, 12);
        legendX += 14;
        g2.setColor(textColor);
        g2.drawString("=fail", legendX, currentY + 11);
        legendX += legendFm.stringWidth("=fail") + 12;

        // Inconclusive legend
        g2.setColor(inconclusiveColor);
        g2.fillRect(legendX, currentY, 12, 12);
        legendX += 14;
        g2.setColor(textColor);
        g2.drawString("=inconclusive", legendX, currentY + 11);
        legendX += legendFm.stringWidth("=inconclusive") + 12;

        // Block count
        g2.drawString("(" + nBlocks + " blocks)", legendX, currentY + 11);
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        if (data == null || data.getRows().isEmpty()) {
            return null;
        }

        List<HeatMapRow> rows = data.getRows();
        int nBlocks = data.getNBlocks();

        // Check if the mouse is in the cell grid area
        int mouseX = e.getX();
        int mouseY = e.getY();

        if (mouseX < LABEL_WIDTH || mouseX >= LABEL_WIDTH + nBlocks * CELL_WIDTH) {
            return null;
        }

        int col = (mouseX - LABEL_WIDTH) / CELL_WIDTH;
        if (col < 0 || col >= nBlocks) {
            return null;
        }

        // Calculate which row the mouse is on, accounting for category headers
        int currentY = TOP_MARGIN;
        String lastCategory = null;
        int targetRow = -1;

        for (int rowIdx = 0; rowIdx < rows.size(); rowIdx++) {
            HeatMapRow row = rows.get(rowIdx);
            String category = row.getCategory();

            if (category != null && !category.equals(lastCategory)) {
                currentY += HEADER_HEIGHT;
                lastCategory = category;
            }

            if (mouseY >= currentY && mouseY < currentY + CELL_HEIGHT) {
                targetRow = rowIdx;
                break;
            }

            currentY += CELL_HEIGHT;
        }

        if (targetRow < 0 || targetRow >= rows.size()) {
            return null;
        }

        HeatMapRow row = rows.get(targetRow);
        HeatMapCell[] cells = row.getCells();
        if (col >= cells.length) {
            return null;
        }

        HeatMapCell cell = cells[col];
        List<String> hostNames = cell.getHostNames();

        boolean isErrorCol = data.hasErrorColumn(col);
        String pctText = HeatMapData.cellPercentageText(cell, data.getMapType(), isErrorCol);

        StringBuilder sb = new StringBuilder("<html>");
        sb.append(pctText);
        sb.append("<br>Host(s): ");
        if (hostNames != null && !hostNames.isEmpty()) {
            sb.append(String.join(", ", hostNames));
        } else {
            sb.append("(none)");
        }
        sb.append("<br>");
        sb.append("Pass: ").append(cell.getPassCount());
        sb.append("  Fail: ").append(cell.getFailCount());
        sb.append("  Inconclusive: ").append(cell.getInconclusiveCount());
        sb.append("</html>");

        return sb.toString();
    }

    @Override
    public Dimension getPreferredSize() {
        if (data == null || data.getRows().isEmpty()) {
            return new Dimension(400, 200);
        }

        List<HeatMapRow> rows = data.getRows();
        int nBlocks = data.getNBlocks();

        // Count unique categories
        int uniqueCategories = 0;
        String lastCategory = null;
        for (HeatMapRow row : rows) {
            String category = row.getCategory();
            if (category != null && !category.equals(lastCategory)) {
                uniqueCategories++;
                lastCategory = category;
            }
        }

        int width = LABEL_WIDTH + (nBlocks * CELL_WIDTH) + 20;
        int height = TOP_MARGIN
                + (rows.size() * CELL_HEIGHT)
                + (uniqueCategories * HEADER_HEIGHT)
                + 40; // space for legend

        return new Dimension(width, height);
    }
}
