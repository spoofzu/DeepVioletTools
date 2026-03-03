package com.mps.deepviolettools.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseEvent;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.JPanel;

import com.mps.deepviolettools.util.FontPreferences;

/**
 * A custom-painted horizontal bar showing the distribution of letter grades
 * across scan results. Each grade gets a proportionally-sized colored
 * segment; error hosts appear as a gray segment at the right end.
 */
public class GradeDistributionBar extends JPanel {

    private static final int BAR_HEIGHT = 28;
    private static final int ARC = 12;
    private static final int GAP = 1;

    private static final Map<String, Color> GRADE_COLORS = new LinkedHashMap<>();
    static {
        GRADE_COLORS.put("A+", new Color(0x4CAF50));
        GRADE_COLORS.put("A",  new Color(0x4CAF50));
        GRADE_COLORS.put("B",  new Color(0x2196F3));
        GRADE_COLORS.put("C",  new Color(0xFF9800));
        GRADE_COLORS.put("D",  new Color(0xFF5722));
        GRADE_COLORS.put("F",  new Color(0xF44336));
    }
    private static final Color ERROR_COLOR = new Color(0x9E9E9E);

    private static final Color PLACEHOLDER_GRAY = new Color(0x9E9E9E);

    private FontPreferences prefs;
    private boolean placeholder;

    private Map<String, Integer> gradeCounts = new LinkedHashMap<>();
    private int totalHosts;
    private int errorCount;

    // Cached segment layout for tooltip hit-testing
    private String[] segLabels;
    private int[] segX;
    private int[] segW;

    public GradeDistributionBar(FontPreferences prefs) {
        this.prefs = prefs;
        setToolTipText("");
        setPreferredSize(new Dimension(100, BAR_HEIGHT));
        setMinimumSize(new Dimension(100, BAR_HEIGHT));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, BAR_HEIGHT));
    }

    public void setPrefs(FontPreferences prefs) {
        this.prefs = prefs;
        repaint();
    }

    /**
     * Enable or disable placeholder (ghosted) rendering. When true,
     * all grade segments are rendered in gray instead of grade colors.
     */
    public void setPlaceholder(boolean placeholder) {
        this.placeholder = placeholder;
        repaint();
    }

    /**
     * Update the grade distribution data and repaint.
     *
     * @param gradeCounts map of grade string (e.g. "A+") to host count
     * @param totalHosts  total number of hosts (success + error)
     * @param errorCount  number of hosts that failed to scan
     */
    public void setDistribution(Map<String, Integer> gradeCounts, int totalHosts, int errorCount) {
        this.gradeCounts = gradeCounts != null ? gradeCounts : new LinkedHashMap<>();
        this.totalHosts = totalHosts;
        this.errorCount = errorCount;
        segLabels = null;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (totalHosts <= 0) return;

        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();
        int barY = (h - BAR_HEIGHT) / 2;

        // Build segment list: grades in order, then errors
        java.util.List<String> labels = new java.util.ArrayList<>();
        java.util.List<Integer> counts = new java.util.ArrayList<>();
        java.util.List<Color> colors = new java.util.ArrayList<>();

        for (String grade : new String[]{"A+", "A", "B", "C", "D", "F"}) {
            Integer count = gradeCounts.get(grade);
            if (count != null && count > 0) {
                labels.add(grade + ": " + count);
                counts.add(count);
                colors.add(placeholder ? PLACEHOLDER_GRAY : GRADE_COLORS.get(grade));
            }
        }
        if (errorCount > 0) {
            labels.add("Err: " + errorCount);
            counts.add(errorCount);
            colors.add(placeholder ? PLACEHOLDER_GRAY : ERROR_COLOR);
        }

        if (labels.isEmpty()) return;

        // Compute segment widths: proportional but with a minimum so labels are readable
        int nSegs = labels.size();
        int totalGap = (nSegs - 1) * GAP;
        int usable = w - totalGap;

        Font appFont = prefs.getAppFont();
        Font font = appFont.deriveFont(Font.BOLD, (float) appFont.getSize());
        FontMetrics fm = g2.getFontMetrics(font);

        // Minimum width per segment = label text width + padding
        int labelPad = 10;
        int[] minWidths = new int[nSegs];
        for (int i = 0; i < nSegs; i++) {
            minWidths[i] = fm.stringWidth(labels.get(i)) + labelPad;
        }

        // Pass 1: assign proportional widths, clamped to minimum
        int[] widths = new int[nSegs];
        int reservedForClamped = 0;
        int countsOfUnclamped = 0;
        for (int i = 0; i < nSegs; i++) {
            int proportional = (int) ((double) counts.get(i) / totalHosts * usable);
            if (proportional < minWidths[i]) {
                widths[i] = minWidths[i];
                reservedForClamped += minWidths[i];
            } else {
                widths[i] = -1; // mark as unclamped
                countsOfUnclamped += counts.get(i);
            }
        }

        // Pass 2: distribute remaining space among unclamped segments proportionally
        int remaining = usable - reservedForClamped;
        if (countsOfUnclamped > 0 && remaining > 0) {
            int assigned2 = 0;
            int lastUnclamped = -1;
            for (int i = 0; i < nSegs; i++) {
                if (widths[i] == -1) {
                    widths[i] = (int) ((double) counts.get(i) / countsOfUnclamped * remaining);
                    assigned2 += widths[i];
                    lastUnclamped = i;
                }
            }
            // Give rounding remainder to the last unclamped segment
            if (lastUnclamped >= 0) {
                widths[lastUnclamped] += remaining - assigned2;
            }
        } else {
            // All segments are at minimum — just use minimums
            for (int i = 0; i < nSegs; i++) {
                if (widths[i] == -1) {
                    widths[i] = minWidths[i];
                }
            }
        }

        // Final rounding correction — ensure total matches usable
        int totalAssigned = 0;
        for (int i = 0; i < nSegs; i++) totalAssigned += widths[i];
        if (totalAssigned != usable && nSegs > 0) {
            int largest = 0;
            for (int i = 1; i < nSegs; i++) {
                if (widths[i] > widths[largest]) largest = i;
            }
            widths[largest] += usable - totalAssigned;
        }

        // Cache layout for tooltips
        segLabels = labels.toArray(new String[0]);
        segX = new int[nSegs];
        segW = widths.clone();

        g2.setFont(font);

        int x = 0;
        for (int i = 0; i < nSegs; i++) {
            segX[i] = x;
            g2.setColor(colors.get(i));

            if (nSegs == 1) {
                g2.fillRoundRect(x, barY, widths[i], BAR_HEIGHT, ARC, ARC);
            } else if (i == 0) {
                // Left end: round left corners
                g2.fillRoundRect(x, barY, widths[i] + ARC, BAR_HEIGHT, ARC, ARC);
                g2.fillRect(x + widths[i] - 1, barY, ARC + 1, BAR_HEIGHT);
            } else if (i == nSegs - 1) {
                // Right end: round right corners
                g2.fillRoundRect(x - ARC, barY, widths[i] + ARC, BAR_HEIGHT, ARC, ARC);
                g2.fillRect(x, barY, ARC, BAR_HEIGHT);
            } else {
                g2.fillRect(x, barY, widths[i], BAR_HEIGHT);
            }

            // Draw label if it fits
            String label = labels.get(i);
            int textW = fm.stringWidth(label);
            if (textW + 8 <= widths[i]) {
                g2.setColor(Color.WHITE);
                int textX = x + (widths[i] - textW) / 2;
                int textY = barY + (BAR_HEIGHT + fm.getAscent() - fm.getDescent()) / 2;
                g2.drawString(label, textX, textY);
            }

            x += widths[i] + GAP;
        }
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        if (segLabels == null || segLabels.length == 0) return null;

        int mx = e.getX();
        for (int i = 0; i < segLabels.length; i++) {
            if (mx >= segX[i] && mx < segX[i] + segW[i]) {
                String label = segLabels[i];
                // Parse count from label "A: 5" or "Err: 3"
                String[] parts = label.split(": ");
                String grade = parts[0];
                int count = Integer.parseInt(parts[1]);
                int pct = (int) Math.round((double) count / totalHosts * 100);
                return grade + ": " + count + " host" + (count != 1 ? "s" : "") + " (" + pct + "%)";
            }
        }
        return null;
    }

    /**
     * Returns the color associated with the given letter grade.
     */
    public static Color colorForGrade(String grade) {
        Color c = GRADE_COLORS.get(grade);
        return c != null ? c : ERROR_COLOR;
    }
}
