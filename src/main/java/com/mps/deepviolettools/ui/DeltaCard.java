package com.mps.deepviolettools.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JPanel;

import com.mps.deepviolettools.model.CardSize;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * A custom-painted card displaying the summary of a delta scan comparison.
 * Shows a delta badge, base/target scan metadata, and change counts.
 *
 * <p>Follows the same visual style as {@link HostCard} (rounded corners,
 * hover/selected states, card colors from preferences).</p>
 *
 * <p>Fires {@code PropertyChangeEvent("selectedDelta", null, deltaResult)}
 * when clicked.</p>
 */
public class DeltaCard extends JPanel {

    private static final int ARC = 10;
    private static final int PADDING = 12;

    private final DeltaScanResult deltaResult;
    private FontPreferences prefs;
    private boolean hovered;
    private boolean selected;

    // Pre-computed display strings
    private final String baseScanLabel;
    private final String targetScanLabel;
    private final String summaryLine;

    public DeltaCard(DeltaScanResult deltaResult, FontPreferences prefs) {
        this.deltaResult = deltaResult;
        this.prefs = prefs;

        // Build display labels
        String baseName = deltaResult.getBaseFile() != null
                ? deltaResult.getBaseFile().getName() : "base";
        String targetName = deltaResult.getTargetFile() != null
                ? deltaResult.getTargetFile().getName() : "target";
        this.baseScanLabel = "Base: " + stripExtension(baseName)
                + " (" + deltaResult.getBaseHostCount() + " hosts)";
        this.targetScanLabel = "Target: " + stripExtension(targetName)
                + " (" + deltaResult.getTargetHostCount() + " hosts)";

        StringBuilder sb = new StringBuilder();
        int changed = deltaResult.getChangedCount();
        int added = deltaResult.getAddedCount();
        int removed = deltaResult.getRemovedCount();
        if (changed > 0) sb.append(changed).append(" changed");
        if (added > 0) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(added).append(" added");
        }
        if (removed > 0) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(removed).append(" removed");
        }
        if (sb.length() == 0) sb.append("No changes");
        this.summaryLine = sb.toString();

        CardSize cs = prefs.getCardSize();
        setPreferredSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setMinimumSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setMaximumSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setOpaque(false);

        MouseAdapter mouseHandler = new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                hovered = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                hovered = false;
                repaint();
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                firePropertyChange("selectedDelta", null, deltaResult);
            }
        };
        addMouseListener(mouseHandler);
    }

    public DeltaScanResult getDeltaResult() {
        return deltaResult;
    }

    public void setPrefs(FontPreferences prefs) {
        this.prefs = prefs;
        CardSize cs = prefs.getCardSize();
        Dimension d = new Dimension(cs.getWidth(), cs.getHeight());
        setPreferredSize(d);
        setMinimumSize(d);
        setMaximumSize(d);
        revalidate();
        repaint();
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();

        Color bgColor = prefs.getCardBg();
        Color fgColor = prefs.getCardText();
        Color dimColor = prefs.getCardDim();
        Font cardFont = prefs.getCardFont();
        int badgeSize = prefs.getCardBadgeSize();

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

        int x = PADDING;
        int y = PADDING;

        // Delta badge — colored circle with delta symbol
        Color accentColor = prefs.getCardSelected();
        g2.setColor(accentColor);
        g2.fillOval(x, y, badgeSize, badgeSize);
        g2.setColor(Color.WHITE);
        Font badgeFont = cardFont.deriveFont(Font.BOLD,
                (float) (cardFont.getSize() + 2));
        g2.setFont(badgeFont);
        FontMetrics bfm = g2.getFontMetrics();
        String badgeChar = "\u0394"; // Delta symbol
        int bx = x + (badgeSize - bfm.stringWidth(badgeChar)) / 2;
        int by = y + (badgeSize + bfm.getAscent() - bfm.getDescent()) / 2;
        g2.drawString(badgeChar, bx, by);

        // "Delta Comparison" title next to badge
        int textX = x + badgeSize + 8;
        Font titleFont = cardFont.deriveFont(Font.BOLD, (float) cardFont.getSize());
        g2.setFont(titleFont);
        g2.setColor(fgColor);
        int maxTextW = w - textX - PADDING;
        g2.drawString(CardRenderer.clipText(g2, "Delta Comparison", maxTextW),
                textX, y + bfm.getAscent());

        // Data lines below the badge
        Font dataFont = cardFont.deriveFont(Font.PLAIN,
                (float) (cardFont.getSize() - 1));
        g2.setFont(dataFont);
        FontMetrics dfm = g2.getFontMetrics();
        int lineH = dfm.getHeight() + 2;
        int dataY = y + badgeSize + 14;
        int dataMaxW = w - 2 * PADDING;

        // Base scan line
        g2.setColor(dimColor);
        g2.drawString(CardRenderer.clipText(g2, baseScanLabel, dataMaxW),
                x, dataY);
        dataY += lineH;

        // Target scan line
        g2.drawString(CardRenderer.clipText(g2, targetScanLabel, dataMaxW),
                x, dataY);
        dataY += lineH + 4;

        // Summary line with color coding
        g2.setColor(fgColor);
        g2.setFont(dataFont.deriveFont(Font.BOLD));
        g2.drawString(CardRenderer.clipText(g2, summaryLine, dataMaxW),
                x, dataY);
    }

    private static String stripExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot > 0 ? filename.substring(0, dot) : filename;
    }
}
