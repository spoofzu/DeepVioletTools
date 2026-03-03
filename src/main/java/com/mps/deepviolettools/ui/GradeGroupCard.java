package com.mps.deepviolettools.ui;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JPanel;
import javax.swing.UIManager;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolettools.model.CardSize;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * A custom-painted card representing all hosts that share a particular
 * letter grade. Shows aggregate statistics (score range, protocol
 * distribution, average security headers, weakest cipher).
 *
 * <p>Fires a {@code PropertyChangeEvent("gradeZoom", null, grade)}
 * when clicked.</p>
 */
public class GradeGroupCard extends JPanel {

    private static final int ARC = 10;
    private static final int PADDING = 14;

    private final String grade;
    private final List<HostResult> hosts;
    private FontPreferences prefs;
    private boolean hovered;

    // Pre-computed display data
    private final int hostCount;
    private final String scoreRange;
    private final String protocolSummary;
    private final String avgHeaders;
    private final String weakestCipher;

    public GradeGroupCard(String grade, List<HostResult> hosts, FontPreferences prefs) {
        this.grade = grade;
        this.hosts = hosts;
        this.prefs = prefs;
        this.hostCount = hosts.size();

        // Score range
        int minScore = Integer.MAX_VALUE;
        int maxScore = Integer.MIN_VALUE;
        for (HostResult hr : hosts) {
            IRiskScore rs = hr.getRiskScore();
            if (rs != null) {
                int s = rs.getTotalScore();
                if (s < minScore) minScore = s;
                if (s > maxScore) maxScore = s;
            }
        }
        if (minScore == Integer.MAX_VALUE) {
            this.scoreRange = "N/A";
        } else if (minScore == maxScore) {
            this.scoreRange = String.valueOf(minScore);
        } else {
            this.scoreRange = minScore + "\u2013" + maxScore;
        }

        // Protocol distribution
        Map<String, Integer> protoCounts = new HashMap<>();
        for (HostResult hr : hosts) {
            Map<String, String> conn = hr.getConnProperties();
            if (conn != null && conn.containsKey("NEGOTIATED_PROTOCOL")) {
                protoCounts.merge(conn.get("NEGOTIATED_PROTOCOL"), 1, Integer::sum);
            }
        }
        StringBuilder protoSb = new StringBuilder();
        for (Map.Entry<String, Integer> e : protoCounts.entrySet()) {
            if (protoSb.length() > 0) protoSb.append(", ");
            protoSb.append(e.getKey()).append(" (").append(e.getValue()).append(")");
        }
        this.protocolSummary = protoSb.length() > 0 ? protoSb.toString() : "N/A";

        // Average security headers
        int headerTotal = 0;
        int headerCount = 0;
        int headerPossible = 0;
        for (HostResult hr : hosts) {
            Map<String, String> secHeaders = hr.getSecurityHeaders();
            if (secHeaders != null) {
                headerPossible = secHeaders.size();
                int present = 0;
                for (String val : secHeaders.values()) {
                    if (val != null && !"MISSING".equalsIgnoreCase(val)) {
                        present++;
                    }
                }
                headerTotal += present;
                headerCount++;
            }
        }
        if (headerCount > 0 && headerPossible > 0) {
            double avg = (double) headerTotal / headerCount;
            this.avgHeaders = String.format("%.1f / %d", avg, headerPossible);
        } else {
            this.avgHeaders = "N/A";
        }

        // Weakest cipher across group
        String[] levels = {"CLEAR", "WEAK", "MEDIUM", "STRONG"};
        int worstIdx = levels.length - 1;
        for (HostResult hr : hosts) {
            ICipherSuite[] ciphers = hr.getCiphers();
            if (ciphers == null) continue;
            for (ICipherSuite cs : ciphers) {
                String eval = cs.getStrengthEvaluation();
                if (eval == null) continue;
                for (int i = 0; i < levels.length; i++) {
                    if (eval.equalsIgnoreCase(levels[i]) && i < worstIdx) {
                        worstIdx = i;
                        break;
                    }
                }
            }
        }
        this.weakestCipher = worstIdx < levels.length ? levels[worstIdx] : "N/A";

        CardSize cs = prefs.getCardSize();
        setPreferredSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setMinimumSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setMaximumSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setOpaque(false);

        addMouseListener(new MouseAdapter() {
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
                firePropertyChange("gradeZoom", null, grade);
            }
        });
    }

    public String getGrade() {
        return grade;
    }

    public List<HostResult> getHosts() {
        return hosts;
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

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();

        Font cardFont = prefs.getCardFont();
        Color bgColor = prefs.getCardBg();
        Color fgColor = prefs.getCardText();
        int badgeSize = prefs.getCardBadgeSize();

        // Card background
        g2.setColor(bgColor);
        g2.fillRoundRect(0, 0, w, h, ARC, ARC);

        // Border
        if (hovered) {
            g2.setColor(fgColor);
        } else {
            g2.setColor(prefs.getCardBorder());
        }
        g2.drawRoundRect(0, 0, w - 1, h - 1, ARC, ARC);

        int x = PADDING;
        int y = PADDING;

        // Large grade badge — sized from prefs
        Color badgeColor = GradeDistributionBar.colorForGrade(grade);
        g2.setColor(badgeColor);
        g2.fillOval(x, y, badgeSize, badgeSize);
        g2.setColor(Color.WHITE);
        Font badgeFont = cardFont.deriveFont(Font.BOLD, (float) (cardFont.getSize() + 2));
        g2.setFont(badgeFont);
        FontMetrics bfm = g2.getFontMetrics();
        int bx = x + (badgeSize - bfm.stringWidth(grade)) / 2;
        int by = y + (badgeSize + bfm.getAscent() - bfm.getDescent()) / 2;
        g2.drawString(grade, bx, by);

        // Host count — no font/color changes (uses component defaults)
        Font titleFont = getFont().deriveFont(Font.BOLD, 14f);
        g2.setFont(titleFont);
        Color labelFg = UIManager.getColor("Label.foreground");
        if (labelFg == null) labelFg = Color.BLACK;
        g2.setColor(labelFg);
        String countText = hostCount + " host" + (hostCount != 1 ? "s" : "");
        g2.drawString(countText, x + badgeSize + 10, y + bfm.getAscent());

        // Data lines — card font, font size, text color from prefs
        Font dataFont = cardFont.deriveFont(Font.PLAIN, (float) cardFont.getSize());
        g2.setFont(dataFont);
        FontMetrics dfm = g2.getFontMetrics();
        int lineH = dfm.getHeight() + 2;
        int dataY = y + badgeSize + 14;
        int maxTextW = w - 2 * PADDING;

        g2.setColor(fgColor);
        g2.drawString(clipText(g2, "Score range: " + scoreRange, maxTextW), x, dataY);
        dataY += lineH;

        g2.drawString(clipText(g2, "Protocols: " + protocolSummary, maxTextW), x, dataY);
        dataY += lineH;

        g2.drawString(clipText(g2, "Avg headers: " + avgHeaders, maxTextW), x, dataY);
        dataY += lineH;

        g2.drawString(clipText(g2, "Weakest cipher: " + weakestCipher, maxTextW), x, dataY);
        dataY += lineH + 4;

        // Call-to-action — card font, font size, italic, keep badge-blend color
        Color ctaColor = HostCard.blendColors(badgeColor, bgColor, 0.7f);
        g2.setColor(ctaColor);
        Font ctaFont = cardFont.deriveFont(Font.ITALIC, (float) cardFont.getSize());
        g2.setFont(ctaFont);
        g2.drawString("Click to view hosts  \u2192", x, dataY);
    }

    private String clipText(Graphics2D g2, String text, int maxWidth) {
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
