package com.mps.deepviolettools.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.AlphaComposite;
import java.awt.Composite;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Map;

import javax.swing.JPanel;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolettools.model.CardMetaElement;
import com.mps.deepviolettools.model.CardSize;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * A custom-painted card displaying the scan summary for a single host.
 * Shows the letter grade badge, hostname, risk score, negotiated protocol,
 * worst cipher strength, security header count, and certificate status.
 *
 * <p>Normal cards delegate rendering to {@link CardRenderer} using the
 * configured {@link com.mps.deepviolettools.model.CardLayout}.  Error
 * cards use a hardcoded layout.</p>
 *
 * <p>Fires a {@code PropertyChangeEvent("selectedHost", null, hostResult)}
 * when clicked.</p>
 */
public class HostCard extends JPanel {

    private static final int ARC = 10;
    private static final int PADDING = 12;

    // Mini risk bar constants
    private static final int MINI_BAR_BLOCKS = 10;
    private static final int MINI_BAR_HEIGHT = 4;
    private static final int MINI_BAR_GAP = 2;

    private final HostResult hostResult;
    private FontPreferences prefs;
    private boolean hovered;
    private boolean selected;
    private boolean placeholder;

    // Extracted display data
    private final String hostname;
    private final String ipAddress;
    private final String grade;
    private final int score;
    private final String protocol;
    private final String worstCipher;
    private final String headerInfo;
    private final String certStatus;
    private final String certExpiry;
    private final String keyInfo;
    private final String issuer;
    private final String sanCount;
    private final String revocation;
    private final boolean isError;
    private final String errorLine;

    // Mini risk bar data: [category][0=pass, 1=inconclusive, 2=fail] block counts
    private final int[][] categoryBars;
    private final String[] categoryNames;

    /** ElementDataProvider backed by this card's scan data. */
    private final CardRenderer.ElementDataProvider dataProvider =
            new CardRenderer.ElementDataProvider() {
        @Override
        public String getText(CardMetaElement element) {
            switch (element) {
                case GRADE: return grade;
                case SCORE: return score >= 0 ? score + "/100" : "N/A";
                case HOSTNAME: return hostname;
                case IP: return ipAddress != null ? ipAddress : "N/A";
                case TLS_VERSION: return protocol != null ? protocol : "N/A";
                case CIPHERS: return worstCipher != null ? worstCipher : "N/A";
                case HEADERS: return headerInfo != null ? headerInfo : "N/A";
                case CERT: return certStatus != null ? certStatus : "N/A";
                case CERT_EXPIRY: return certExpiry != null ? certExpiry : "N/A";
                case KEY_INFO: return keyInfo != null ? keyInfo : "N/A";
                case ISSUER: return issuer != null ? issuer : "N/A";
                case SAN_COUNT: return sanCount != null ? sanCount : "N/A";
                case REVOCATION: return revocation != null ? revocation : "N/A";
                case RISK_BARS: return "";
                default: return "";
            }
        }

        @Override
        public String getGrade() { return grade; }

        @Override
        public int[][] getCategoryBars() { return categoryBars; }

        @Override
        public String[] getCategoryNames() { return categoryNames; }
    };

    public HostCard(HostResult hostResult, FontPreferences prefs) {
        this.hostResult = hostResult;
        this.prefs = prefs;
        this.isError = !hostResult.isSuccess();

        // Extract hostname from URL
        String url = hostResult.getTargetUrl();
        String host = url;
        String ip = null;
        try {
            URL u = new URL(url);
            host = u.getHost();
            if (u.getPort() > 0 && u.getPort() != 443) {
                host += ":" + u.getPort();
            }
        } catch (MalformedURLException ignored) {
            // Strip protocol prefix as fallback
            if (host.startsWith("https://")) host = host.substring(8);
            if (host.endsWith("/")) host = host.substring(0, host.length() - 1);
        }
        this.hostname = host;

        // Extract IP from connection properties or resolve
        Map<String, String> conn = isError ? null : hostResult.getConnProperties();
        if (conn != null && conn.containsKey("REMOTE_ADDRESS")) {
            ip = conn.get("REMOTE_ADDRESS");
        }
        if (ip == null && !isError) {
            try {
                String bareHost = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
                ip = InetAddress.getByName(bareHost).getHostAddress();
            } catch (UnknownHostException ignored) {
                // leave null
            }
        }
        this.ipAddress = ip;

        if (isError) {
            this.grade = "!";
            this.score = -1;
            this.protocol = null;
            this.worstCipher = null;
            this.headerInfo = null;
            this.certStatus = null;
            this.certExpiry = null;
            this.keyInfo = null;
            this.issuer = null;
            this.sanCount = null;
            this.revocation = null;
            this.categoryBars = null;
            this.categoryNames = null;
            String msg = hostResult.getErrorMessage();
            this.errorLine = msg != null ? msg.split("[\r\n]")[0] : "Unknown error";
        } else {
            // Grade + score
            IRiskScore rs = hostResult.getRiskScore();
            if (rs != null) {
                this.grade = rs.getLetterGrade().toDisplayString();
                this.score = rs.getTotalScore();
            } else {
                this.grade = "?";
                this.score = -1;
            }

            // Negotiated protocol
            if (conn != null && conn.containsKey("NEGOTIATED_PROTOCOL")) {
                this.protocol = conn.get("NEGOTIATED_PROTOCOL");
            } else {
                this.protocol = null;
            }

            // Worst cipher strength
            ICipherSuite[] ciphers = hostResult.getCiphers();
            this.worstCipher = findWorstCipher(ciphers);

            // Security headers count
            Map<String, String> secHeaders = hostResult.getSecurityHeaders();
            if (secHeaders != null) {
                int present = 0;
                int total = secHeaders.size();
                for (String val : secHeaders.values()) {
                    if (val != null && !"MISSING".equalsIgnoreCase(val)) {
                        present++;
                    }
                }
                this.headerInfo = present + "/" + total;
            } else {
                this.headerInfo = null;
            }

            // Cert status from scan tree
            this.certStatus = extractCertStatus(hostResult);
            this.certExpiry = extractScanValue(hostResult, "days until expiration");
            this.keyInfo = extractKeyInfo(hostResult);
            this.issuer = extractIssuer(hostResult);
            this.sanCount = extractScanValue(hostResult, "san count");
            this.revocation = extractRevocationSummary(hostResult);
            this.errorLine = null;

            // Mini risk bars — one per category
            IRiskScore riskScore = hostResult.getRiskScore();
            if (riskScore != null) {
                ICategoryScore[] cats = riskScore.getCategoryScores();
                if (cats != null && cats.length > 0) {
                    this.categoryBars = new int[cats.length][3];
                    this.categoryNames = new String[cats.length];
                    for (int i = 0; i < cats.length; i++) {
                        categoryNames[i] = cats[i].getDisplayName();
                        categoryBars[i] = computeBarBlocks(cats[i]);
                    }
                } else {
                    this.categoryBars = null;
                    this.categoryNames = null;
                }
            } else {
                this.categoryBars = null;
                this.categoryNames = null;
            }
        }

        CardSize cs = prefs.getCardSize();
        setPreferredSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setMinimumSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setMaximumSize(new Dimension(cs.getWidth(), cs.getHeight()));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setOpaque(false);

        // Enable per-pixel tooltips for risk bar hover
        javax.swing.ToolTipManager.sharedInstance().registerComponent(this);

        MouseAdapter mouseHandler = new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (placeholder) return;
                hovered = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                if (placeholder) return;
                hovered = false;
                repaint();
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (placeholder) return;
                firePropertyChange("selectedHost", null, hostResult);
            }
        };
        addMouseListener(mouseHandler);
    }

    public HostResult getHostResult() {
        return hostResult;
    }

    public boolean isError() {
        return isError;
    }

    public String getGrade() {
        return grade;
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

    public boolean isPlaceholder() {
        return placeholder;
    }

    public void setPlaceholder(boolean placeholder) {
        this.placeholder = placeholder;
        setCursor(Cursor.getPredefinedCursor(
                placeholder ? Cursor.DEFAULT_CURSOR : Cursor.HAND_CURSOR));
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        Composite origComposite = null;
        if (placeholder) {
            origComposite = g2.getComposite();
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.35f));
        }

        int w = getWidth();
        int h = getHeight();

        if (isError) {
            Color fgColor = prefs.getCardText();
            Color dimColor = prefs.getCardDim();

            // Card background
            g2.setColor(prefs.getCardBg());
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

            paintErrorCard(g2, PADDING, PADDING, w, fgColor, dimColor);
        } else {
            CardRenderer.paintCard(g2, w, h, prefs,
                    prefs.getCardLayout(), dataProvider,
                    selected, hovered, -1, -1, placeholder);
        }

        if (origComposite != null) {
            g2.setComposite(origComposite);
        }
    }

    private void paintErrorCard(Graphics2D g2, int x, int y, int w, Color fgColor, Color dimColor) {
        Font cardFont = prefs.getCardFont();
        int badgeSize = prefs.getCardBadgeSize();
        Color errorColor = prefs.getCardError();

        // Error badge
        g2.setColor(errorColor);
        g2.fillOval(x, y, badgeSize, badgeSize);
        g2.setColor(Color.WHITE);
        Font badgeFont = cardFont.deriveFont(Font.BOLD, (float) (cardFont.getSize() + 2));
        g2.setFont(badgeFont);
        FontMetrics bfm = g2.getFontMetrics();
        int bx = x + (badgeSize - bfm.stringWidth("!")) / 2;
        int by = y + (badgeSize + bfm.getAscent() - bfm.getDescent()) / 2;
        g2.drawString("!", bx, by);

        // Hostname
        Font hostFont = cardFont.deriveFont(Font.BOLD, (float) cardFont.getSize());
        g2.setFont(hostFont);
        g2.setColor(fgColor);
        String displayHost = CardRenderer.clipText(g2, hostname, w - x - badgeSize - PADDING * 2);
        g2.drawString(displayHost, x + badgeSize + 8, y + bfm.getAscent());

        // "SCAN FAILED"
        Font dataFont = cardFont.deriveFont(Font.PLAIN, (float) (cardFont.getSize() - 1));
        g2.setFont(dataFont);
        int dataY = y + badgeSize + 14;
        g2.setColor(errorColor);
        g2.drawString("SCAN FAILED", x, dataY);
        dataY += g2.getFontMetrics().getHeight() + 2;

        // Error message
        g2.setColor(dimColor);
        g2.drawString(CardRenderer.clipText(g2, errorLine, w - 2 * PADDING), x, dataY);
    }

    /**
     * Compute pass/inconclusive/fail block counts for a single category,
     * matching the algorithm in {@code UIBackgroundScanTask.buildScoreBar()}.
     */
    private static int[] computeBarBlocks(ICategoryScore cat) {
        int catScore = cat.getScore();
        int passBlocks = (int) Math.round((double) catScore / 100 * MINI_BAR_BLOCKS);
        passBlocks = Math.min(passBlocks, MINI_BAR_BLOCKS);

        double totalDed = 0, incDed = 0;
        IDeduction[] deds = cat.getDeductions();
        if (deds != null) {
            for (IDeduction d : deds) {
                totalDed += d.getScore();
                if (d.isInconclusive()) incDed += d.getScore();
            }
        }
        int pointsLost = 100 - catScore;
        int incPoints = totalDed > 0
                ? (int) Math.round(pointsLost * (incDed / totalDed)) : 0;
        int clampedInc = Math.min(incPoints, pointsLost);

        int incBlocks = (int) Math.round((double) clampedInc / 100 * MINI_BAR_BLOCKS);
        int failBlocks = MINI_BAR_BLOCKS - passBlocks - incBlocks;
        if (failBlocks < 0) { incBlocks += failBlocks; failBlocks = 0; }

        return new int[]{passBlocks, incBlocks, failBlocks};
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        if (categoryBars == null || categoryNames == null) return null;

        int barCount = categoryBars.length;
        int totalH = barCount * MINI_BAR_HEIGHT + (barCount - 1) * MINI_BAR_GAP;
        int bottomY = getHeight() - PADDING;
        int startY = bottomY - totalH;

        int my = e.getY();
        if (my < startY || my > bottomY) return null;

        int idx = (my - startY) / (MINI_BAR_HEIGHT + MINI_BAR_GAP);
        if (idx >= 0 && idx < barCount) {
            int passPercent = categoryBars[idx][0] * 100 / MINI_BAR_BLOCKS;
            return categoryNames[idx] + ": " + passPercent + "%";
        }
        return null;
    }

    private static String findWorstCipher(ICipherSuite[] ciphers) {
        if (ciphers == null || ciphers.length == 0) return null;
        // Strength ordering: CLEAR < WEAK < MEDIUM < STRONG
        String[] levels = {"CLEAR", "WEAK", "MEDIUM", "STRONG"};
        int worstIdx = levels.length - 1;
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
        return levels[worstIdx];
    }

    private static String extractCertStatus(HostResult hr) {
        if (hr.getScanTree() == null) return null;
        StringBuilder sb = new StringBuilder();
        hr.getScanTree().walk(node -> {
            if (sb.length() > 0) return;
            if (node.getKey() != null) {
                String key = node.getKey().toLowerCase();
                if (key.contains("trust state") || key.contains("certificate trust")) {
                    String val = node.getValue();
                    if (val != null) {
                        sb.append(val.trim());
                    }
                }
            }
        });
        if (sb.length() > 0) return sb.toString();
        return null;
    }

    /**
     * Extract the first key-value node whose key contains the given substring.
     */
    private static String extractScanValue(HostResult hr, String keySubstring) {
        if (hr.getScanTree() == null) return null;
        StringBuilder sb = new StringBuilder();
        hr.getScanTree().walk(node -> {
            if (sb.length() > 0) return;
            if (node.getKey() != null && node.getValue() != null) {
                if (node.getKey().toLowerCase().contains(keySubstring)) {
                    sb.append(node.getValue().trim());
                }
            }
        });
        return sb.length() > 0 ? sb.toString() : null;
    }

    /**
     * Extract key algorithm and size, e.g. "RSA-2048" or "EC-256 (secp256r1)".
     */
    private static String extractKeyInfo(HostResult hr) {
        if (hr.getScanTree() == null) return null;
        String algo = extractScanValue(hr, "public key algorithm");
        String size = extractScanValue(hr, "public key size");
        String curve = extractScanValue(hr, "public key curve");
        if (algo == null) return null;
        StringBuilder sb = new StringBuilder(algo);
        if (size != null) {
            sb.append('-').append(size.replace(" bits", ""));
        }
        if (curve != null) {
            sb.append(" (").append(curve).append(')');
        }
        return sb.toString();
    }

    /**
     * Extract the issuer CN from the Issuer DN.
     */
    private static String extractIssuer(HostResult hr) {
        String issuerDn = extractScanValue(hr, "issuer dn");
        if (issuerDn == null) return null;
        // Extract CN= value
        for (String part : issuerDn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("CN=")) {
                return trimmed.substring(3).trim();
            }
        }
        // Fall back to the O= value
        for (String part : issuerDn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("O=")) {
                return trimmed.substring(2).trim();
            }
        }
        return issuerDn.length() > 30 ? issuerDn.substring(0, 30) + "..." : issuerDn;
    }

    /**
     * Extract a short revocation status summary from the scan tree.
     */
    private static String extractRevocationSummary(HostResult hr) {
        if (hr.getScanTree() == null) return null;
        StringBuilder sb = new StringBuilder();
        hr.getScanTree().walk(node -> {
            if (sb.length() > 0) return;
            if (node.getKey() != null) {
                String key = node.getKey().toLowerCase();
                if (key.contains("ocsp check") || key.contains("ocsp status")) {
                    String val = node.getValue();
                    if (val != null) {
                        sb.append(val.trim());
                    }
                }
            }
        });
        if (sb.length() > 0) return sb.toString();
        // Check for revocation-related warnings
        StringBuilder warn = new StringBuilder();
        hr.getScanTree().walk(node -> {
            if (warn.length() > 0) return;
            if (node.getKey() != null && node.getKey().toLowerCase().contains("revoked")) {
                warn.append("REVOKED");
            }
        });
        return warn.length() > 0 ? warn.toString() : null;
    }

    static Color blendColors(Color c1, Color c2, float ratio) {
        float inv = 1f - ratio;
        int r = Math.round(c1.getRed() * ratio + c2.getRed() * inv);
        int g = Math.round(c1.getGreen() * ratio + c2.getGreen() * inv);
        int b = Math.round(c1.getBlue() * ratio + c2.getBlue() * inv);
        return new Color(Math.min(255, r), Math.min(255, g), Math.min(255, b));
    }
}
