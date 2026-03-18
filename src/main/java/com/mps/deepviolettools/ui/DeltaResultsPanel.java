package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import com.mps.deepviolettools.model.CipherDelta;
import com.mps.deepviolettools.model.DeltaDirection;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.model.FingerprintDelta;
import com.mps.deepviolettools.model.HostDelta;
import com.mps.deepviolettools.model.MapDelta;
import com.mps.deepviolettools.model.RiskDelta;
import com.mps.deepviolettools.model.SharedRiskAnalysis;
import com.mps.deepviolettools.util.FontPreferences;
import com.mps.deepviolettools.util.ReportExporter;

/**
 * Panel for displaying delta scan results with a card-based layout.
 * Shows a single {@link DeltaCard} in the card area and a structured
 * detail pane below with shared risk analysis styled like a normal
 * scan report.
 */
public class DeltaResultsPanel extends JPanel {

    private FontPreferences prefs;

    private final JPanel cardContainer;
    private final JScrollPane cardScroll;
    private final JTextPane detailPane;
    private final StyledDocument detailDoc;
    private final JScrollPane detailScroll;
    private final JSplitPane splitPane;

    private DeltaScanResult currentResult;
    private SharedRiskAnalysis sharedAnalysis;
    private DeltaCard deltaCard;

    private boolean externalDetailMode;

    // Colors for delta direction rendering (workbench mode)
    private static final Color ADDED_COLOR = new Color(76, 175, 80);     // green
    private static final Color REMOVED_COLOR = new Color(244, 67, 54);   // red
    private static final Color CHANGED_COLOR = new Color(255, 193, 7);   // yellow

    public DeltaResultsPanel(FontPreferences prefs) {
        super(new BorderLayout(0, 4));
        this.prefs = prefs;

        // Card container with WrapLayout
        cardContainer = new JPanel(new WrapLayout(FlowLayout.LEFT, 8, 8));
        cardScroll = new JScrollPane(cardContainer);
        cardScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        cardScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        cardScroll.setBorder(null);
        cardScroll.getVerticalScrollBar().setUnitIncrement(16);

        // Detail pane
        detailPane = new JTextPane();
        detailPane.setEditable(false);
        detailDoc = detailPane.getStyledDocument();
        detailScroll = new JScrollPane(detailPane);
        detailScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        detailScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        detailScroll.setBorder(null);

        // Split pane: cards on top, detail on bottom
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, cardScroll, detailScroll);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(null);
        splitPane.setResizeWeight(0.15);

        add(splitPane, BorderLayout.CENTER);
        applyTheme(prefs);
    }

    /**
     * Set the delta scan results to display.
     */
    public void setResults(DeltaScanResult result) {
        this.currentResult = result;

        // Compute shared risk analysis
        if (result != null) {
            this.sharedAnalysis = SharedRiskAnalysis.analyze(result);
        } else {
            this.sharedAnalysis = null;
        }

        // Build card
        cardContainer.removeAll();
        if (result != null) {
            deltaCard = new DeltaCard(result, prefs);
            deltaCard.setSelected(true);
            deltaCard.addPropertyChangeListener("selectedDelta", e -> {
                refreshDetail();
            });
            cardContainer.add(deltaCard);
        } else {
            deltaCard = null;
        }
        cardContainer.revalidate();
        cardContainer.repaint();

        // Render detail
        if (result != null) {
            renderDetail();
        }

        firePropertyChange("viewState", null, "DELTA");
    }

    /**
     * Clear all results and reset the panel.
     */
    public void clearResults() {
        currentResult = null;
        sharedAnalysis = null;
        deltaCard = null;
        cardContainer.removeAll();
        cardContainer.revalidate();
        cardContainer.repaint();
        try {
            detailDoc.remove(0, detailDoc.getLength());
        } catch (BadLocationException ignored) {
        }
        firePropertyChange("viewState", null, "EMPTY");
    }

    /**
     * Re-render the detail pane (e.g., after workbench mode toggle).
     */
    public void refreshDetail() {
        if (currentResult != null) {
            renderDetail();
        }
    }

    // ---- External detail API (matching ScanResultsPanel) ----

    /**
     * Enable or disable external detail mode. When enabled, the detail
     * scroll pane is removed from the internal split so the parent
     * container can place it externally.
     */
    public void setExternalDetailMode(boolean external) {
        this.externalDetailMode = external;
        if (external) {
            // Remove detail from internal split — parent will place it
            splitPane.setBottomComponent(null);
            splitPane.setDividerSize(0);
            splitPane.revalidate();
        } else {
            // Restore detail inside the internal split
            splitPane.setBottomComponent(detailScroll);
            splitPane.setDividerSize(6);
            splitPane.setResizeWeight(0.15);
            splitPane.revalidate();
        }
    }

    public JScrollPane getDetailScrollPane() {
        return detailScroll;
    }

    public StyledDocument getDetailDocument() {
        return detailDoc;
    }

    public JTextPane getDetailPane() {
        return detailPane;
    }

    public boolean isDetailShowing() {
        return currentResult != null;
    }

    public int getDetailDividerLocation() {
        if (splitPane.getBottomComponent() == null) return -1;
        return splitPane.getDividerLocation();
    }

    public void applyTheme(FontPreferences themePrefs) {
        this.prefs = themePrefs;
        detailPane.setBackground(themePrefs.getScanBackground());
        detailPane.setFont(themePrefs.getScanFont());
        detailPane.setCaretColor(themePrefs.getScanDefaultText());
        if (deltaCard != null) {
            deltaCard.setPrefs(themePrefs);
        }
        if (currentResult != null) {
            renderDetail();
        }
    }

    // ---- Detail rendering ----

    private void renderDetail() {
        try {
            detailDoc.remove(0, detailDoc.getLength());
        } catch (BadLocationException ignored) {
        }

        Font font = prefs.getScanFont();
        Color noticeColor = prefs.getScanNotice();
        Color headingColor = prefs.getScanHeading();
        Color subsectionColor = prefs.getScanSubsection();
        Color contentColor = prefs.getScanContent();
        boolean wrap = prefs.isHardwrapEnabled();
        int wrapWidth = prefs.getHardwrapWidth();

        // ---- Standard DeepViolet banner ----
        String banner = ReportExporter.buildBannerText("DeepViolet Delta Comparison");
        for (String line : banner.split("\n", -1)) {
            appendStyled(line + "\n", font, noticeColor, true);
        }

        if (sharedAnalysis == null || sharedAnalysis.getTotalHostCount() == 0) {
            appendStyled("\n", font, contentColor, false);
            appendStyled("[Shared Risks]\n", font, headingColor, true);
            appendWrappedLine("   No shared risks found.", "      ",
                    wrap, wrapWidth, font, contentColor, false);
            detailPane.setCaretPosition(0);
            return;
        }

        boolean includeMeta = prefs.isSectionIncludeMetadata();

        // ---- Universal shared risks (all hosts) ----
        if (prefs.isSectionRiskAssessment()) {
            appendStyled("\n", font, contentColor, false);
            appendStyled("[Shared Risks]\n", font, headingColor, true);

            // Show base and target scan file paths
            String basePath = currentResult.getBaseFile() != null
                    ? currentResult.getBaseFile().getAbsolutePath() : "(unknown)";
            String targetPath = currentResult.getTargetFile() != null
                    ? currentResult.getTargetFile().getAbsolutePath() : "(unknown)";
            appendSubsection("   Base scan", basePath, "      ",
                    wrap, wrapWidth, font, subsectionColor, contentColor);
            appendSubsection("   Target scan", targetPath, "      ",
                    wrap, wrapWidth, font, subsectionColor, contentColor);

            List<RiskDelta.DeductionInfo> universal = sharedAnalysis.getUniversalDeductions();
            if (!universal.isEmpty()) {
                for (RiskDelta.DeductionInfo di : universal) {
                    Color sevColor = prefs.getColorForSeverity(di.getSeverity());
                    String line = "   " + di.getRuleId() + " [" + di.getSeverity()
                            + "] " + di.getDescription()
                            + " (score: " + formatScore(di.getScore()) + ")";
                    appendWrappedLine(line, "      ", wrap, wrapWidth,
                            font, sevColor, true);
                }
            } else {
                appendWrappedLine("   No risks shared across all hosts.", "      ",
                        wrap, wrapWidth, font, contentColor, false);
            }

            // ---- Per-host-group shared risks ----
            for (SharedRiskAnalysis.SharedRiskGroup group : sharedAnalysis.getHostGroups()) {
                appendStyled("\n", font, contentColor, false);
                appendStyled("[Shared Risks]\n", font, headingColor, true);

                Set<String> hostUrls = group.getHostUrls();
                appendSubsection("   Hosts", String.join(", ", hostUrls), "      ",
                        wrap, wrapWidth, font, subsectionColor, contentColor);

                for (RiskDelta.DeductionInfo di : group.getDeductions()) {
                    Color sevColor = prefs.getColorForSeverity(di.getSeverity());
                    String line = "   " + di.getRuleId() + " [" + di.getSeverity()
                            + "] " + di.getDescription()
                            + " (score: " + formatScore(di.getScore()) + ")";
                    appendWrappedLine(line, "      ", wrap, wrapWidth,
                            font, sevColor, true);
                }
            }
        }

        // ---- Workbench mode: per-host detailed section deltas ----
        if (prefs.isWorkbenchMode()) {
            renderWorkbenchSections(font, headingColor, subsectionColor,
                    contentColor, wrap, wrapWidth);
        }

        detailPane.setCaretPosition(0);
    }

    // ---- Workbench mode: per-host section deltas ----

    private void renderWorkbenchSections(Font font, Color headingColor,
                                          Color subsectionColor, Color contentColor,
                                          boolean wrap, int wrapWidth) {
        List<HostDelta> hostDeltas = currentResult.getHostDeltas();
        boolean includeMeta = prefs.isSectionIncludeMetadata();

        // Delta summary (always shown)
        appendStyled("\n", font, contentColor, false);
        appendStyled("[Delta Summary]\n", font, headingColor, true);
        appendWrappedLine("   Changed: " + currentResult.getChangedCount()
                + "   Added: " + currentResult.getAddedCount()
                + "   Removed: " + currentResult.getRemovedCount()
                + "   Unchanged: " + currentResult.getUnchangedCount(),
                "      ", wrap, wrapWidth, font, contentColor, false);

        // Per-host risk score changes (guarded by risk assessment setting)
        if (prefs.isSectionRiskAssessment()) {
            boolean hasRiskChanges = false;
            for (HostDelta hd : hostDeltas) {
                if (hd.getRiskDelta() != null && hd.getRiskDelta().hasChanges()) {
                    hasRiskChanges = true;
                    break;
                }
            }
            if (hasRiskChanges) {
                appendStyled("\n", font, contentColor, false);
                appendStyled("[Risk Score Changes]\n", font, headingColor, true);
                for (HostDelta hd : hostDeltas) {
                    RiskDelta rd = hd.getRiskDelta();
                    if (rd == null || !rd.hasChanges()) continue;
                    Color dirColor = directionColor(rd.getDirection());
                    String line = "   " + hd.getNormalizedUrl() + ": "
                            + rd.getBaseGrade() + " (" + rd.getBaseScore() + ") \u2192 "
                            + rd.getTargetGrade() + " (" + rd.getTargetScore() + ")"
                            + " [" + (rd.getScoreDiff() >= 0 ? "+" : "")
                            + rd.getScoreDiff() + "]";
                    appendWrappedLine(line, "      ", wrap, wrapWidth,
                            font, dirColor, false);
                }
            }
        }

        // Per-host detailed section deltas
        for (HostDelta hd : hostDeltas) {
            if (!hd.hasChanges()) continue;

            boolean hasEnabled = hasEnabledSections(hd);
            if (!hasEnabled) continue;

            appendStyled("\n", font, contentColor, false);
            appendStyled("[" + hd.getNormalizedUrl() + "]\n", font, headingColor, true);

            if (prefs.isSectionRiskAssessment())
                renderRiskDeductions(hd, font, subsectionColor, contentColor,
                        wrap, wrapWidth, includeMeta);
            String host = hd.getNormalizedUrl();
            if (prefs.isSectionCipherSuites())
                renderCipherDelta(hd.getCipherDelta(), host, font, subsectionColor,
                        contentColor, wrap, wrapWidth, includeMeta);
            if (prefs.isSectionSecurityHeaders())
                renderMapDelta(hd.getSecurityHeadersDelta(), "Security Headers",
                        host, font, subsectionColor, contentColor, wrap, wrapWidth, includeMeta);
            if (prefs.isSectionConnection())
                renderMapDelta(hd.getConnectionDelta(), "Connection",
                        host, font, subsectionColor, contentColor, wrap, wrapWidth, includeMeta);
            if (prefs.isSectionHttpResponse())
                renderMapDelta(hd.getHttpHeadersDelta(), "HTTP Headers",
                        host, font, subsectionColor, contentColor, wrap, wrapWidth, includeMeta);
            if (prefs.isSectionTlsFingerprint())
                renderFingerprintDelta(hd.getFingerprintDelta(), host, font,
                        subsectionColor, contentColor, wrap, wrapWidth, includeMeta);
        }

        // Added/removed hosts (always shown)
        List<HostDelta> addedHosts = currentResult.getHostDeltas(
                HostDelta.HostStatus.ADDED);
        if (!addedHosts.isEmpty()) {
            appendStyled("\n", font, contentColor, false);
            appendStyled("[Hosts Added]\n", font, headingColor, true);
            for (HostDelta hd : addedHosts) {
                appendWrappedLine("   + " + hd.getNormalizedUrl(), "      ",
                        wrap, wrapWidth, font, ADDED_COLOR, false);
            }
        }

        List<HostDelta> removedHosts = currentResult.getHostDeltas(
                HostDelta.HostStatus.REMOVED);
        if (!removedHosts.isEmpty()) {
            appendStyled("\n", font, contentColor, false);
            appendStyled("[Hosts Removed]\n", font, headingColor, true);
            for (HostDelta hd : removedHosts) {
                appendWrappedLine("   - " + hd.getNormalizedUrl(), "      ",
                        wrap, wrapWidth, font, REMOVED_COLOR, false);
            }
        }
    }

    private void renderRiskDeductions(HostDelta hd, Font font,
                                       Color subsectionColor, Color contentColor,
                                       boolean wrap, int wrapWidth,
                                       boolean includeMeta) {
        RiskDelta rd = hd.getRiskDelta();
        if (rd == null || !rd.hasChanges()) return;

        String host = hd.getNormalizedUrl();
        if (!rd.getAddedDeductions().isEmpty()) {
            appendStyled("   Added deductions (" + host + "):\n", font, subsectionColor, true);
            for (RiskDelta.DeductionInfo di : rd.getAddedDeductions()) {
                Color sevColor = prefs.getColorForSeverity(di.getSeverity());
                String line = "      " + di.getRuleId();
                if (includeMeta) {
                    line += " [" + di.getSeverity() + "] " + di.getDescription()
                            + " (score: " + formatScore(di.getScore()) + ")";
                }
                appendWrappedLine(line, "         ", wrap, wrapWidth,
                        font, sevColor, true);
            }
        }
        if (!rd.getRemovedDeductions().isEmpty()) {
            appendStyled("   Removed deductions (" + host + "):\n", font, subsectionColor, true);
            for (RiskDelta.DeductionInfo di : rd.getRemovedDeductions()) {
                Color sevColor = prefs.getColorForSeverity(di.getSeverity());
                String line = "      " + di.getRuleId();
                if (includeMeta) {
                    line += " [" + di.getSeverity() + "] " + di.getDescription()
                            + " (score: " + formatScore(di.getScore()) + ")";
                }
                appendWrappedLine(line, "         ", wrap, wrapWidth,
                        font, sevColor, true);
            }
        }
    }

    private void renderCipherDelta(CipherDelta cd, String host, Font font,
                                    Color subsectionColor, Color contentColor,
                                    boolean wrap, int wrapWidth,
                                    boolean includeMeta) {
        if (cd == null || !cd.hasChanges()) return;

        appendStyled("   Cipher suite changes (" + host + "):\n", font, subsectionColor, true);
        for (CipherDelta.CipherInfo ci : cd.getAddedCiphers()) {
            String line = "      + " + ci.getName();
            if (includeMeta) {
                line += " (" + ci.getStrength() + ", " + ci.getProtocol() + ")";
            }
            appendWrappedLine(line, "         ", wrap, wrapWidth,
                    font, ADDED_COLOR, false);
        }
        for (CipherDelta.CipherInfo ci : cd.getRemovedCiphers()) {
            String line = "      - " + ci.getName();
            if (includeMeta) {
                line += " (" + ci.getStrength() + ", " + ci.getProtocol() + ")";
            }
            appendWrappedLine(line, "         ", wrap, wrapWidth,
                    font, REMOVED_COLOR, false);
        }
    }

    private void renderMapDelta(MapDelta md, String title, String host,
                                 Font font, Color subsectionColor, Color contentColor,
                                 boolean wrap, int wrapWidth,
                                 boolean includeMeta) {
        if (md == null || !md.hasChanges()) return;

        appendStyled("   " + title + " changes (" + host + "):\n", font, subsectionColor, true);
        for (Map.Entry<String, String> e : md.getAddedEntries().entrySet()) {
            String line = "      + " + e.getKey();
            if (includeMeta) line += ": " + e.getValue();
            appendWrappedLine(line, "         ", wrap, wrapWidth,
                    font, ADDED_COLOR, false);
        }
        for (Map.Entry<String, String> e : md.getRemovedEntries().entrySet()) {
            String line = "      - " + e.getKey();
            if (includeMeta) line += ": " + e.getValue();
            appendWrappedLine(line, "         ", wrap, wrapWidth,
                    font, REMOVED_COLOR, false);
        }
        for (Map.Entry<String, String[]> e : md.getChangedEntries().entrySet()) {
            String line = "      ~ " + e.getKey();
            if (includeMeta) {
                line += ": \"" + e.getValue()[0] + "\" \u2192 \"" + e.getValue()[1] + "\"";
            }
            appendWrappedLine(line, "         ", wrap, wrapWidth,
                    font, CHANGED_COLOR, false);
        }
    }

    private void renderFingerprintDelta(FingerprintDelta fd, String host,
                                         Font font, Color subsectionColor, Color contentColor,
                                         boolean wrap, int wrapWidth,
                                         boolean includeMeta) {
        if (fd == null || !fd.hasChanges()) return;

        appendStyled("   Probe Fingerprint changes (" + host + "):\n", font, subsectionColor, true);
        for (FingerprintDelta.ProbeDiff pd : fd.getProbeDiffs()) {
            String line = "      Probe " + pd.getProbeNumber();
            if (includeMeta) {
                line += ": " + pd.getBaseCode() + " \u2192 " + pd.getTargetCode();
            }
            appendWrappedLine(line, "         ", wrap, wrapWidth, font, CHANGED_COLOR, false);
        }
    }

    private boolean hasEnabledSections(HostDelta hd) {
        if (prefs.isSectionRiskAssessment()
                && hd.getRiskDelta() != null && hd.getRiskDelta().hasChanges())
            return true;
        if (prefs.isSectionCipherSuites()
                && hd.getCipherDelta() != null && hd.getCipherDelta().hasChanges())
            return true;
        if (prefs.isSectionSecurityHeaders()
                && hd.getSecurityHeadersDelta() != null && hd.getSecurityHeadersDelta().hasChanges())
            return true;
        if (prefs.isSectionConnection()
                && hd.getConnectionDelta() != null && hd.getConnectionDelta().hasChanges())
            return true;
        if (prefs.isSectionHttpResponse()
                && hd.getHttpHeadersDelta() != null && hd.getHttpHeadersDelta().hasChanges())
            return true;
        if (prefs.isSectionTlsFingerprint()
                && hd.getFingerprintDelta() != null && hd.getFingerprintDelta().hasChanges())
            return true;
        return false;
    }

    private static Color directionColor(DeltaDirection dir) {
        if (dir == null) return CHANGED_COLOR;
        return switch (dir) {
            case IMPROVED -> ADDED_COLOR;
            case DEGRADED -> REMOVED_COLOR;
            case MIXED -> CHANGED_COLOR;
            case NEUTRAL -> CHANGED_COLOR;
            case UNCHANGED -> CHANGED_COLOR;
        };
    }

    // ---- Styled text helpers ----

    /**
     * Append a subsection label (bold, subsection color) followed by
     * its value (content color) on the same line, with hard wrapping
     * applied to the combined text.
     */
    private void appendSubsection(String label, String value, String contIndent,
                                   boolean wrap, int wrapWidth,
                                   Font font, Color labelColor, Color valueColor) {
        String labelPart = label + ": ";
        String fullLine = labelPart + value;

        if (!wrap || fullLine.length() <= wrapWidth) {
            appendStyled(labelPart, font, labelColor, true);
            appendStyled(value + "\n", font, valueColor, false);
            return;
        }

        // Label fits but value overflows — render label, then wrap value
        appendStyled(labelPart, font, labelColor, true);
        int firstValueLen = wrapWidth - labelPart.length();
        if (firstValueLen <= 0) {
            // Label itself exceeds wrap width; newline then wrap value
            appendStyled("\n", font, valueColor, false);
            wrapContinuation(value, contIndent, wrapWidth, font, valueColor, false);
            return;
        }
        int end = findBreakPoint(value, firstValueLen);
        appendStyled(value.substring(0, end) + "\n", font, valueColor, false);
        if (end < value.length()) {
            wrapContinuation(value.substring(end).trim(), contIndent,
                    wrapWidth, font, valueColor, false);
        }
    }

    /**
     * Append a single-color line with optional hard wrapping.
     * Matches the behavior of {@code MainFrm.appendWrappedSingle()}.
     */
    private void appendWrappedLine(String text, String contIndent,
                                    boolean wrap, int wrapWidth,
                                    Font font, Color fg, boolean bold) {
        if (!wrap || text.length() <= wrapWidth) {
            appendStyled(text + "\n", font, fg, bold);
            return;
        }

        int pos = 0;
        boolean first = true;
        while (pos < text.length()) {
            int available = first ? wrapWidth : wrapWidth - contIndent.length();
            if (available <= 0) available = 20;
            int remaining = text.length() - pos;
            int end;
            if (remaining <= available) {
                end = text.length();
            } else {
                end = pos + findBreakPoint(text.substring(pos), available);
            }
            String segment = text.substring(pos, end);
            if (!first) {
                segment = contIndent + segment.trim();
            }
            appendStyled(segment + "\n", font, fg, bold);
            pos = end;
            first = false;
        }
    }

    /**
     * Render continuation lines for a wrapped value.
     */
    private void wrapContinuation(String text, String contIndent,
                                   int wrapWidth, Font font,
                                   Color fg, boolean bold) {
        int pos = 0;
        int lineLen = wrapWidth - contIndent.length();
        if (lineLen <= 0) lineLen = 20;

        while (pos < text.length()) {
            int remaining = text.length() - pos;
            int end;
            if (remaining <= lineLen) {
                end = text.length();
            } else {
                end = pos + findBreakPoint(text.substring(pos), lineLen);
            }
            String segment = text.substring(pos, end).trim();
            if (!segment.isEmpty()) {
                appendStyled(contIndent + segment + "\n", font, fg, bold);
            }
            pos = end;
        }
    }

    /**
     * Find a suitable break point within maxLen characters of text.
     * Prefers breaking at comma or space boundaries.
     * Matches the behavior of {@code MainFrm.findBreakPoint()}.
     */
    private static int findBreakPoint(String text, int maxLen) {
        if (text.length() <= maxLen) {
            return text.length();
        }
        int lastComma = text.lastIndexOf(',', maxLen);
        int lastSpace = text.lastIndexOf(' ', maxLen);
        int breakAt = Math.max(lastComma, lastSpace);
        if (breakAt > 20) {
            return breakAt + 1;
        }
        // No good break point; hard-break at maxLen
        return maxLen;
    }

    /**
     * Append styled text to the document.
     */
    private void appendStyled(String text, Font font, Color fg, boolean bold) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, font.getFamily());
        StyleConstants.setFontSize(attrs, font.getSize());
        StyleConstants.setForeground(attrs, fg);
        StyleConstants.setBold(attrs, bold);
        try {
            detailDoc.insertString(detailDoc.getLength(), text, attrs);
        } catch (BadLocationException ignored) {
        }
    }

    private static String formatScore(double score) {
        if (score == (int) score) {
            return String.valueOf((int) score);
        }
        return String.format("%.2f", score);
    }
}
