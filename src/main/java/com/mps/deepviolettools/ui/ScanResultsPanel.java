package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.text.StyledDocument;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.model.ScanNode;
import com.mps.deepviolettools.util.FontPreferences;
import com.mps.deepviolettools.util.ReportExporter;

/**
 * Interactive panel for displaying scan results as a grade distribution
 * bar and a grid of clickable host cards. Supports three navigation states:
 * OVERVIEW (all results), GRADE_ZOOM (single grade's hosts), and HOST_DETAIL
 * (selected host's full report).
 *
 * <p>For small scans (&le;20 successful hosts), individual {@link HostCard}s
 * are shown. For larger scans, {@link GradeGroupCard}s are shown first,
 * with click-to-zoom navigation to individual hosts.</p>
 */
public class ScanResultsPanel extends JPanel {

    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.ui");
    private static final String SAMPLE_SCAN_RESOURCE = "/sample-scan.dvscan.json";
    private static final int ADAPTIVE_THRESHOLD = 20;

    private enum NavState { OVERVIEW, GRADE_ZOOM, HOST_DETAIL }

    private final BiConsumer<ScanNode, StyledDocument> detailRenderer;
    private FontPreferences prefs;

    private final GradeDistributionBar gradeBar;
    private final JPanel cardContainer;
    private final JScrollPane cardScroll;
    private final JTextPane detailPane;
    private final StyledDocument detailDoc;
    private final JScrollPane detailScroll;
    private final JSplitPane splitPane;

    private ScanResult currentResult;
    private NavState navState = NavState.OVERVIEW;
    private String zoomedGrade;
    private HostCard selectedCard;

    // When true, placeholder cards are displayed instead of real results.
    private boolean placeholderActive;

    // When true, the detail pane is rendered but not displayed internally;
    // the parent container is responsible for showing the detail scroll pane.
    private boolean externalDetailMode;

    // Cached data
    private List<HostResult> successHosts;
    private List<HostResult> errorHosts;
    private Map<String, List<HostResult>> gradeGroups;
    private Map<String, Integer> gradeCounts;

    /**
     * @param prefs          current theme preferences
     * @param detailRenderer callback that renders a ScanNode tree into a StyledDocument
     */
    public ScanResultsPanel(FontPreferences prefs, BiConsumer<ScanNode, StyledDocument> detailRenderer) {
        super(new BorderLayout(0, 4));
        this.prefs = prefs;
        this.detailRenderer = detailRenderer;

        // Grade distribution bar
        gradeBar = new GradeDistributionBar(prefs);
        gradeBar.setBorder(BorderFactory.createEmptyBorder(4, 4, 2, 4));
        add(gradeBar, BorderLayout.NORTH);

        // Card container — Scrollable panel that tracks viewport width so
        // WrapLayout wraps cards at the right edge and re-wraps on resize.
        cardContainer = new ScrollableWrapPanel(new WrapLayout(FlowLayout.LEFT, 8, 8));
        cardScroll = new JScrollPane(cardContainer);
        cardScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        cardScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        cardScroll.setBorder(null);
        cardScroll.getVerticalScrollBar().setUnitIncrement(16);

        // Click background to deselect current host card
        cardContainer.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                deselectHost();
            }
        });

        // Re-validate on resize so WrapLayout recomputes row breaks
        cardScroll.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                cardContainer.revalidate();
            }
        });

        // Detail pane (initially hidden)
        detailPane = new JTextPane();
        detailPane.setEditable(false);
        detailDoc = detailPane.getStyledDocument();
        detailScroll = new JScrollPane(detailPane);
        detailScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        detailScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        detailScroll.setBorder(null);

        // Split pane
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, cardScroll, detailScroll);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(null);

        // Start with detail hidden
        hideDetailPane();
        add(splitPane, BorderLayout.CENTER);

        // Placeholder state at startup
        showPlaceholderState();
    }

    /**
     * Display the results from a completed scan.
     */
    public void setResults(ScanResult result) {
        this.placeholderActive = false;
        gradeBar.setPlaceholder(false);
        this.currentResult = result;
        if (result == null || result.getResults().isEmpty()) {
            clearResults();
            return;
        }

        // Partition hosts into success/error and group by grade
        successHosts = new ArrayList<>();
        errorHosts = new ArrayList<>();
        gradeGroups = new LinkedHashMap<>();
        gradeCounts = new LinkedHashMap<>();

        // Maintain grade ordering
        for (String g : new String[]{"A+", "A", "B", "C", "D", "F"}) {
            gradeGroups.put(g, new ArrayList<>());
        }

        for (HostResult hr : result.getResults()) {
            if (!hr.isSuccess()) {
                errorHosts.add(hr);
                continue;
            }
            successHosts.add(hr);
            IRiskScore rs = hr.getRiskScore();
            String grade = (rs != null) ? rs.getLetterGrade().toDisplayString() : "F";
            gradeGroups.computeIfAbsent(grade, k -> new ArrayList<>()).add(hr);
        }

        // Build grade counts (non-zero only)
        for (Map.Entry<String, List<HostResult>> e : gradeGroups.entrySet()) {
            if (!e.getValue().isEmpty()) {
                gradeCounts.put(e.getKey(), e.getValue().size());
            }
        }

        // Remove empty grade buckets
        gradeGroups.values().removeIf(List::isEmpty);

        // Update grade bar
        gradeBar.setDistribution(gradeCounts,
                result.getSuccessCount() + result.getErrorCount(),
                result.getErrorCount());

        // Show appropriate view
        navState = NavState.OVERVIEW;
        zoomedGrade = null;
        selectedCard = null;
        hideDetailPane();
        detailPane.setEnabled(true);
        buildCards();
        selectFirstCard();
        firePropertyChange("viewState", null, navState.name());
    }

    /**
     * Clear all results and show empty state.
     */
    public void clearResults() {
        currentResult = null;
        successHosts = null;
        errorHosts = null;
        gradeGroups = null;
        gradeCounts = null;
        selectedCard = null;
        navState = NavState.OVERVIEW;
        zoomedGrade = null;
        gradeBar.setDistribution(null, 0, 0);
        hideDetailPane();
        try {
            detailDoc.remove(0, detailDoc.getLength());
        } catch (javax.swing.text.BadLocationException ignored) {
        }
        showPlaceholderState();
        firePropertyChange("viewState", null, "EMPTY");
    }

    /**
     * Returns true if placeholder cards are currently displayed.
     */
    public boolean isPlaceholderActive() {
        return placeholderActive;
    }

    /**
     * Returns true if scan results are loaded.
     */
    public boolean hasResults() {
        return currentResult != null;
    }

    /**
     * Returns true if the detail pane is currently showing a host's report.
     */
    public boolean isDetailShowing() {
        return navState == NavState.HOST_DETAIL;
    }

    /**
     * Returns the currently selected host result, or null if none is selected.
     */
    public HostResult getSelectedHostResult() {
        return (selectedCard != null) ? selectedCard.getHostResult() : null;
    }

    /**
     * Returns the list of host results currently visible as cards.
     */
    public List<HostResult> getVisibleHostResults() {
        List<HostResult> visible = new ArrayList<>();
        for (java.awt.Component c : cardContainer.getComponents()) {
            if (c instanceof HostCard) {
                visible.add(((HostCard) c).getHostResult());
            }
        }
        return visible;
    }

    /**
     * Deselect the current host card and hide the detail pane.
     */
    public void deselectHost() {
        if (placeholderActive) return;
        if (navState != NavState.HOST_DETAIL || selectedCard == null) return;

        selectedCard.setSelected(false);
        selectedCard = null;
        hideDetailPane();

        // Return to previous overview state
        if (zoomedGrade != null) {
            navState = NavState.GRADE_ZOOM;
        } else {
            navState = NavState.OVERVIEW;
        }
        firePropertyChange("viewState", null, navState.name());
    }

    /**
     * Re-apply theme colors from updated preferences.
     */
    public void applyTheme(FontPreferences prefs) {
        this.prefs = prefs;

        detailPane.setBackground(prefs.getScanBackground());
        detailPane.setFont(prefs.getScanFont());
        detailPane.setCaretColor(prefs.getScanDefaultText());

        gradeBar.setPrefs(prefs);

        // Update card prefs and repaint
        for (Component c : cardContainer.getComponents()) {
            if (c instanceof HostCard) {
                ((HostCard) c).setPrefs(prefs);
            } else if (c instanceof GradeGroupCard) {
                ((GradeGroupCard) c).setPrefs(prefs);
            }
        }
        cardContainer.repaint();

        // Re-render detail content with the new font/colors.
        // Covers both a selected host card and the startup placeholder.
        if (navState == NavState.HOST_DETAIL && selectedCard != null) {
            showHostDetail(selectedCard.getHostResult());
        } else if (detailDoc.getLength() > 0) {
            rerenderDetailFromCards();
        }
    }

    // ---- Navigation ----

    private void buildCards() {
        cardContainer.removeAll();

        if (navState == NavState.OVERVIEW) {
            if (successHosts.size() > ADAPTIVE_THRESHOLD) {
                buildGradeGroupCards();
            } else {
                buildHostCards(successHosts);
            }
            addErrorCards();
        } else if (navState == NavState.GRADE_ZOOM) {
            addBackButton();
            List<HostResult> gradeHosts = gradeGroups.get(zoomedGrade);
            if (gradeHosts != null) {
                buildHostCards(gradeHosts);
            }
            // Show errors in zoom view too if zoomed grade is null (shouldn't happen)
        }

        cardContainer.revalidate();
        cardContainer.repaint();

        // Scroll to top
        javax.swing.SwingUtilities.invokeLater(() ->
                cardScroll.getVerticalScrollBar().setValue(0));
    }

    private void buildHostCards(List<HostResult> hosts) {
        PropertyChangeListener hostClickListener = this::onHostCardClicked;
        for (HostResult hr : hosts) {
            HostCard card = new HostCard(hr, prefs);
            card.addPropertyChangeListener("selectedHost", hostClickListener);
            cardContainer.add(card);
        }
    }

    private void buildGradeGroupCards() {
        PropertyChangeListener gradeClickListener = this::onGradeGroupClicked;
        for (Map.Entry<String, List<HostResult>> e : gradeGroups.entrySet()) {
            GradeGroupCard card = new GradeGroupCard(e.getKey(), e.getValue(), prefs);
            card.addPropertyChangeListener("gradeZoom", gradeClickListener);
            cardContainer.add(card);
        }
    }

    private void addErrorCards() {
        if (errorHosts == null || errorHosts.isEmpty()) return;

        // Separator label
        JLabel errorLabel = new JLabel("  Scan Errors");
        errorLabel.setFont(getFont().deriveFont(Font.BOLD, 13f));
        Color dimColor = UIManager.getColor("Label.disabledForeground");
        if (dimColor == null) dimColor = Color.GRAY;
        errorLabel.setForeground(dimColor);
        errorLabel.setPreferredSize(new Dimension(10000, 24));
        errorLabel.setMaximumSize(new Dimension(10000, 24));
        cardContainer.add(errorLabel);

        PropertyChangeListener hostClickListener = this::onHostCardClicked;
        for (HostResult hr : errorHosts) {
            HostCard card = new HostCard(hr, prefs);
            card.addPropertyChangeListener("selectedHost", hostClickListener);
            cardContainer.add(card);
        }
    }

    private void addBackButton() {
        JButton btnBack = new JButton("\u2190 Back");
        btnBack.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btnBack.addActionListener(e -> {
            navState = NavState.OVERVIEW;
            zoomedGrade = null;
            selectedCard = null;
            hideDetailPane();
            buildCards();
            firePropertyChange("viewState", null, navState.name());
        });
        // Give the back button full-row width so cards start on next line
        btnBack.setPreferredSize(new Dimension(
                btnBack.getPreferredSize().width,
                btnBack.getPreferredSize().height));
        cardContainer.add(btnBack);
    }

    /**
     * Auto-select the first successful host card so the detail pane is
     * populated immediately after a scan completes.  When grade-group
     * cards are showing (large scans) this is a no-op — the user must
     * first drill into a grade before individual cards appear.
     */
    /**
     * Re-render the detail pane from the first card that has a scan tree.
     * Used by {@link #applyTheme} when no card is selected (e.g. placeholder).
     */
    private void rerenderDetailFromCards() {
        for (Component c : cardContainer.getComponents()) {
            if (c instanceof HostCard) {
                HostResult hr = ((HostCard) c).getHostResult();
                if (hr != null && hr.getScanTree() != null && detailRenderer != null) {
                    try {
                        detailDoc.remove(0, detailDoc.getLength());
                    } catch (javax.swing.text.BadLocationException ignored) {
                    }
                    detailRenderer.accept(hr.getScanTree(), detailDoc);
                    detailPane.setCaretPosition(0);
                    return;
                }
            }
        }
    }

    private void selectFirstCard() {
        for (Component c : cardContainer.getComponents()) {
            if (c instanceof HostCard) {
                HostCard card = (HostCard) c;
                HostResult hr = card.getHostResult();
                if (hr != null && hr.isSuccess()) {
                    card.setSelected(true);
                    selectedCard = card;
                    navState = NavState.HOST_DETAIL;
                    showHostDetail(hr);
                    return;
                }
            }
        }
    }

    private void onGradeGroupClicked(PropertyChangeEvent evt) {
        String grade = (String) evt.getNewValue();
        navState = NavState.GRADE_ZOOM;
        zoomedGrade = grade;
        selectedCard = null;
        hideDetailPane();
        buildCards();
        firePropertyChange("viewState", null, navState.name());
    }

    private void onHostCardClicked(PropertyChangeEvent evt) {
        if (placeholderActive) return;
        HostResult hr = (HostResult) evt.getNewValue();

        // Deselect previous card
        if (selectedCard != null) {
            selectedCard.setSelected(false);
        }

        // Find and select new card
        HostCard clickedCard = null;
        for (Component c : cardContainer.getComponents()) {
            if (c instanceof HostCard) {
                HostCard hc = (HostCard) c;
                if (hc.getHostResult() == hr) {
                    clickedCard = hc;
                    break;
                }
            }
        }

        if (clickedCard != null) {
            clickedCard.setSelected(true);
            selectedCard = clickedCard;
        }

        navState = NavState.HOST_DETAIL;
        showHostDetail(hr);
        firePropertyChange("viewState", null, navState.name());
    }

    private void showHostDetail(HostResult hr) {
        // Show detail pane in split
        showDetailPane();

        // Clear and render
        try {
            detailDoc.remove(0, detailDoc.getLength());
        } catch (javax.swing.text.BadLocationException ignored) {
        }

        if (!hr.isSuccess()) {
            // Render error details
            try {
                javax.swing.text.SimpleAttributeSet errorAttr = new javax.swing.text.SimpleAttributeSet();
                javax.swing.text.StyleConstants.setForeground(errorAttr,
                        prefs.getScanWarning());
                javax.swing.text.StyleConstants.setFontFamily(errorAttr,
                        prefs.getScanFont().getFamily());
                javax.swing.text.StyleConstants.setFontSize(errorAttr,
                        prefs.getScanFont().getSize());

                detailDoc.insertString(0,
                        "Scan Error: " + hr.getTargetUrl() + "\n\n" + hr.getErrorMessage(),
                        errorAttr);
            } catch (javax.swing.text.BadLocationException ignored) {
            }
        } else if (hr.getScanTree() != null && detailRenderer != null) {
            detailRenderer.accept(hr.getScanTree(), detailDoc);
        }

        detailPane.setCaretPosition(0);
    }

    private void showDetailPane() {
        if (externalDetailMode) return;
        splitPane.setBottomComponent(detailScroll);
        splitPane.setDividerSize(6);
        int saved = prefs.getSplitDetail();
        if (saved >= 0) {
            splitPane.setDividerLocation(saved);
        } else {
            splitPane.setDividerLocation(0.4);
        }
        splitPane.revalidate();
    }

    private void hideDetailPane() {
        splitPane.setBottomComponent(null);
        splitPane.setDividerSize(0);
        splitPane.revalidate();
    }

    private void showEmptyState() {
        cardContainer.removeAll();
        JLabel emptyLabel = new JLabel("No scan results", SwingConstants.CENTER);
        emptyLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        emptyLabel.setPreferredSize(new Dimension(300, 60));
        cardContainer.add(emptyLabel);
        cardContainer.revalidate();
        cardContainer.repaint();
    }

    /**
     * Show grayed-out placeholder card and detail report loaded from the
     * bundled sample scan resource, so users can see the layout and adjust
     * splitter/dock positions at startup.
     */
    private void showPlaceholderState() {
        cardContainer.removeAll();
        placeholderActive = true;

        ScanResult sample = loadSampleScan();
        if (sample == null || sample.getResults().isEmpty()) {
            showEmptyState();
            return;
        }

        // Grade bar from sample data
        Map<String, Integer> sampleGrades = new LinkedHashMap<>();
        for (HostResult hr : sample.getResults()) {
            if (!hr.isSuccess()) continue;
            IRiskScore rs = hr.getRiskScore();
            String grade = (rs != null) ? rs.getLetterGrade().toDisplayString() : "F";
            sampleGrades.merge(grade, 1, Integer::sum);
        }
        gradeBar.setPlaceholder(true);
        gradeBar.setDistribution(sampleGrades, sample.getResults().size(), 0);

        // Build placeholder card(s)
        HostCard firstCard = null;
        for (HostResult hr : sample.getResults()) {
            HostCard card = new HostCard(hr, prefs);
            card.setPlaceholder(true);
            if (firstCard == null) {
                firstCard = card;
                card.setSelected(true);
            }
            cardContainer.add(card);
        }

        // Render detail content for the first card's scan tree.
        // Don't show the detail pane internally — MainFrm will place it
        // externally next to the targets panel via buildScanSplitPane().
        if (firstCard != null && firstCard.getHostResult().getScanTree() != null) {
            try {
                detailDoc.remove(0, detailDoc.getLength());
            } catch (javax.swing.text.BadLocationException ignored) {
            }
            if (detailRenderer != null) {
                detailRenderer.accept(firstCard.getHostResult().getScanTree(), detailDoc);
            }
            detailPane.setCaretPosition(0);
            detailPane.setEnabled(false);
        }

        cardContainer.revalidate();
        cardContainer.repaint();
    }

    /**
     * Load the bundled sample scan from classpath resources.
     */
    private ScanResult loadSampleScan() {
        try (java.io.InputStream in = getClass().getResourceAsStream(SAMPLE_SCAN_RESOURCE)) {
            if (in == null) {
                logger.warn("Sample scan resource not found: {}", SAMPLE_SCAN_RESOURCE);
                return null;
            }
            return ReportExporter.loadScanFromJson(in);
        } catch (Exception e) {
            logger.warn("Failed to load sample scan: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Enable or disable external detail mode. When enabled, clicking a card
     * still renders the detail into the internal document but does not show
     * the detail split internally. The parent container should listen for
     * {@code "viewState"} changes and display {@link #getDetailScrollPane()}
     * externally.
     */
    public void setExternalDetailMode(boolean external) {
        this.externalDetailMode = external;
        if (external && navState == NavState.HOST_DETAIL) {
            hideDetailPane();
        }
    }

    public boolean isExternalDetailMode() {
        return externalDetailMode;
    }

    /**
     * Returns the detail scroll pane for external placement when
     * {@link #setExternalDetailMode(boolean)} is active.
     */
    public JScrollPane getDetailScrollPane() {
        return detailScroll;
    }

    /**
     * Returns the detail pane's {@link StyledDocument} so callers can
     * render arbitrary content (e.g. delta scan results) into the panel.
     */
    /**
     * Returns the current divider location of the internal detail split pane,
     * or -1 if the detail pane is hidden.
     */
    public int getDetailDividerLocation() {
        if (splitPane.getBottomComponent() == null) return -1;
        return splitPane.getDividerLocation();
    }

    public StyledDocument getDetailDocument() {
        return detailDoc;
    }

    /**
     * Returns the detail {@link JTextPane} for caret positioning.
     */
    public JTextPane getDetailPane() {
        return detailPane;
    }

    /**
     * Show the detail pane full-screen (hiding cards) for delta report display.
     * Clears the card area, hides the grade bar, and expands the detail pane
     * to fill the entire panel.
     */
    public void showFullDetailPane() {
        currentResult = null;
        gradeBar.setDistribution(null, 0, 0);
        cardContainer.removeAll();
        cardContainer.revalidate();
        cardContainer.repaint();

        if (!externalDetailMode) {
            // Show detail pane expanded internally
            splitPane.setBottomComponent(detailScroll);
            splitPane.setDividerLocation(0);
            splitPane.setDividerSize(0);
            splitPane.revalidate();
        }

        firePropertyChange("viewState", null, "DELTA");
    }

    /**
     * A JPanel that implements {@link Scrollable} to track the viewport width.
     * This forces the panel to match the scroll pane's visible width so that
     * {@link WrapLayout} wraps cards at the right edge and re-wraps on resize,
     * while still allowing vertical scrolling.
     */
    private static class ScrollableWrapPanel extends JPanel implements Scrollable {

        ScrollableWrapPanel(java.awt.LayoutManager layout) {
            super(layout);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle visibleRect, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle visibleRect, int orientation, int direction) {
            return (orientation == SwingConstants.VERTICAL) ? visibleRect.height : visibleRect.width;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }
}
