package org.ms.terminal.gui;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.util.ArrayDeque;
import java.util.Deque;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class TerminalPanel extends JPanel implements KeyListener, ComponentListener {

    private static final boolean DEBUG = false;

    private static final Font DEFAULT_FONT = new Font("Monospaced", Font.PLAIN, 16);
    private static final Color DEFAULT_BG = new Color(34,34,33);
    private static final Color DEFAULT_CURSOR_COLOR = Color.WHITE;

    private final ContentBuffer contentBuffer = new ContentBuffer();
    private final SparseCharacterArray sparseArray = new SparseCharacterArray();
    private final ViewportManager viewport;
    private final ContentProcessor processor;

    // Cursor state
    private int cursorRow = 0, cursorCol = 0;
    private boolean cursorVisible = true;
    private Color cursorColor = DEFAULT_CURSOR_COLOR;
    private Timer blinkTimer;
    private int blinkCycleMs = 0;

    // Cursor glyph (optional)
    private boolean cursorGlyphEnabled = false;
    private String cursorGlyph = ">";

    // Typewriter (cursor-only, opt-in)
    private boolean slowRollOnInitialRender = false;
    private boolean initialSlowRollDone = true;
    private boolean typewriterActive = false;
    private Timer typewriterTimer;
    private int animRow = 0, animCol = 0;
    private int typewriterDelayMs = 12;

    // Prevent re-entrant viewport reflow (offset changes during size change)
    private boolean inViewportReflow = false;
    // Track last known viewport size to detect real resizes
    private int lastViewportRows;
    private int lastViewportCols;



    public void setSlowRollOnInitialRender(boolean enabled) { this.slowRollOnInitialRender = enabled; }
    public void setTypewriterDelayMs(int ms) { this.typewriterDelayMs = Math.max(1, ms); }

    // Programmatic typewriter — tokenized (tags apply instantly; text is char-by-char)
    private int charRenderDelayMs = 0;                 // 0 = immediate
    private Timer charRenderTimer;

    private static final class Token {
        enum Type { TEXT, TAG }
        final Type type;
        String payload; // for TEXT: remaining visible text; for TAG: full "{...}"
        Token(Type t, String p) { type = t; payload = p; }
    }
    private final Deque<Token> writeQueue = new ArrayDeque<>();

    public void setCharRenderDelay(int ms) {
        this.charRenderDelayMs = Math.max(0, ms);
        if (charRenderTimer != null) {
            charRenderTimer.setDelay(charRenderDelayMs);
            charRenderTimer.setInitialDelay(charRenderDelayMs);
        }
    }

    // Font metrics
    private FontMetrics fontMetrics;
    private int charWidth;
    private int lineHeight;

    // Scroll models
    private final DefaultBoundedRangeModel vModel = new DefaultBoundedRangeModel(0, 0, 0, 0);
    private final DefaultBoundedRangeModel hModel = new DefaultBoundedRangeModel(0, 0, 0, 0);
    private boolean updatingModels = false;
    private boolean updatingFromModel = false;
    private int lastMaxOffsetRow = 0, lastMaxOffsetCol = 0;
    private boolean autoFollow = true;

    // Text selection state
    private boolean selecting = false;
    private int selAnchorRow = -1, selAnchorCol = -1;
    private int selEndRow = -1, selEndCol = -1;
    private Color selectionColor = new Color(80, 120, 200, 120);
    private Color selectionFgColor = null; // null = use original text color

    // When true, keyboard input (typing) is ignored — terminal is read-only
    private boolean readOnly = false;
    public void setReadOnly(boolean readOnly) { this.readOnly = readOnly; }
    public boolean isReadOnly() { return readOnly; }

    public void setSelectionColor(Color color) { this.selectionColor = color; }
    public void setSelectedTextColor(Color color) { this.selectionFgColor = color; }

    public void clearSelection() {
        selAnchorRow = -1; selAnchorCol = -1;
        selEndRow = -1; selEndCol = -1;
        selecting = false;
        repaint();
    }

    public BoundedRangeModel getVerticalModel()   { return vModel; }
    public BoundedRangeModel getHorizontalModel() { return hModel; }
    public boolean isAutoFollowEnabled()          { return autoFollow; }
    public void setAutoFollowEnabled(boolean on)  { this.autoFollow = on; }

    // Constructor
    public TerminalPanel() { this(24, 80); }
    public TerminalPanel(int rows, int cols) {
        this.viewport = new ViewportManager(rows, cols);
        viewport.addListener(this::onViewportChanged);
        this.lastViewportRows = viewport.getRows(); // or simply: rows
        this.lastViewportCols = viewport.getCols(); // or simply: cols

        this.processor = new ContentProcessor(sparseArray, viewport);
        // Default: TAGS_ONLY
        this.processor.setMarkupMode(ContentProcessor.MarkupMode.TAGS_ONLY);

        setBackground(DEFAULT_BG);
        setFocusable(true);
        addKeyListener(this);
        addComponentListener(this);

        // Key bindings so PageUp/Down/Home/End work reliably
        installKeyBindings();
        addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                requestFocusInWindow();
                if (SwingUtilities.isLeftMouseButton(e)) {
                    selAnchorRow = viewport.getOffsetRow() + e.getY() / lineHeight;
                    selAnchorCol = viewport.getOffsetCol() + e.getX() / charWidth;
                    selEndRow = selAnchorRow;
                    selEndCol = selAnchorCol;
                    selecting = true;
                    repaint();
                }
            }
            @Override public void mouseReleased(MouseEvent e) {
                selecting = false;
            }
        });
        addMouseMotionListener(new MouseMotionAdapter() {
            @Override public void mouseDragged(MouseEvent e) {
                if (selecting) {
                    selEndRow = viewport.getOffsetRow() + e.getY() / lineHeight;
                    selEndCol = viewport.getOffsetCol() + e.getX() / charWidth;
                    repaint();
                }
            }
        });

        contentBuffer.addListener(this::onContentChanged);
        viewport.addListener(this::onViewportChanged);

        updateFontMetrics();
        processor.setBaseFont(DEFAULT_FONT);
        setupCursorBlink();

        // Bind scroll models
        ChangeListener modelListener = (ChangeEvent e) -> {
            if (updatingModels) return;
            updatingFromModel = true;
            try {
                int newRow = vModel.getValue();
                int newCol = hModel.getValue();
                viewport.setOffset(newRow, newCol);
                repaint();
                int maxOffsetRow = Math.max(0, (sparseArray.getMaxRow()) - viewport.getRows() + 1);
                autoFollow = (newRow >= maxOffsetRow);
            } finally {
                updatingFromModel = false;
            }
        };
        vModel.addChangeListener(modelListener);
        hModel.addChangeListener(modelListener);

        updateScrollModels(false);
    }

    // ==== Public API ====
    public void setMarkupMode(ContentProcessor.MarkupMode mode) {
        processor.setMarkupMode(mode);
        // Re-process existing content under the new mode
        onContentChanged();
    }

    public void write(String text) {
        if (text == null || text.isEmpty()) return;
        if (charRenderDelayMs <= 0) {
            contentBuffer.append(text); // immediate, includes tags; processor will ignore tags visually
            return;
        }
        enqueueTokens(text);
    }
    public void writeln(String text) { write(text + "\n"); }

    public CharacterCell getCharAt(int row, int col) { return sparseArray.getCharAt(row, col); }

    public void setCharAt(int row, int col, CharacterCell cell) {
        sparseArray.setCharAt(row, col, cell);
        updateCursorPosition();
        repaint();
    }

    public void clear() {
        contentBuffer.clear();
        sparseArray.clear();
        cursorRow = 0; cursorCol = 0;

        stopTypewriterIfRunning();
        stopCharTimer();
        writeQueue.clear();

        initialSlowRollDone = !slowRollOnInitialRender;
        repaint();
        updateScrollModels(false);
    }

    public void setCursorColor(Color color) { this.cursorColor = color; }

    public void setBlinkCycleTime(int cycleMs) {
        int newCycle = Math.max(0, cycleMs);
        this.blinkCycleMs = newCycle;
        if (newCycle == 0) {
            stopBlinkTimer();
            cursorVisible = true;
            repaint();
            return;
        }
        int half = Math.max(1, newCycle / 2);
        if (blinkTimer == null) {
            blinkTimer = new Timer(half, e -> { cursorVisible = !cursorVisible; repaint(); });
            blinkTimer.setInitialDelay(half);
            blinkTimer.start();
        } else {
            blinkTimer.setDelay(half);
            blinkTimer.setInitialDelay(half);
            if (!blinkTimer.isRunning()) blinkTimer.start();
        }
    }

    public void setCursorChar(String glyph) {
        if (glyph == null || glyph.isEmpty()) cursorGlyphEnabled = false;
        else { cursorGlyph = glyph.substring(0, 1); cursorGlyphEnabled = true; }
        repaint();
    }

    public Point getCursorPosition() { return new Point(cursorCol, cursorRow); }
    public int getCursorRow() { return cursorRow; }
    public int getCursorCol() { return cursorCol; }

    public void setWordWrap(boolean enabled) {
        processor.setWordWrapEnabled(enabled);
        processor.processContent(contentBuffer.getContent());
        clampViewportToContent(false);
        repaint();
        updateScrollModels(false);
    }

    // ==== Internals ====

    private void updateFontMetrics() {
        fontMetrics = getFontMetrics(DEFAULT_FONT);
        charWidth = fontMetrics.charWidth('M');
        lineHeight = fontMetrics.getHeight();
        processor.setBaseFont(DEFAULT_FONT);
    }

    private void setupCursorBlink() {
        // Blink disabled by default; use setBlinkCycleTime to enable
    }
    private void stopBlinkTimer() { if (blinkTimer != null) { blinkTimer.stop(); blinkTimer = null; } }

    private void stopTypewriterIfRunning() {
        if (typewriterTimer != null) { typewriterTimer.stop(); typewriterTimer = null; }
        typewriterActive = false;
    }

    private void maybeStartInitialTypewriter() {
        if (!slowRollOnInitialRender || initialSlowRollDone || typewriterActive) return;
        typewriterActive = true;
        animRow = 0; animCol = 0;
        final int targetRow = cursorRow, targetCol = cursorCol;
        typewriterTimer = new Timer(typewriterDelayMs, e -> {
            if (animRow == targetRow && animCol == targetCol) {
                stopTypewriterIfRunning();
                initialSlowRollDone = true;
                repaint();
                return;
            }
            animCol++;
            if (animCol >= viewport.getCols()) { animCol = 0; animRow++; }
            repaint();
        });
        typewriterTimer.setInitialDelay(typewriterDelayMs);
        typewriterTimer.start();
    }

    private void onContentChanged() {
        Runnable work = () -> {
            processor.processContent(contentBuffer.getContent());
            clampViewportToContent(false);
            updateCursorPosition();
            maybeStartInitialTypewriter();
            repaint();
            updateScrollModels(false);
        };
        if (SwingUtilities.isEventDispatchThread()) work.run();
        else SwingUtilities.invokeLater(work);
    }

    /** Viewport listener now reacts to size changes ONLY; offset-only changes are ignored here. */
    private void onViewportChanged() {
        // Bail out if we re-enter due to offset adjustments during a reflow
        if (inViewportReflow) return;

        Runnable work = () -> {
            int rows = viewport.getRows();
            int cols = viewport.getCols();
            boolean sizeChanged = (rows != lastViewportRows) || (cols != lastViewportCols);
            if (!sizeChanged) return; // offset-only: do nothing

            if (DEBUG) System.out.println("Viewport size changed to " + cols + "x" + rows +
                    " (was " + lastViewportCols + "x" + lastViewportRows + ")");

            inViewportReflow = true;
            try {
                processor.processContent(contentBuffer.getContent());
                clampViewportToContent(true);
                lastViewportRows = rows; lastViewportCols = cols;

                updateCursorPosition(); // may set offset; listener will fire but guard blocks re-entry
                revalidate();
                repaint();
                updateScrollModels(/*sizeChange*/ true);
            } finally {
                inViewportReflow = false;
            }
        };

        if (SwingUtilities.isEventDispatchThread()) work.run();
        else SwingUtilities.invokeLater(work);
    }


    private void clampViewportToContent(boolean stickToBottom) {
        int rows = viewport.getRows(), cols = viewport.getCols();
        if (rows <= 0 || cols <= 0) return;

        int maxRow = sparseArray.getMaxRow();
        int maxCol = sparseArray.getMaxCol();

        int maxOffsetRow = Math.max(0, maxRow - rows + 1);
        int maxOffsetCol = Math.max(0, maxCol - cols + 1);

        int newOffsetRow = viewport.getOffsetRow();
        int newOffsetCol = viewport.getOffsetCol();

        newOffsetRow = (maxRow < rows) ? 0 : Math.min(newOffsetRow, maxOffsetRow);
        newOffsetCol = (maxCol < cols) ? 0 : Math.min(newOffsetCol, maxOffsetCol);

        if (stickToBottom) newOffsetRow = maxOffsetRow;

        if (newOffsetRow != viewport.getOffsetRow() || newOffsetCol != viewport.getOffsetCol()) {
            viewport.setOffset(newOffsetRow, newOffsetCol);
        }
    }

    private void updateCursorPosition() {
        cursorRow = processor.getCursorRow();
        cursorCol = processor.getCursorCol();

        int startRow = viewport.getOffsetRow();
        int startCol = viewport.getOffsetCol();
        int endRow   = startRow + viewport.getRows();
        int endCol   = startCol + viewport.getCols();

        if (cursorRow >= endRow) {
            viewport.setOffset(Math.max(0, cursorRow - viewport.getRows() + 1), viewport.getOffsetCol());
        } else if (cursorRow < startRow) {
            viewport.setOffset(cursorRow, viewport.getOffsetCol());
        }
        if (cursorCol >= endCol) {
            viewport.setOffset(viewport.getOffsetRow(), Math.max(0, cursorCol - viewport.getCols() + 1));
        } else if (cursorCol < startCol) {
            viewport.setOffset(viewport.getOffsetRow(), cursorCol);
        }
    }

    private void updateScrollModels(boolean sizeChange) {
        updatingModels = true;
        try {
            int rows = viewport.getRows(), cols = viewport.getCols();
            int contentRows = sparseArray.getMaxRow() + 1;
            int contentCols = sparseArray.getMaxCol() + 1;

            int maxOffsetRow = Math.max(0, contentRows - rows);
            int maxOffsetCol = Math.max(0, contentCols - cols);

            int currentRowVal = vModel.getValue();
            boolean wasAtBottom = currentRowVal >= lastMaxOffsetRow;

            vModel.setMinimum(0);
            vModel.setMaximum(contentRows);
            vModel.setExtent(rows);
            int newRowVal = clamp(currentRowVal, 0, maxOffsetRow);
            if ((autoFollow && wasAtBottom) || (autoFollow && sizeChange)) {
                newRowVal = maxOffsetRow;
            }
            vModel.setValue(newRowVal);
            lastMaxOffsetRow = maxOffsetRow;

            hModel.setMinimum(0);
            hModel.setMaximum(contentCols);
            hModel.setExtent(cols);
            int newColVal = clamp(hModel.getValue(), 0, maxOffsetCol);
            hModel.setValue(newColVal);
            lastMaxOffsetCol = maxOffsetCol;

            if (!updatingFromModel) {
                viewport.setOffset(vModel.getValue(), hModel.getValue());
                if (wasAtBottom) autoFollow = true;
            }
        } finally {
            updatingModels = false;
        }
    }

    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }

    // ===================== Rendering =====================
    @Override protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2d = (Graphics2D) g.create();
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        renderCharacters(g2d);
        renderSelection(g2d);
        renderCursor(g2d);
        g2d.dispose();
    }

    private void renderCharacters(Graphics2D g) {
        int startRow = viewport.getOffsetRow(), endRow = startRow + viewport.getRows();
        int startCol = viewport.getOffsetCol(), endCol = startCol + viewport.getCols();

        for (int row = startRow; row < endRow; row++) {
            for (int col = startCol; col < endCol; col++) {
                CharacterCell cell = sparseArray.getCharAt(row, col);
                int x = (col - startCol) * charWidth;
                int y = (row - startRow) * lineHeight;

                g.setColor(cell.getBackgroundColor());
                g.fillRect(x, y, charWidth, lineHeight);

                char ch = cell.getCharacter();
                if (ch != ' ' && ch != '\0') {
                    g.setColor(cell.getForegroundColor());
                    g.setFont(cell.getEffectiveFont());
                    FontMetrics fm = g.getFontMetrics();
                    int charY = y + fm.getAscent();
                    g.drawString(String.valueOf(ch), x, charY);

                    if (cell.isUnderline()) {
                        int underlineY = charY + 2;
                        g.drawLine(x, underlineY, x + charWidth, underlineY);
                    }
                }
            }
        }
    }

    private void renderCursor(Graphics2D g) {
        if (!cursorVisible) return;

        int drawRow = typewriterActive ? animRow : cursorRow;
        int drawCol = typewriterActive ? animCol : cursorCol;

        int screenRow = drawRow - viewport.getOffsetRow();
        int screenCol = drawCol - viewport.getOffsetCol();

        if (screenRow >= 0 && screenRow < viewport.getRows() &&
                screenCol >= 0 && screenCol < viewport.getCols()) {
            int x = screenCol * charWidth;
            int y = screenRow * lineHeight;

            if (cursorGlyphEnabled) {
                g.setColor(cursorColor);
                g.setFont(DEFAULT_FONT);
                int charY = y + fontMetrics.getAscent();
                g.drawString(cursorGlyph, x, charY);
            } else {
                g.setColor(cursorColor);
                g.fillRect(x, y, charWidth, lineHeight);
            }
        }
    }

    private void renderSelection(Graphics2D g) {
        if (!hasSelection()) return;
        int r0, c0, r1, c1;
        if (selAnchorRow < selEndRow || (selAnchorRow == selEndRow && selAnchorCol <= selEndCol)) {
            r0 = selAnchorRow; c0 = selAnchorCol; r1 = selEndRow; c1 = selEndCol;
        } else {
            r0 = selEndRow; c0 = selEndCol; r1 = selAnchorRow; c1 = selAnchorCol;
        }
        int startRow = viewport.getOffsetRow(), endRow = startRow + viewport.getRows();
        for (int row = Math.max(r0, startRow); row <= Math.min(r1, endRow - 1); row++) {
            int screenRow = row - startRow;
            int colStart = (row == r0) ? c0 : 0;
            int colEnd = (row == r1) ? c1 : viewport.getCols() - 1;
            int x = (colStart - viewport.getOffsetCol()) * charWidth;
            int w = (colEnd - colStart + 1) * charWidth;
            int y = screenRow * lineHeight;

            // Fill selection background
            g.setColor(selectionColor);
            g.fillRect(x, y, w, lineHeight);

            // Re-render selected text with foreground color
            if (selectionFgColor != null) {
                g.setColor(selectionFgColor);
                for (int col = colStart; col <= colEnd; col++) {
                    CharacterCell cell = sparseArray.getCharAt(row, col);
                    char ch = cell.getCharacter();
                    if (ch != ' ' && ch != '\0') {
                        int cx = (col - viewport.getOffsetCol()) * charWidth;
                        g.setFont(cell.getEffectiveFont());
                        FontMetrics fm = g.getFontMetrics();
                        g.drawString(String.valueOf(ch), cx, y + fm.getAscent());
                    }
                }
            }
        }
    }

    private boolean hasSelection() {
        return selAnchorRow >= 0 && (selAnchorRow != selEndRow || selAnchorCol != selEndCol);
    }

    /**
     * Returns the plain text of the selected region, or empty string if nothing selected.
     */
    public String getSelectedText() {
        if (!hasSelection()) return "";
        int r0, c0, r1, c1;
        if (selAnchorRow < selEndRow || (selAnchorRow == selEndRow && selAnchorCol <= selEndCol)) {
            r0 = selAnchorRow; c0 = selAnchorCol; r1 = selEndRow; c1 = selEndCol;
        } else {
            r0 = selEndRow; c0 = selEndCol; r1 = selAnchorRow; c1 = selAnchorCol;
        }
        return extractText(r0, c0, r1, c1);
    }

    /**
     * Returns all terminal content as plain text.
     */
    public String getPlainText() {
        return extractText(0, 0, sparseArray.getMaxRow(), sparseArray.getMaxCol());
    }

    private String extractText(int r0, int c0, int r1, int c1) {
        StringBuilder sb = new StringBuilder();
        for (int row = r0; row <= r1; row++) {
            int colStart = (row == r0) ? c0 : 0;
            int colEnd = (row == r1) ? c1 : sparseArray.getMaxCol();
            StringBuilder line = new StringBuilder();
            for (int col = colStart; col <= colEnd; col++) {
                char ch = sparseArray.getCharAt(row, col).getCharacter();
                line.append((ch == '\0') ? ' ' : ch);
            }
            // Trim trailing spaces from each line
            String trimmed = line.toString().stripTrailing();
            sb.append(trimmed);
            if (row < r1) sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * Copies the selected text to the system clipboard.
     */
    public void copySelection() {
        String text = getSelectedText();
        if (!text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
        }
    }

    @Override public Dimension getPreferredSize() {
        return new Dimension(viewport.getCols() * charWidth, viewport.getRows() * lineHeight);
    }

    // ===================== Events =====================
    @Override public void componentResized(ComponentEvent e) {
        if (getWidth() > 0 && getHeight() > 0) {
            updateFontMetrics();
            int newCols = Math.max(1, getWidth() / charWidth);
            int newRows = Math.max(1, getHeight() / lineHeight);
            viewport.setSize(newRows, newCols);
        }
    }
    @Override public void componentMoved(ComponentEvent e) {}
    @Override public void componentShown(ComponentEvent e) { requestFocusInWindow(); }
    @Override public void componentHidden(ComponentEvent e) {}

    @Override public void keyTyped(KeyEvent e) {
        if (readOnly) return;
        char ch = e.getKeyChar();
        if (!Character.isISOControl(ch)) contentBuffer.append(ch);
    }
    @Override public void keyPressed(KeyEvent e) {
        if (readOnly) return;
        switch (e.getKeyCode()) {
            case KeyEvent.VK_ENTER:      contentBuffer.append("\n"); break;
            case KeyEvent.VK_BACK_SPACE: contentBuffer.append("\b"); break;
            case KeyEvent.VK_TAB:        contentBuffer.append("\t"); break;
        }
    }
    @Override public void keyReleased(KeyEvent e) {}

    // ==== Key bindings for PageUp/Down/Home/End (already discussed) ====
    private void installKeyBindings() {
        InputMap im = getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW);
        ActionMap am = getActionMap();

        int platformMod = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, platformMod), "term.copy");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP,   0), "term.pageUp");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, 0), "term.pageDown");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_HOME,      0), "term.home");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_END,       0), "term.end");

        am.put("term.copy",    new AbstractAction() { public void actionPerformed(java.awt.event.ActionEvent e){ copySelection(); }});
        am.put("term.pageUp",   new AbstractAction() { public void actionPerformed(java.awt.event.ActionEvent e){ doPageUp(); }});
        am.put("term.pageDown", new AbstractAction() { public void actionPerformed(java.awt.event.ActionEvent e){ doPageDown(); }});
        am.put("term.home",     new AbstractAction() { public void actionPerformed(java.awt.event.ActionEvent e){ doHome(); }});
        am.put("term.end",      new AbstractAction() { public void actionPerformed(java.awt.event.ActionEvent e){ doEnd(); }});
    }
    private void doPageUp() {
        BoundedRangeModel m = vModel;
        int page = Math.max(1, m.getExtent());
        int maxOffset = Math.max(0, m.getMaximum() - m.getExtent());
        int next = Math.max(0, m.getValue() - page);
        m.setValue(next);
        autoFollow = (next >= maxOffset);
    }
    private void doPageDown() {
        BoundedRangeModel m = vModel;
        int page = Math.max(1, m.getExtent());
        int maxOffset = Math.max(0, m.getMaximum() - m.getExtent());
        int next = Math.min(maxOffset, m.getValue() + page);
        m.setValue(next);
        autoFollow = (next >= maxOffset);
    }
    private void doHome() {
        vModel.setValue(0);
        autoFollow = false;
    }
    private void doEnd() {
        int maxOffset = Math.max(0, vModel.getMaximum() - vModel.getExtent());
        vModel.setValue(maxOffset);
        autoFollow = true;
    }

    // ===================== Tokenized programmatic writer =====================
    private void enqueueTokens(String text) {
        Runnable r = () -> {
            tokenizeIntoQueue(text, writeQueue);
            startCharTimer();
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private void startCharTimer() {
        if (charRenderTimer == null) {
            charRenderTimer = new Timer(charRenderDelayMs, e -> {
                // Drain immediate tags; emit one visible char per tick
                while (!writeQueue.isEmpty()) {
                    Token t = writeQueue.peekFirst();
                    if (t.type == Token.Type.TAG) {
                        contentBuffer.append(t.payload); // append full tag now
                        writeQueue.removeFirst();
                        continue; // same tick, apply next item
                    }
                    // TEXT
                    if (t.payload.isEmpty()) { writeQueue.removeFirst(); continue; }
                    char ch = t.payload.charAt(0);
                    t.payload = t.payload.substring(1);
                    contentBuffer.append(ch);
                    break; // one visible char per tick
                }
                if (writeQueue.isEmpty()) stopCharTimer();
            });
            charRenderTimer.setInitialDelay(charRenderDelayMs);
            charRenderTimer.start();
        } else if (!charRenderTimer.isRunning()) {
            charRenderTimer.start();
        }
    }

    private void stopCharTimer() {
        if (charRenderTimer != null) { charRenderTimer.stop(); charRenderTimer = null; }
    }

    // Simple tokenizer: recognizes "{{" -> TEXT("{"), and "{...}" -> TAG; everything else as TEXT
    private static void tokenizeIntoQueue(String s, Deque<Token> out) {
        int i = 0, n = s.length();
        StringBuilder textBuf = new StringBuilder();

        while (i < n) {
            char c = s.charAt(i);
            if (c == '{') {
                // "{{" -> literal '{'
                if (i + 1 < n && s.charAt(i + 1) == '{') {
                    textBuf.append('{');
                    i += 2;
                    continue;
                }
                // try to find closing '}'
                int close = s.indexOf('}', i + 1);
                if (close == -1) {
                    // treat as literal '{'
                    textBuf.append('{');
                    i++;
                    continue;
                }
                // flush pending text
                if (textBuf.length() > 0) {
                    out.addLast(new Token(Token.Type.TEXT, textBuf.toString()));
                    textBuf.setLength(0);
                }
                // enqueue tag verbatim (zero-width)
                out.addLast(new Token(Token.Type.TAG, s.substring(i, close + 1)));
                i = close + 1;
            } else {
                textBuf.append(c);
                i++;
            }
        }
        if (textBuf.length() > 0) out.addLast(new Token(Token.Type.TEXT, textBuf.toString()));
    }
}
