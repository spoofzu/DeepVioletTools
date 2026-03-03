package org.ms.terminal.gui;

import java.awt.Color;
import java.awt.Font;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ContentProcessor {

    private static final Logger logger = LoggerFactory.getLogger("org.ms.terminal.gui.ContentProcessor");

    public enum MarkupMode { TAGS_ONLY, ANSI_ONLY, BOTH }

    private final SparseCharacterArray sparseArray;
    private final ViewportManager viewport;

    private int cursorRow = 0;
    private int cursorCol = 0;
    private CharacterCell currentStyle = new CharacterCell();
    private boolean wordWrapEnabled = true;

    // Base font provided by the panel
    private Font baseFont = new Font("Monospaced", Font.PLAIN, 12);

    // MARKUP MODE: default to TAGS_ONLY per spec
    private MarkupMode markupMode = MarkupMode.TAGS_ONLY;

    // ANSI parsing (used only if mode allows)
    private boolean inEscape = false;
    private boolean inBracket = false;
    private final StringBuilder escapeSequence = new StringBuilder();

    // Tag state stack
    private static final int STACK_LIMIT = 256;
    private final Deque<CharacterCell> styleStack = new ArrayDeque<>(STACK_LIMIT);

    public ContentProcessor(SparseCharacterArray sparseArray, ViewportManager viewport) {
        this.sparseArray = sparseArray;
        this.viewport = viewport;
    }

    // ===== Public API =====
    public void setWordWrapEnabled(boolean enabled) { this.wordWrapEnabled = enabled; }
    public int getCursorRow() { return cursorRow; }
    public int getCursorCol() { return cursorCol; }

    public void setBaseFont(Font f) { if (f != null) this.baseFont = f; }
    public void setMarkupMode(MarkupMode mode) { if (mode != null) this.markupMode = mode; }
    public MarkupMode getMarkupMode() { return markupMode; }

    public void processContent(String content) {
        sparseArray.clear();
        cursorRow = 0;
        cursorCol = 0;
        currentStyle = new CharacterCell();
        currentStyle.setFont(baseFont);

        inEscape = false;
        inBracket = false;
        escapeSequence.setLength(0);
        styleStack.clear();

        if (viewport.getCols() <= 0 || viewport.getRows() <= 0) return;

        if (wordWrapEnabled) processContentWithWordWrap(content);
        else processContentWithCharWrap(content);
    }

    // ===== Passes =====
    private void processContentWithWordWrap(String content) {
        StringBuilder currentWord = new StringBuilder();
        CharacterCell wordStyle = currentStyle.copy();

        for (int i = 0; i < content.length(); i++) {
            char ch = content.charAt(i);

            // TAGS
            if (markupMode != MarkupMode.ANSI_ONLY) {
                int consumed = tryHandleTag(content, i);
                if (consumed > 0) { i += consumed - 1; continue; }
            }

            // ANSI
            if (markupMode != MarkupMode.TAGS_ONLY && handleEscapeSequence(ch)) continue;

            switch (ch) {
                case '\n':
                    placeCurrentWord(currentWord, wordStyle);
                    currentWord.setLength(0);
                    cursorRow++; cursorCol = 0;
                    break;
                case '\r':
                    placeCurrentWord(currentWord, wordStyle);
                    currentWord.setLength(0);
                    cursorCol = 0;
                    break;
                case '\t': {
                    placeCurrentWord(currentWord, wordStyle);
                    currentWord.setLength(0);
                    int tabSize = 8;
                    int newCol = ((cursorCol / tabSize) + 1) * tabSize;
                    if (newCol >= viewport.getCols()) { cursorRow++; cursorCol = 0; }
                    else { cursorCol = newCol; }
                    break;
                }
                case '\b':
                    if (currentWord.length() > 0) currentWord.setLength(currentWord.length() - 1);
                    else if (cursorCol > 0) { cursorCol--; sparseArray.setCharAt(cursorRow, cursorCol, null); }
                    break;
                case ' ':
                    placeCurrentWord(currentWord, wordStyle);
                    currentWord.setLength(0);
                    placeCharacterWithWrap(' ');
                    break;
                default:
                    if (!Character.isISOControl(ch)) {
                        currentWord.append(ch);
                        wordStyle = currentStyle.copy(); // capture style at word start
                    }
                    break;
            }
        }
        placeCurrentWord(currentWord, wordStyle);
    }

    private void processContentWithCharWrap(String content) {
        for (int i = 0; i < content.length(); i++) {
            char ch = content.charAt(i);

            if (markupMode != MarkupMode.ANSI_ONLY) {
                int consumed = tryHandleTag(content, i);
                if (consumed > 0) { i += consumed - 1; continue; }
            }
            if (markupMode != MarkupMode.TAGS_ONLY && handleEscapeSequence(ch)) continue;

            switch (ch) {
                case '\n': cursorRow++; cursorCol = 0; break;
                case '\r': cursorCol = 0; break;
                case '\t': {
                    int tabSize = 8;
                    int newCol = ((cursorCol / tabSize) + 1) * tabSize;
                    if (newCol >= viewport.getCols()) { cursorRow++; cursorCol = 0; }
                    else { cursorCol = newCol; }
                    break;
                }
                case '\b':
                    if (cursorCol > 0) { cursorCol--; sparseArray.setCharAt(cursorRow, cursorCol, null); }
                    break;
                default:
                    if (!Character.isISOControl(ch)) placeCharacterWithWrap(ch);
                    break;
            }
        }
    }

    // ===== Tag parsing =====
    /**
     * Try to handle a tag beginning at index.
     * Returns chars consumed (>0) if handled; 0 if not a tag.
     */
    private int tryHandleTag(String s, int index) {
        if (s.charAt(index) != '{') return 0;

        // Escape for literal '{'
        if (index + 1 < s.length() && s.charAt(index + 1) == '{') {
            placeCharacterWithWrap('{');
            return 2;
        }

        // Find closing brace
        int close = s.indexOf('}', index + 1);
        if (close == -1) {
            // Unterminated: render literal '{'
            placeCharacterWithWrap('{');
            return 1;
        }

        String inner = s.substring(index + 1, close).trim();
        if (inner.isEmpty()) {
            // Empty tag: ignore silently
            return (close - index + 1);
        }

        // Only treat as a tag if it "looks like" one; otherwise render literally.
        if (!isLikelyTag(inner)) {
            // Render literal "{inner}"
            placeCharacterWithWrap('{');
            for (int k = 0; k < inner.length(); k++) placeCharacterWithWrap(inner.charAt(k));
            placeCharacterWithWrap('}');
            return (close - index + 1);
        }

        // Apply known tag forms; unrecognized get a warning but are consumed zero-width.
        if (!applyTag(inner)) {
            warn("Unrecognized tag: {" + inner + "}");
        }
        return (close - index + 1);
    }

    private boolean isLikelyTag(String innerRaw) {
        String s = innerRaw.trim().toLowerCase(Locale.ROOT);
        return s.startsWith("fg:") || s.startsWith("fg=") ||
                s.startsWith("bg:") || s.startsWith("bg=") ||
                s.equals("reset")  || s.startsWith("reset:") ||
                s.equals("push")   || s.equals("pop") ||
                s.startsWith("+")  || s.startsWith("-");
    }

    private boolean applyTag(String innerRaw) {
        String inner = innerRaw.trim();

        // push/pop
        if (equalsIgnoreCase(inner, "push")) {
            if (styleStack.size() >= STACK_LIMIT) {
                warn("Style stack overflow (>" + STACK_LIMIT + "), ignoring {push}");
            } else {
                styleStack.push(currentStyle.copy());
            }
            return true;
        }
        if (equalsIgnoreCase(inner, "pop")) {
            if (styleStack.isEmpty()) {
                warn("Style stack underflow on {pop}");
            } else {
                currentStyle = styleStack.pop();
                currentStyle.setFont(baseFont);
            }
            return true;
        }

        // reset / reset:fg / reset:bg / reset:styles / reset:all
        if (inner.toLowerCase(Locale.ROOT).startsWith("reset")) {
            String[] parts = inner.split(":", 2);
            if (parts.length == 1 || equalsIgnoreCase(parts[1], "all")) {
                currentStyle = new CharacterCell();
                currentStyle.setFont(baseFont);
            } else {
                String channel = parts[1].trim().toLowerCase(Locale.ROOT);
                switch (channel) {
                    case "fg":
                        currentStyle.setForegroundColor(new CharacterCell().getForegroundColor());
                        break;
                    case "bg":
                        currentStyle.setBackgroundColor(new CharacterCell().getBackgroundColor());
                        break;
                    case "styles":
                        currentStyle.setBold(false);
                        currentStyle.setItalic(false);
                        currentStyle.setUnderline(false);
                        currentStyle.setBlink(false);
                        break;
                    default:
                        warn("Unknown reset channel: " + channel);
                        // consume anyway
                }
            }
            return true;
        }

        // style +/- : +bold, -underline, etc.
        if (inner.startsWith("+") || inner.startsWith("-")) {
            boolean on = inner.charAt(0) == '+';
            String key = inner.substring(1).trim().toLowerCase(Locale.ROOT);
            switch (key) {
                case "bold":      currentStyle.setBold(on); break;
                case "italic":    currentStyle.setItalic(on); break;
                case "underline": currentStyle.setUnderline(on); break;
                case "blink":     currentStyle.setBlink(on); break;
                default:
                    warn("Unknown style key: " + key);
            }
            return true;
        }

        // fg/bg with ":" or "="
        int sep = inner.indexOf(':');
        if (sep < 0) sep = inner.indexOf('=');
        if (sep > 0) {
            String key = inner.substring(0, sep).trim().toLowerCase(Locale.ROOT);
            String val = inner.substring(sep + 1).trim();
            switch (key) {
                case "fg": {
                    Color c = parseColor(val);
                    if (c != null) currentStyle.setForegroundColor(c);
                    else warn("Bad color for fg: " + val);
                    return true;
                }
                case "bg": {
                    Color c = parseColor(val);
                    if (c != null) currentStyle.setBackgroundColor(c);
                    else warn("Bad color for bg: " + val);
                    return true;
                }
                default:
                    warn("Unknown tag key: " + key);
                    return true; // consume anyway
            }
        }

        // Not recognized
        return false;
    }

    private static boolean equalsIgnoreCase(String a, String b) {
        return a.equalsIgnoreCase(b);
    }

    // ===== Color parsing =====
    private Color parseColor(String v) {
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.startsWith("#")) {
            try {
                if (s.length() == 4) {
                    int r = Integer.parseInt(s.substring(1, 2), 16);
                    int g = Integer.parseInt(s.substring(2, 3), 16);
                    int b = Integer.parseInt(s.substring(3, 4), 16);
                    return new Color(r * 17, g * 17, b * 17);
                } else if (s.length() == 7) {
                    int r = Integer.parseInt(s.substring(1, 3), 16);
                    int g = Integer.parseInt(s.substring(3, 5), 16);
                    int b = Integer.parseInt(s.substring(5, 7), 16);
                    return new Color(r, g, b);
                } else {
                    warn("Hex color must be #rgb or #rrggbb: " + s);
                    return null;
                }
            } catch (NumberFormatException nfe) {
                warn("Bad hex color: " + s);
                return null;
            }
        }

        // Aliases
        s = s.replace("grey", "gray");
        if (s.startsWith("light-")) s = "bright-" + s.substring(6);

        switch (s) {
            // standard
            case "black":   return ANSI_STD[0];
            case "red":     return ANSI_STD[1];
            case "green":   return ANSI_STD[2];
            case "yellow":  return ANSI_STD[3];
            case "blue":    return ANSI_STD[4];
            case "magenta": return ANSI_STD[5];
            case "cyan":    return ANSI_STD[6];
            case "white":   return ANSI_STD[7];
            // bright
            case "bright-black":
            case "gray":
            case "grey":    return ANSI_BRIGHT[0];
            case "bright-red":     return ANSI_BRIGHT[1];
            case "bright-green":   return ANSI_BRIGHT[2];
            case "bright-yellow":  return ANSI_BRIGHT[3];
            case "bright-blue":    return ANSI_BRIGHT[4];
            case "bright-magenta": return ANSI_BRIGHT[5];
            case "bright-cyan":    return ANSI_BRIGHT[6];
            case "bright-white":   return ANSI_BRIGHT[7];
        }
        return null;
    }

    // ===== ANSI (optional) =====
    private boolean handleEscapeSequence(char ch) {
        if (ch == '\033') { inEscape = true; escapeSequence.setLength(0); return true; }
        if (inEscape) {
            escapeSequence.append(ch);
            if (ch == '[') { inBracket = true; return true; }
            else if (inBracket && (ch == 'm' || ch == 'H' || ch == 'J' || ch == 'K')) {
                processAnsiSequence(escapeSequence.toString());
                inEscape = false; inBracket = false; return true;
            } else if (!Character.isDigit(ch) && ch != ';' && ch != '[') {
                inEscape = false; inBracket = false; return true;
            }
            return true;
        }
        return false;
    }

    private void processAnsiSequence(String sequence) {
        if (sequence.endsWith("m")) {
            String codes = sequence.substring(1, sequence.length() - 1);
            if (codes.isEmpty()) codes = "0";
            for (String code : codes.split(";")) {
                try { applyAnsiCode(Integer.parseInt(code.trim())); }
                catch (NumberFormatException ignored) {}
            }
        }
    }

    private void applyAnsiCode(int code) {
        switch (code) {
            case 0:
                currentStyle = new CharacterCell();
                currentStyle.setFont(baseFont);
                break;
            case 1: currentStyle.setBold(true); break;
            case 3: currentStyle.setItalic(true); break;
            case 4: currentStyle.setUnderline(true); break;
            case 5: currentStyle.setBlink(true); break;
            case 22: currentStyle.setBold(false); break;
            case 23: currentStyle.setItalic(false); break;
            case 24: currentStyle.setUnderline(false); break;
            case 25: currentStyle.setBlink(false); break;
            default:
                if (code >= 30 && code <= 37) currentStyle.setForegroundColor(ANSI_STD[code - 30]);
                else if (code >= 90 && code <= 97) currentStyle.setForegroundColor(ANSI_BRIGHT[code - 90]);
                else if (code >= 40 && code <= 47) currentStyle.setBackgroundColor(ANSI_STD[code - 40]);
                else if (code >= 100 && code <= 107) currentStyle.setBackgroundColor(ANSI_BRIGHT[code - 100]);
                break;
        }
    }

    // ===== Placement =====
    private void placeCurrentWord(StringBuilder word, CharacterCell style) {
        if (word.length() == 0) return;
        int viewportCols = viewport.getCols();
        if (viewportCols <= 0) return;

        if (cursorCol + word.length() > viewportCols && cursorCol > 0) {
            cursorRow++; cursorCol = 0;
        }
        for (int i = 0; i < word.length(); i++) {
            if (cursorRow < 0 || cursorCol < 0) {
                cursorRow = Math.max(0, cursorRow); cursorCol = Math.max(0, cursorCol);
            }
            CharacterCell cell = style.copy();
            cell.setCharacter(word.charAt(i));
            sparseArray.setCharAt(cursorRow, cursorCol, cell);
            cursorCol++;
            if (cursorCol >= viewportCols) { cursorRow++; cursorCol = 0; }
        }
    }

    private void placeCharacterWithWrap(char ch) {
        int viewportCols = viewport.getCols();
        if (viewportCols <= 0) return;
        if (cursorCol >= viewportCols) { cursorRow++; cursorCol = 0; }
        if (cursorRow < 0 || cursorCol < 0) {
            cursorRow = Math.max(0, cursorRow); cursorCol = Math.max(0, cursorCol);
        }

        CharacterCell cell = currentStyle.copy();
        cell.setCharacter(ch);
        sparseArray.setCharAt(cursorRow, cursorCol, cell);
        cursorCol++;
    }

    private static void warn(String msg) {
        logger.debug("[Tags] {}", msg);
    }

    // ANSI color palettes
    private static final Color[] ANSI_STD = {
            Color.BLACK,
            new Color(170, 0, 0),
            new Color(0, 170, 0),
            new Color(170, 170, 0),
            new Color(0, 0, 170),
            new Color(170, 0, 170),
            new Color(0, 170, 170),
            new Color(170, 170, 170)
    };
    private static final Color[] ANSI_BRIGHT = {
            new Color(85, 85, 85),
            new Color(255, 85, 85),
            new Color(85, 255, 85),
            new Color(255, 255, 85),
            new Color(85, 85, 255),
            new Color(255, 85, 255),
            new Color(85, 255, 255),
            new Color(255, 255, 255)
    };
}
