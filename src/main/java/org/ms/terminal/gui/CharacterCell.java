package org.ms.terminal.gui;

import java.awt.*;

// ========== CHARACTER CELL DEFINITION ==========
public class CharacterCell {
    // Local defaults so this class no longer depends on TerminalPanel’s statics
    private static final Font DEFAULT_FONT = new Font("Monospaced", Font.PLAIN, 12);
    private static final Color DEFAULT_FG = new Color(192, 192, 192);
    private static final Color DEFAULT_BG = new Color(34, 34, 33);

    private char character;
    private Color foregroundColor;
    private Color backgroundColor;
    private Font font;
    private boolean bold;
    private boolean italic;
    private boolean underline;
    private boolean blink;

    public CharacterCell() {
        this(' ', DEFAULT_FG, DEFAULT_BG, DEFAULT_FONT, false, false, false, false);
    }
    public CharacterCell(char character, Color fg, Color bg) {
        this(character, fg, bg, DEFAULT_FONT, false, false, false, false);
    }
    public CharacterCell(char character, Color fg, Color bg, Font font,
                         boolean bold, boolean italic, boolean underline, boolean blink) {
        this.character = character;
        this.foregroundColor = fg;
        this.backgroundColor = bg;
        this.font = font;
        this.bold = bold;
        this.italic = italic;
        this.underline = underline;
        this.blink = blink;
    }

    public char getCharacter() { return character; }
    public void setCharacter(char character) { this.character = character; }
    public Color getForegroundColor() { return foregroundColor; }
    public void setForegroundColor(Color color) { this.foregroundColor = color; }
    public Color getBackgroundColor() { return backgroundColor; }
    public void setBackgroundColor(Color color) { this.backgroundColor = color; }
    public Font getFont() { return font; }
    public void setFont(Font font) { this.font = font; }
    public boolean isBold() { return bold; }
    public void setBold(boolean bold) { this.bold = bold; }
    public boolean isItalic() { return italic; }
    public void setItalic(boolean italic) { this.italic = italic; }
    public boolean isUnderline() { return underline; }
    public void setUnderline(boolean underline) { this.underline = underline; }
    public boolean isBlink() { return blink; }
    public void setBlink(boolean blink) { this.blink = blink; }

    public CharacterCell copy() {
        return new CharacterCell(character, foregroundColor, backgroundColor,
                font, bold, italic, underline, blink);
    }
    public Font getEffectiveFont() {
        int style = Font.PLAIN;
        if (bold) style |= Font.BOLD;
        if (italic) style |= Font.ITALIC;
        return new Font(font.getName(), style, font.getSize());
    }
}
