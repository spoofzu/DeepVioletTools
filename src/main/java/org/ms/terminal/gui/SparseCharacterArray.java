package org.ms.terminal.gui;

import java.util.HashMap;
import java.util.Map;

public class SparseCharacterArray {
    private final Map<Long, CharacterCell> cells = new HashMap<>();
    private int maxRow = 0;
    private int maxCol = 0;

    private long getKey(int row, int col) {
        return ((long) row << 32) | (col & 0xFFFFFFFFL);
    }
    private int getRowFromKey(long key) { return (int) (key >>> 32); }
    private int getColFromKey(long key) { return (int) (key & 0xFFFFFFFFL); }

    public CharacterCell getCharAt(int row, int col) {
        CharacterCell cell = cells.get(getKey(row, col));
        return cell != null ? cell : new CharacterCell();
    }

    public void setCharAt(int row, int col, CharacterCell cell) {
        if (cell == null) {
            cells.remove(getKey(row, col));
        } else {
            cells.put(getKey(row, col), cell.copy());
            maxRow = Math.max(maxRow, row);
            maxCol = Math.max(maxCol, col);
        }
    }

    public void clearRegion(int startRow, int startCol, int endRow, int endCol) {
        for (int r = startRow; r <= endRow; r++) {
            for (int c = startCol; c <= endCol; c++) {
                cells.remove(getKey(r, c));
            }
        }
    }

    public void shiftUp(int startRow, int lines) {
        Map<Long, CharacterCell> newCells = new HashMap<>();
        cells.forEach((key, cell) -> {
            int row = getRowFromKey(key);
            int col = getColFromKey(key);
            if (row >= startRow + lines) {
                newCells.put(getKey(row - lines, col), cell);
            }
        });
        cells.clear();
        cells.putAll(newCells);
        // Recompute maxes (cheap enough given sparse nature)
        maxRow = 0; maxCol = 0;
        for (Map.Entry<Long, CharacterCell> e : cells.entrySet()) {
            int r = getRowFromKey(e.getKey());
            int c = getColFromKey(e.getKey());
            if (r > maxRow) maxRow = r;
            if (c > maxCol) maxCol = c;
        }
    }

    public int getMaxRow() { return maxRow; }
    public int getMaxCol() { return maxCol; }
    public void clear() { cells.clear(); maxRow = 0; maxCol = 0; }
}
