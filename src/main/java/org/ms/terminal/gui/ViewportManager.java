package org.ms.terminal.gui;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ViewportManager {
    private int rows;
    private int cols;
    private int offsetRow = 0;
    private int offsetCol = 0;

    private final List<ViewportListener> listeners = new CopyOnWriteArrayList<>();

    public ViewportManager(int rows, int cols) {
        this.rows = Math.max(1, rows);
        this.cols = Math.max(1, cols);
    }

    public int getRows() { return rows; }
    public int getCols() { return cols; }
    public int getOffsetRow() { return offsetRow; }
    public int getOffsetCol() { return offsetCol; }

    public void setSize(int rows, int cols) {
        int newRows = Math.max(1, rows);
        int newCols = Math.max(1, cols);
        if (this.rows == newRows && this.cols == newCols) return;
        this.rows = newRows;
        this.cols = newCols;
        notifyListeners();
    }

    public void setOffset(int row, int col) {
        int nr = Math.max(0, row);
        int nc = Math.max(0, col);
        if (nr == this.offsetRow && nc == this.offsetCol) return;
        this.offsetRow = nr;
        this.offsetCol = nc;
        notifyListeners();
    }

    public void addListener(ViewportListener l) { listeners.add(l); }

    private void notifyListeners() { listeners.forEach(ViewportListener::onViewportChanged); }
}
