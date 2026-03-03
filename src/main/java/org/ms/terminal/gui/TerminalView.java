package org.ms.terminal.gui;

import java.awt.*;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class TerminalView extends JPanel {

    private final TerminalPanel terminal;
    private final JScrollBar vbar = new JScrollBar(JScrollBar.VERTICAL);
    private final JScrollBar hbar = new JScrollBar(JScrollBar.HORIZONTAL);

    // Rows scrolled per mouse wheel notch (tweak as desired)
    private int rowsPerWheel = 3;

    public TerminalView() {
        this(new TerminalPanel());
    }

    public TerminalView(TerminalPanel terminal) {
        super(new BorderLayout());
        this.terminal = terminal;

        // Bind bars to the panel’s models (no extra logic needed)
        vbar.setModel(terminal.getVerticalModel());
        hbar.setModel(terminal.getHorizontalModel());

        // Layout: terminal center, bars on right/bottom
        add(terminal, BorderLayout.CENTER);
        add(vbar, BorderLayout.EAST);
        add(hbar, BorderLayout.SOUTH);

        // Show/hide horizontal bar automatically (wrap usually collapses its range)
        ChangeListener hVis = (ChangeEvent e) -> {
            BoundedRangeModel m = hbar.getModel();
            boolean needed = (m.getMaximum() - m.getExtent()) > 0;
            hbar.setVisible(needed);
            revalidate();
        };
        hbar.getModel().addChangeListener(hVis);
        hVis.stateChanged(null); // initialize

        // Mouse wheel scroll (vertical)
        terminal.addMouseWheelListener(new MouseWheelListener() {
            @Override public void mouseWheelMoved(MouseWheelEvent e) {
                BoundedRangeModel m = vbar.getModel();
                int maxOffset = Math.max(0, m.getMaximum() - m.getExtent());
                int delta = e.getWheelRotation() * rowsPerWheel;
                int next = clamp(m.getValue() + delta, 0, maxOffset);
                m.setValue(next);
            }
        });
    }

    public TerminalPanel getTerminal() { return terminal; }

    /** How many rows to move per mouse wheel notch. */
    public void setRowsPerWheel(int rows) { this.rowsPerWheel = Math.max(1, rows); }

    private static int clamp(int v, int lo, int hi) { return Math.max(lo, Math.min(hi, v)); }
}
