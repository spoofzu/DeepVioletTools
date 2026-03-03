package com.mps.deepviolettools.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

import javax.swing.JViewport;

/**
 * A {@link FlowLayout} subclass that computes the correct preferred height
 * based on the container's current width, enabling proper wrapping inside
 * a {@link javax.swing.JScrollPane}. When the container is inside a
 * {@code JScrollPane}, the viewport width is used so cards wrap at the
 * visible edge and re-wrap on resize.
 */
public class WrapLayout extends FlowLayout {

    public WrapLayout() {
        super();
    }

    public WrapLayout(int align) {
        super(align);
    }

    public WrapLayout(int align, int hgap, int vgap) {
        super(align, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return computeSize(target);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        Dimension d = computeSize(target);
        d.width = 0;
        return d;
    }

    private Dimension computeSize(Container target) {
        synchronized (target.getTreeLock()) {
            // Use viewport width when inside a JScrollPane so wrapping
            // follows the visible area rather than the panel's own size.
            int targetWidth = target.getSize().width;
            if (target.getParent() instanceof JViewport) {
                targetWidth = target.getParent().getWidth();
            }
            if (targetWidth <= 0) {
                targetWidth = Integer.MAX_VALUE;
            }

            Insets insets = target.getInsets();
            int maxWidth = targetWidth - insets.left - insets.right;
            int hgap = getHgap();
            int vgap = getVgap();

            int x = 0;
            int y = insets.top + vgap;
            int rowHeight = 0;

            for (int i = 0; i < target.getComponentCount(); i++) {
                Component c = target.getComponent(i);
                if (!c.isVisible()) continue;

                Dimension d = c.getPreferredSize();
                if (x > 0 && x + d.width > maxWidth) {
                    y += rowHeight + vgap;
                    x = 0;
                    rowHeight = 0;
                }
                x += d.width + hgap;
                rowHeight = Math.max(rowHeight, d.height);
            }
            y += rowHeight + vgap + insets.bottom;

            return new Dimension(targetWidth, y);
        }
    }
}
