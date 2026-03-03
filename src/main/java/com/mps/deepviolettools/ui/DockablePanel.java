package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

/**
 * Wrapper panel with a side grip handle that allows docking the wrapped
 * content component to LEFT, TOP, or RIGHT within its parent container.
 * Fires a {@code "dockPosition"} property change when the user completes
 * a dock drag.
 */
public class DockablePanel extends JPanel {

	/** Dock positions supported by this panel. */
	public enum DockPosition {
		LEFT, TOP, RIGHT
	}

	private static final int GRIP_WIDTH = 16;

	private final JComponent content;
	private final JPanel gripPanel;
	private DockPosition currentPosition = DockPosition.LEFT;

	// Drag state
	private boolean dragging;
	private Point dragStart;
	private DockPosition dropTarget;

	// Drop zone overlay painted on the ancestor scan tab panel
	private JPanel dropOverlay;

	public DockablePanel(JComponent content, String title) {
		super(new BorderLayout());
		this.content = content;

		gripPanel = new JPanel() {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				paintGripDots(g, this);
			}
		};
		gripPanel.setOpaque(false);
		gripPanel.setPreferredSize(new Dimension(GRIP_WIDTH, 0));
		gripPanel.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));

		MouseAdapter dragHandler = new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (SwingUtilities.isLeftMouseButton(e)) {
					dragging = true;
					dragStart = e.getLocationOnScreen();
					dropTarget = null;
					showDropOverlay();
				}
			}

			@Override
			public void mouseDragged(MouseEvent e) {
				if (!dragging) return;
				updateDropTarget(e.getLocationOnScreen());
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (!dragging) return;
				dragging = false;
				hideDropOverlay();
				if (dropTarget != null && dropTarget != currentPosition) {
					DockPosition old = currentPosition;
					currentPosition = dropTarget;
					firePropertyChange("dockPosition", old.name(), currentPosition.name());
				}
				dropTarget = null;
			}
		};
		gripPanel.addMouseListener(dragHandler);
		gripPanel.addMouseMotionListener(dragHandler);

		add(gripPanel, BorderLayout.WEST);
		add(content, BorderLayout.CENTER);
	}

	public DockPosition getDockPosition() {
		return currentPosition;
	}

	public void setDockPosition(DockPosition pos) {
		this.currentPosition = pos;
	}

	public JComponent getContent() {
		return content;
	}

	/** Paint subtle vertical grip dots matching toolbar and target button grips. */
	private void paintGripDots(Graphics g, JPanel grip) {
		Graphics2D g2 = (Graphics2D) g.create();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);
		Color fg = grip.getForeground();
		g2.setColor(new Color(fg.getRed(), fg.getGreen(), fg.getBlue(), 80));
		int x = 4;
		int yStart = 5;
		int yEnd = grip.getHeight() - 5;
		for (int y = yStart; y < yEnd; y += 3) {
			g2.fillRect(x, y, 2, 1);
			g2.fillRect(x + 4, y, 2, 1);
		}
		g2.dispose();
	}

	/**
	 * Show translucent drop zone overlays on the scan tab panel.
	 * Uses a glass pane approach by layering a transparent panel.
	 */
	private void showDropOverlay() {
		JPanel scanTab = findScanTabPanel();
		if (scanTab == null) return;

		dropOverlay = new JPanel(null) {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				paintDropZones(g, this);
			}
		};
		dropOverlay.setOpaque(false);
		dropOverlay.setBounds(0, 0, scanTab.getWidth(), scanTab.getHeight());

		// Use the layered pane of the root pane to overlay
		javax.swing.JRootPane rootPane = SwingUtilities.getRootPane(this);
		if (rootPane != null) {
			javax.swing.JLayeredPane layered = rootPane.getLayeredPane();
			Point scanTabLoc = SwingUtilities.convertPoint(scanTab, 0, 0, layered);
			dropOverlay.setBounds(scanTabLoc.x, scanTabLoc.y,
					scanTab.getWidth(), scanTab.getHeight());
			layered.add(dropOverlay, javax.swing.JLayeredPane.DRAG_LAYER);
			layered.repaint();
		}
	}

	private void hideDropOverlay() {
		if (dropOverlay != null) {
			java.awt.Container parent = dropOverlay.getParent();
			if (parent != null) {
				parent.remove(dropOverlay);
				parent.repaint();
			}
			dropOverlay = null;
		}
	}

	/** Paint left/top/right drop zone indicators. */
	private void paintDropZones(Graphics g, JPanel overlay) {
		int w = overlay.getWidth();
		int h = overlay.getHeight();
		int zoneW = w / 5;
		int zoneH = h / 5;

		Graphics2D g2 = (Graphics2D) g.create();

		Color active = new Color(33, 150, 243, 80);
		Color inactive = new Color(33, 150, 243, 30);
		Color defaultActive = new Color(76, 175, 80, 80);
		Color defaultInactive = new Color(76, 175, 80, 30);

		// Left zone (full height, left strip)
		g2.setColor((dropTarget == DockPosition.LEFT) ? defaultActive : defaultInactive);
		g2.fillRect(0, 0, zoneW, h);

		// Top zone (full width minus side strips, top strip)
		g2.setColor((dropTarget == DockPosition.TOP) ? active : inactive);
		g2.fillRect(zoneW, 0, w - 2 * zoneW, zoneH);

		// Right zone (full height, right strip)
		g2.setColor((dropTarget == DockPosition.RIGHT) ? active : inactive);
		g2.fillRect(w - zoneW, 0, zoneW, h);

		// Draw zone labels
		g2.setColor(new Color(255, 255, 255, 160));
		g2.setFont(g2.getFont().deriveFont(12f));
		java.awt.FontMetrics fm = g2.getFontMetrics();

		String leftLabel = "\u25C0 Left (Default)";
		g2.drawString(leftLabel, (zoneW - fm.stringWidth(leftLabel)) / 2,
				h / 2 + fm.getAscent() / 2);

		String topLabel = "\u25B2 Top";
		int topCenterX = zoneW + (w - 2 * zoneW) / 2;
		g2.drawString(topLabel, topCenterX - fm.stringWidth(topLabel) / 2,
				zoneH / 2 + fm.getAscent() / 2);

		String rightLabel = "Right \u25B6";
		g2.drawString(rightLabel, w - zoneW + (zoneW - fm.stringWidth(rightLabel)) / 2,
				h / 2 + fm.getAscent() / 2);

		g2.dispose();
	}

	/** Determine which drop zone the cursor is over. */
	private void updateDropTarget(Point screenPoint) {
		JPanel scanTab = findScanTabPanel();
		if (scanTab == null) return;

		Point local = new Point(screenPoint);
		SwingUtilities.convertPointFromScreen(local, scanTab);

		int w = scanTab.getWidth();
		int h = scanTab.getHeight();
		int zoneW = w / 5;
		int zoneH = h / 5;

		DockPosition newTarget = null;
		if (local.x < zoneW) {
			newTarget = DockPosition.LEFT;
		} else if (local.x > w - zoneW) {
			newTarget = DockPosition.RIGHT;
		} else if (local.y < zoneH) {
			newTarget = DockPosition.TOP;
		}

		if (newTarget != dropTarget) {
			dropTarget = newTarget;
			if (dropOverlay != null) {
				dropOverlay.repaint();
			}
		}
	}

	/** Walk up the hierarchy to find the scan tab JPanel (the scan tab root). */
	private JPanel findScanTabPanel() {
		Component c = getParent();
		while (c != null) {
			if (c instanceof JPanel) {
				// The scan tab panel is the one directly in a JTabbedPane
				Component grandparent = c.getParent();
				if (grandparent instanceof javax.swing.JTabbedPane) {
					return (JPanel) c;
				}
			}
			c = c.getParent();
		}
		// Fallback: return the highest JPanel ancestor below the frame
		c = getParent();
		JPanel last = null;
		while (c != null) {
			if (c instanceof JPanel) last = (JPanel) c;
			if (c instanceof javax.swing.JFrame) break;
			c = c.getParent();
		}
		return last;
	}
}
