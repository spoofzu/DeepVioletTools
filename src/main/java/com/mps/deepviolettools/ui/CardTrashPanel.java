package com.mps.deepviolettools.ui;

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.BasicStroke;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.TransferHandler;

import com.mps.deepviolettools.model.CardLayout;
import com.mps.deepviolettools.model.CardMetaElement;
import com.mps.deepviolettools.model.CardSize;
import com.mps.deepviolettools.model.CardSlotConfig;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * Right-column panel for the card layout editor containing grid dimension
 * spinners (Cols, Rows), a reset button, and a trash drop target for
 * removing elements.
 */
public class CardTrashPanel extends JPanel {

	private final JSpinner spinCols;
	private final JSpinner spinRows;
	private final JButton btnSmall;
	private final JButton btnMedium;
	private final JButton btnLarge;
	private final TrashDropTarget trashTarget;
	private final ResetIcon resetIcon;
	private CardLayout cardLayout;
	private CardSize cardSize;
	private Runnable onLayoutChanged;
	private Runnable onResetClicked;
	private Runnable onCardSizeChanged;

	public CardTrashPanel(FontPreferences prefs) {
		this.cardLayout = prefs.getCardLayout();
		this.cardSize = prefs.getCardSize();

		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		setPreferredSize(new Dimension(80, 320));
		setMinimumSize(new Dimension(70, 180));

		// Cols spinner
		JLabel lblCols = new JLabel("Cols:");
		lblCols.setAlignmentX(CENTER_ALIGNMENT);
		spinCols = new JSpinner(new SpinnerNumberModel(
				cardLayout.getCols(), CardLayout.MIN_COLS, CardLayout.MAX_COLS, 1));
		spinCols.setMaximumSize(new Dimension(60, 26));
		spinCols.setAlignmentX(CENTER_ALIGNMENT);

		// Rows spinner
		JLabel lblRows = new JLabel("Rows:");
		lblRows.setAlignmentX(CENTER_ALIGNMENT);
		spinRows = new JSpinner(new SpinnerNumberModel(
				cardLayout.getRows(), CardLayout.MIN_ROWS, CardLayout.MAX_ROWS, 1));
		spinRows.setMaximumSize(new Dimension(60, 26));
		spinRows.setAlignmentX(CENTER_ALIGNMENT);

		// Card size buttons
		JLabel lblCardSz = new JLabel("Card Sz:");
		lblCardSz.setAlignmentX(CENTER_ALIGNMENT);

		btnSmall = new JButton("S");
		btnMedium = new JButton("M");
		btnLarge = new JButton("L");
		Dimension btnDim = new Dimension(22, 22);
		for (JButton b : new JButton[]{btnSmall, btnMedium, btnLarge}) {
			b.setPreferredSize(btnDim);
			b.setMinimumSize(btnDim);
			b.setMaximumSize(btnDim);
			b.setMargin(new java.awt.Insets(0, 0, 0, 0));
			b.setFont(b.getFont().deriveFont(java.awt.Font.BOLD, 10f));
			b.setFocusPainted(false);
		}
		JPanel sizeRow = new JPanel();
		sizeRow.setLayout(new BoxLayout(sizeRow, BoxLayout.X_AXIS));
		sizeRow.setAlignmentX(CENTER_ALIGNMENT);
		sizeRow.setMaximumSize(new Dimension(72, 24));
		sizeRow.add(btnSmall);
		sizeRow.add(Box.createHorizontalStrut(2));
		sizeRow.add(btnMedium);
		sizeRow.add(Box.createHorizontalStrut(2));
		sizeRow.add(btnLarge);
		updateSizeButtonStates();

		btnSmall.addActionListener(e -> selectCardSize(CardSize.SMALL));
		btnMedium.addActionListener(e -> selectCardSize(CardSize.MEDIUM));
		btnLarge.addActionListener(e -> selectCardSize(CardSize.LARGE));

		// Reset icon
		resetIcon = new ResetIcon();
		resetIcon.setAlignmentX(CENTER_ALIGNMENT);

		add(Box.createVerticalStrut(8));
		add(lblCols);
		add(Box.createVerticalStrut(2));
		add(spinCols);
		add(Box.createVerticalStrut(10));
		add(lblRows);
		add(Box.createVerticalStrut(2));
		add(spinRows);
		add(Box.createVerticalStrut(10));
		add(lblCardSz);
		add(Box.createVerticalStrut(2));
		add(sizeRow);
		add(Box.createVerticalStrut(12));
		add(resetIcon);
		add(Box.createVerticalStrut(12));

		// Trash drop target
		trashTarget = new TrashDropTarget();
		trashTarget.setAlignmentX(CENTER_ALIGNMENT);
		add(trashTarget);
		add(Box.createVerticalGlue());

		// Spinner listeners
		spinCols.addChangeListener(e -> {
			int newCols = (Integer) spinCols.getValue();
			cardLayout.resizeGrid(newCols, cardLayout.getRows());
			fireLayoutChanged();
		});
		spinRows.addChangeListener(e -> {
			int newRows = (Integer) spinRows.getValue();
			cardLayout.resizeGrid(cardLayout.getCols(), newRows);
			fireLayoutChanged();
		});
	}

	public CardLayout cardLayout() { return cardLayout; }

	public void setCardLayout(CardLayout layout) {
		this.cardLayout = layout;
		spinCols.setValue(layout.getCols());
		spinRows.setValue(layout.getRows());
	}

	public void setOnLayoutChanged(Runnable callback) {
		this.onLayoutChanged = callback;
	}

	public void setOnResetClicked(Runnable callback) {
		this.onResetClicked = callback;
	}

	public void setOnCardSizeChanged(Runnable callback) {
		this.onCardSizeChanged = callback;
	}

	public CardSize getCardSize() { return cardSize; }

	private void selectCardSize(CardSize size) {
		this.cardSize = size;
		updateSizeButtonStates();
		if (onCardSizeChanged != null) {
			onCardSizeChanged.run();
		}
	}

	private void updateSizeButtonStates() {
		btnSmall.setEnabled(cardSize != CardSize.SMALL);
		btnMedium.setEnabled(cardSize != CardSize.MEDIUM);
		btnLarge.setEnabled(cardSize != CardSize.LARGE);
	}

	private void fireLayoutChanged() {
		if (onLayoutChanged != null) {
			onLayoutChanged.run();
		}
	}

	/**
	 * Circular arrow reset icon. Clicking restores the default layout.
	 */
	private class ResetIcon extends JPanel {
		private boolean hovered;

		ResetIcon() {
			setPreferredSize(new Dimension(40, 40));
			setMaximumSize(new Dimension(40, 40));
			setMinimumSize(new Dimension(36, 36));
			setOpaque(false);
			setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
			setToolTipText("Reset to default layout");

			addMouseListener(new MouseAdapter() {
				@Override
				public void mouseEntered(MouseEvent e) {
					hovered = true;
					repaint();
				}

				@Override
				public void mouseExited(MouseEvent e) {
					hovered = false;
					repaint();
				}

				@Override
				public void mouseClicked(MouseEvent e) {
					if (onResetClicked != null) {
						onResetClicked.run();
					}
				}
			});
		}

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2 = (Graphics2D) g;
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);

			int w = getWidth();
			int h = getHeight();
			int cx = w / 2;
			int cy = h / 2;
			int radius = Math.min(w, h) / 2 - 6;

			Color arrowColor = hovered
					? new Color(100, 160, 220)
					: new Color(128, 128, 128);
			g2.setColor(arrowColor);
			g2.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

			// Draw arc (270 degrees, starting from top)
			int arcX = cx - radius;
			int arcY = cy - radius;
			int arcD = radius * 2;
			g2.drawArc(arcX, arcY, arcD, arcD, 60, 270);

			// Arrowhead at the end of the arc (pointing clockwise at ~330 degrees = top-right)
			double endAngle = Math.toRadians(60); // arc starts at 60 deg
			int tipX = cx + (int) (radius * Math.cos(endAngle));
			int tipY = cy - (int) (radius * Math.sin(endAngle));

			int arrowLen = 6;
			int[] xPts = {
				tipX,
				tipX - arrowLen,
				tipX + arrowLen / 2
			};
			int[] yPts = {
				tipY,
				tipY + arrowLen + 2,
				tipY + arrowLen + 2
			};
			g2.fillPolygon(xPts, yPts, 3);
		}
	}

	/**
	 * Custom-painted trash can drop target.
	 */
	private class TrashDropTarget extends JPanel {
		private boolean dragOver;

		TrashDropTarget() {
			setPreferredSize(new Dimension(60, 60));
			setMaximumSize(new Dimension(60, 60));
			setMinimumSize(new Dimension(50, 50));
			setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

			setTransferHandler(new TransferHandler() {
				@Override
				public boolean canImport(TransferSupport support) {
					boolean ok = support.isDataFlavorSupported(CardMetaTransferable.FLAVOR);
					if (ok && support.isDrop() && !dragOver) {
						dragOver = true;
						repaint();
					}
					return ok;
				}

				@Override
				public boolean importData(TransferSupport support) {
					dragOver = false;
					if (!support.isDataFlavorSupported(CardMetaTransferable.FLAVOR)) {
						return false;
					}
					try {
						Transferable t = support.getTransferable();
						CardMetaElement elem = (CardMetaElement) t.getTransferData(
								CardMetaTransferable.FLAVOR);
						CardSlotConfig config = cardLayout.getConfig(elem);
						if (config != null && config.isVisible()) {
							cardLayout.setConfig(config.withVisible(false));
							fireLayoutChanged();
						}
						repaint();
						return true;
					} catch (UnsupportedFlavorException | IOException e) {
						return false;
					}
				}
			});
		}

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2 = (Graphics2D) g;
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);

			int w = getWidth();
			int h = getHeight();
			int inset = 6;

			// Background when dragging over
			if (dragOver) {
				g2.setColor(new Color(244, 67, 54, 40));
				g2.fillRoundRect(0, 0, w, h, 8, 8);
			}

			// Paint simple trash can icon
			Color trashColor = dragOver
					? new Color(244, 67, 54)
					: new Color(128, 128, 128);
			g2.setColor(trashColor);

			int bx = w / 2 - 14;
			int by = inset + 8;
			int bw = 28;
			int bh = 30;

			// Lid
			g2.fillRect(bx - 2, by - 4, bw + 4, 3);
			g2.fillRect(bx + 8, by - 8, 12, 5);

			// Body
			g2.drawRect(bx, by, bw, bh);

			// Slats
			g2.drawLine(bx + 9, by + 4, bx + 9, by + bh - 4);
			g2.drawLine(bx + 14, by + 4, bx + 14, by + bh - 4);
			g2.drawLine(bx + 19, by + 4, bx + 19, by + bh - 4);
		}

		// Reset drag-over when cursor leaves
		@Override
		public void removeNotify() {
			dragOver = false;
			super.removeNotify();
		}
	}
}
