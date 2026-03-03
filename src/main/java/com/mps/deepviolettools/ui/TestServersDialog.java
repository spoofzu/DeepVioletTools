package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;

/**
 * Modal dialog that presents recently scanned URLs and a list of TLS test
 * servers from badssl.com.  Selecting a server (OK or double-click) populates
 * the host field and triggers a scan.
 *
 * @author Milton Smith
 */
public class TestServersDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private static final String[][] TEST_SERVERS = {
		// Valid certificates (should pass all checks)
		{ "badssl.com", "Valid cert, all checks pass" },
		{ "sha256.badssl.com", "Valid SHA-256 certificate" },
		{ "ecc256.badssl.com", "Valid ECC P-256 certificate" },
		{ "rsa2048.badssl.com", "Valid RSA 2048-bit certificate" },
		// Invalid or problematic certificates
		{ "expired.badssl.com", "Expired certificate" },
		{ "wrong.host.badssl.com", "Hostname mismatch (wrong CN/SAN)" },
		{ "self-signed.badssl.com", "Self-signed (untrusted root)" },
		{ "untrusted-root.badssl.com", "Signed by an untrusted root CA" },
		{ "revoked.badssl.com", "Revoked certificate" },
		{ "incomplete-chain.badssl.com", "Missing intermediate certificate(s)" },
		{ "no-common-name.badssl.com", "Invalid/missing subject" },
		// SCT / Certificate Transparency
		{ "no-sct.badssl.com", "No embedded SCTs (CT not logged)" },
		{ "invalid-expected-sct.badssl.com", "SCT from retired/unknown CT log" },
	};

	private String selectedUrl;
	private boolean recentSelected;
	private boolean multiSelect;
	private List<String> selectedRecentItems = new ArrayList<>();
	private List<String> selectedTestServerUrls = new ArrayList<>();
	private JList<String> lstRecent;
	private JTable table;

	/**
	 * Create a single-select modal dialog listing recent URLs and TLS test servers.
	 *
	 * @param owner      Parent frame for modal positioning
	 * @param urlHistory Recently scanned URLs (most recent first, max 5)
	 */
	public TestServersDialog(JFrame owner, List<String> urlHistory) {
		this(owner, urlHistory, false);
	}

	/**
	 * Create a modal dialog listing recent URLs and TLS test servers.
	 *
	 * @param owner       Parent frame for modal positioning
	 * @param urlHistory  Recently scanned URLs (most recent first, max 5)
	 * @param multiSelect true to allow Cmd/Ctrl multi-selection from both lists
	 */
	public TestServersDialog(JFrame owner, List<String> urlHistory, boolean multiSelect) {
		super(owner, "Select Scan Target", true);
		this.multiSelect = multiSelect;
		initComponents(urlHistory);
	}

	private void initComponents(List<String> urlHistory) {
		setLayout(new BorderLayout(0, 5));

		// ---- Recent history panel (top) ----
		JPanel pnlRecent = new JPanel(new BorderLayout());
		pnlRecent.setBorder(BorderFactory.createTitledBorder("Recent"));

		if (urlHistory != null && !urlHistory.isEmpty()) {
			lstRecent = new JList<>(urlHistory.toArray(new String[0]));
			lstRecent.setSelectionMode(multiSelect
					? ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
					: ListSelectionModel.SINGLE_SELECTION);
			lstRecent.setVisibleRowCount(Math.min(urlHistory.size(), 5));

			lstRecent.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					// Clear test server selection when recent list is clicked
					table.clearSelection();
					if (e.getClickCount() == 2 && lstRecent.getSelectedIndex() >= 0) {
						if (multiSelect) {
							acceptMultiSelect();
						} else {
							acceptRecent();
						}
					}
				}
			});

			pnlRecent.add(new JScrollPane(lstRecent), BorderLayout.CENTER);
		} else {
			lstRecent = new JList<>(new String[] { "(no recent scans)" });
			lstRecent.setEnabled(false);
			pnlRecent.add(new JScrollPane(lstRecent), BorderLayout.CENTER);
		}

		// ---- Test servers table ----
		DefaultTableModel model = new DefaultTableModel(
				new String[] { "Server", "Description" }, 0) {
			private static final long serialVersionUID = 1L;
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		for (String[] row : TEST_SERVERS) {
			model.addRow(row);
		}

		table = new JTable(model);
		table.setSelectionMode(multiSelect
				? ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
				: ListSelectionModel.SINGLE_SELECTION);
		table.getColumnModel().getColumn(0).setPreferredWidth(200);
		table.getColumnModel().getColumn(1).setPreferredWidth(300);
		table.setRowHeight(24);
		table.setFillsViewportHeight(true);
		table.setRowSelectionAllowed(true);
		table.getTableHeader().setReorderingAllowed(false);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (lstRecent.isEnabled()) {
					// Clear recent selection when test server table is clicked
					lstRecent.clearSelection();
				}
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && table.getSelectedRow() >= 0) {
					if (multiSelect) {
						acceptMultiSelect();
					} else {
						acceptTestServer();
					}
				}
			}
		});

		JScrollPane spTable = new JScrollPane(table);
		spTable.setBorder(BorderFactory.createTitledBorder("Test Servers (badssl.com)"));

		// Split pane: recent history on top (favored), test servers below
		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, pnlRecent, spTable);
		splitPane.setResizeWeight(0.65);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);

		// ---- Buttons (bottom) ----
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton btnOk = new JButton("OK");
		JButton btnCancel = new JButton("Cancel");

		btnOk.addActionListener(e -> {
			if (multiSelect) {
				acceptMultiSelect();
			} else {
				// Prefer recent list selection, then table selection
				if (lstRecent.isEnabled() && lstRecent.getSelectedIndex() >= 0) {
					acceptRecent();
				} else if (table.getSelectedRow() >= 0) {
					acceptTestServer();
				}
			}
		});
		btnCancel.addActionListener(e -> {
			selectedUrl = null;
			dispose();
		});

		buttonPanel.add(btnOk);
		buttonPanel.add(btnCancel);
		add(buttonPanel, BorderLayout.SOUTH);

		getRootPane().setDefaultButton(btnOk);
		setSize(550, 500);
		setLocationRelativeTo(getOwner());
	}

	private void acceptRecent() {
		String value = lstRecent.getSelectedValue();
		if (value != null && !value.startsWith("(")) {
			selectedUrl = value;
			recentSelected = true;
		}
		dispose();
	}

	private void acceptTestServer() {
		int row = table.getSelectedRow();
		if (row >= 0) {
			selectedUrl = "https://" + table.getValueAt(row, 0);
			recentSelected = false;
		}
		dispose();
	}

	private void acceptMultiSelect() {
		selectedRecentItems.clear();
		selectedTestServerUrls.clear();

		if (lstRecent.isEnabled()) {
			for (String v : lstRecent.getSelectedValuesList()) {
				if (v != null && !v.startsWith("(")) {
					selectedRecentItems.add(v);
				}
			}
		}

		int[] rows = table.getSelectedRows();
		for (int row : rows) {
			selectedTestServerUrls.add("https://" + table.getValueAt(row, 0));
		}

		dispose();
	}

	/**
	 * Returns true if the selection came from the Recent list, false if from
	 * the Test Servers table. Only meaningful in single-select mode.
	 *
	 * @return true if a recent entry was selected
	 */
	public boolean isRecentSelected() {
		return recentSelected;
	}

	/**
	 * Returns the selected URL (full https:// URL), or null if cancelled.
	 * Only meaningful in single-select mode.
	 *
	 * @return selected server URL, or null if cancelled
	 */
	public String getSelectedUrl() {
		return selectedUrl;
	}

	/**
	 * Returns selected recent item labels. Only populated in multi-select mode.
	 *
	 * @return list of selected recent labels (may be empty)
	 */
	public List<String> getSelectedRecentItems() {
		return selectedRecentItems;
	}

	/**
	 * Returns selected test server URLs. Only populated in multi-select mode.
	 *
	 * @return list of selected test server URLs (may be empty)
	 */
	public List<String> getSelectedTestServerUrls() {
		return selectedTestServerUrls;
	}
}
