package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * Modal dialog for selecting two .dvscan files for delta comparison.
 * Returns the selected File pair or null if cancelled.
 */
public class DeltaScanDialog extends JDialog {

    private JTextField txtBase;
    private JTextField txtTarget;
    private File baseFile;
    private File targetFile;
    private boolean approved;
    private final File defaultDir;

    public DeltaScanDialog(JFrame parent, File defaultDir) {
        super(parent, "Delta Scan — Compare Two Scans", true);
        this.defaultDir = defaultDir;
        initUI();
        pack();
        setMinimumSize(getSize());
        setLocationRelativeTo(parent);
    }

    private void initUI() {
        JPanel content = new JPanel(new BorderLayout(8, 8));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // File selection grid
        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Base scan row
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        grid.add(new JLabel("Base Scan (older):"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        txtBase = new JTextField(30);
        txtBase.setEditable(false);
        grid.add(txtBase, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        JButton btnBrowseBase = new JButton("Browse...");
        btnBrowseBase.addActionListener(e -> browseFile(true));
        grid.add(btnBrowseBase, gbc);

        // Target scan row
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        grid.add(new JLabel("Target Scan (newer):"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        txtTarget = new JTextField(30);
        txtTarget.setEditable(false);
        grid.add(txtTarget, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        JButton btnBrowseTarget = new JButton("Browse...");
        btnBrowseTarget.addActionListener(e -> browseFile(false));
        grid.add(btnBrowseTarget, gbc);

        content.add(grid, BorderLayout.CENTER);

        // Buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton btnCompare = new JButton("Compare");
        JButton btnCancel = new JButton("Cancel");
        btnCompare.addActionListener(e -> {
            if (baseFile != null && targetFile != null) {
                approved = true;
                dispose();
            }
        });
        btnCancel.addActionListener(e -> dispose());
        buttons.add(btnCompare);
        buttons.add(btnCancel);
        content.add(buttons, BorderLayout.SOUTH);

        setContentPane(content);
        getRootPane().setDefaultButton(btnCompare);
    }

    private void browseFile(boolean isBase) {
        JFileChooser chooser = new JFileChooser(defaultDir);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "DeepViolet Scan Files (*.dvscan)", "dvscan"));
        int ret = chooser.showOpenDialog(this);
        if (ret != JFileChooser.APPROVE_OPTION) return;

        File file = chooser.getSelectedFile();
        if (isBase) {
            baseFile = file;
            txtBase.setText(file.getAbsolutePath());
        } else {
            targetFile = file;
            txtTarget.setText(file.getAbsolutePath());
        }
    }

    /**
     * Returns the selected files as {base, target}, or null if cancelled.
     */
    public File[] getSelectedFiles() {
        if (approved && baseFile != null && targetFile != null) {
            return new File[]{baseFile, targetFile};
        }
        return null;
    }
}
