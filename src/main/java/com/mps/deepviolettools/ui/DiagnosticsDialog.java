package com.mps.deepviolettools.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.mps.deepviolettools.util.FontPreferences;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Modal diagnostics dialog that displays runtime environment information
 * for debugging and support purposes.
 *
 * @author Milton Smith
 */
public class DiagnosticsDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.ui.DiagnosticsDialog");

	public DiagnosticsDialog(JFrame parent) {
		super(parent, "Diagnostics", true);

		JTextArea textArea = new JTextArea(buildDiagnostics());
		textArea.setEditable(false);
		textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		textArea.setCaretPosition(0);

		JScrollPane scrollPane = new JScrollPane(textArea);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton copyButton = new JButton("Copy to Clipboard");
		copyButton.addActionListener(e -> {
			StringSelection sel = new StringSelection(textArea.getText());
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
		});
		JButton closeButton = new JButton("Close");
		closeButton.addActionListener(e -> dispose());
		buttonPanel.add(copyButton);
		buttonPanel.add(closeButton);

		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(scrollPane, BorderLayout.CENTER);
		getContentPane().add(buttonPanel, BorderLayout.SOUTH);

		setSize((int) (parent.getWidth() * 0.75),
				(int) (parent.getHeight() * 0.75));
		setMinimumSize(new Dimension(500, 400));
		setLocationRelativeTo(parent);
		getRootPane().setDefaultButton(closeButton);
	}

	private String buildDiagnostics() {
		StringBuilder sb = new StringBuilder();

		// ── Application ──
		sb.append("── Application ──\n");
		sb.append(fmt("DeepVioletTools Version", readPomVersion("com.mps.violet", "DeepVioletTools")));
		sb.append(fmt("DeepViolet API Version", readPomVersion("com.github.spoofzu", "DeepViolet")));
		sb.append(fmt("JAR Location", getJarLocation()));
		sb.append(fmt("Working Directory", System.getProperty("user.dir")));
		sb.append(fmt("Started At", LocalDateTime.now().format(
				DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))));

		// ── Java Runtime ──
		sb.append("\n── Java Runtime ──\n");
		sb.append(fmt("Java Version", System.getProperty("java.version")));
		sb.append(fmt("Java Vendor", System.getProperty("java.vendor")));
		sb.append(fmt("Java Home", System.getProperty("java.home")));
		sb.append(fmt("VM Name", System.getProperty("java.vm.name")));
		sb.append(fmt("VM Version", System.getProperty("java.vm.version")));

		// ── Operating System ──
		sb.append("\n── Operating System ──\n");
		sb.append(fmt("OS", System.getProperty("os.name") + " " + System.getProperty("os.version")));
		sb.append(fmt("Architecture", System.getProperty("os.arch")));

		// ── Paths ──
		sb.append("\n── Paths ──\n");
		sb.append(fmt("Home Directory", FontPreferences.getHomeDir().getAbsolutePath()));
		sb.append(fmt("Global Config", FontPreferences.getGlobalDir().getAbsolutePath()));
		sb.append(fmt("Properties File",
				new File(FontPreferences.getHomeDir(), "deepviolet.properties").getAbsolutePath()));
		sb.append(fmt("Log Directory",
				new File(new File(new File(FontPreferences.getHomeDir(), "ui"), "logs"), "data").getAbsolutePath()));
		sb.append(fmt("Scans Directory",
				new File(new File(FontPreferences.getHomeDir(), "ui"), "scans").getAbsolutePath()));
		String trustStore = System.getProperty("javax.net.ssl.trustStore");
		if (trustStore == null || trustStore.isEmpty()) {
			trustStore = System.getProperty("java.home") + File.separator
					+ "lib" + File.separator + "security" + File.separator + "cacerts";
		}
		sb.append(fmt("Trust Store", trustStore));

		// ── Loaded Libraries ──
		sb.append("\n── Loaded Libraries ──\n");
		List<String> libs = scanLibraries();
		if (libs.isEmpty()) {
			sb.append("  (none detected)\n");
		} else {
			for (String lib : libs) {
				sb.append("  ").append(lib).append("\n");
			}
		}

		return sb.toString();
	}

	private static String fmt(String label, String value) {
		return String.format("  %-22s %s%n", label + ":", value != null ? value : "unknown");
	}

	private static String getJarLocation() {
		try {
			ProtectionDomain pd = DiagnosticsDialog.class.getProtectionDomain();
			CodeSource cs = pd.getCodeSource();
			return (cs != null) ? cs.getLocation().toExternalForm() : "unknown";
		} catch (Exception e) {
			return "unknown";
		}
	}

	private static String readPomVersion(String groupId, String artifactId) {
		String path = "META-INF/maven/" + groupId + "/" + artifactId + "/pom.properties";
		try (InputStream is = DiagnosticsDialog.class.getClassLoader().getResourceAsStream(path)) {
			if (is == null) return "unknown";
			Properties props = new Properties();
			props.load(is);
			return props.getProperty("version", "unknown");
		} catch (IOException e) {
			return "unknown";
		}
	}

	private static List<String> scanLibraries() {
		List<String> result = new ArrayList<>();
		try {
			ClassLoader cl = DiagnosticsDialog.class.getClassLoader();
			scanPomProperties(cl, result);
		} catch (Exception e) {
			logger.debug("Could not scan libraries: {}", e.getMessage());
		}
		Collections.sort(result);
		return result;
	}

	private static void scanPomProperties(ClassLoader cl, List<String> result) {
		// Try to find pom.properties by enumerating all resources
		// This works in shaded JARs since all META-INF/maven/ entries are merged
		try {
			// Use a broader search to find all pom.properties
			Enumeration<URL> resources = cl.getResources("META-INF/maven");
			while (resources.hasMoreElements()) {
				URL url = resources.nextElement();
				String protocol = url.getProtocol();
				if ("jar".equals(protocol)) {
					scanJarForPomProperties(url, cl, result);
				} else if ("file".equals(protocol)) {
					scanDirForPomProperties(new File(url.toURI()), result);
				}
			}
		} catch (Exception e) {
			logger.debug("Library scan fallback: {}", e.getMessage());
		}
	}

	private static void scanJarForPomProperties(URL mavenDirUrl, ClassLoader cl, List<String> result) {
		try {
			String jarPath = mavenDirUrl.getPath();
			int bangIdx = jarPath.indexOf('!');
			if (bangIdx < 0) return;

			String jarFilePath = jarPath.substring(0, bangIdx);
			URL jarFileUrl = new URL(jarFilePath);
			File jarFile = new File(jarFileUrl.toURI());

			try (java.util.jar.JarFile jf = new java.util.jar.JarFile(jarFile)) {
				jf.stream()
						.filter(entry -> entry.getName().startsWith("META-INF/maven/")
								&& entry.getName().endsWith("/pom.properties"))
						.forEach(entry -> {
							try (InputStream is = jf.getInputStream(entry)) {
								Properties props = new Properties();
								props.load(is);
								String groupId = props.getProperty("groupId", "?");
								String artifactId = props.getProperty("artifactId", "?");
								String version = props.getProperty("version", "?");
								result.add(groupId + ":" + artifactId + " : " + version);
							} catch (IOException ex) {
								// skip unreadable entry
							}
						});
			}
		} catch (Exception e) {
			logger.debug("Could not scan JAR: {}", e.getMessage());
		}
	}

	private static void scanDirForPomProperties(File mavenDir, List<String> result) {
		if (!mavenDir.isDirectory()) return;
		File[] groupDirs = mavenDir.listFiles(File::isDirectory);
		if (groupDirs == null) return;
		for (File groupDir : groupDirs) {
			File[] artifactDirs = groupDir.listFiles(File::isDirectory);
			if (artifactDirs == null) continue;
			for (File artifactDir : artifactDirs) {
				File pomProps = new File(artifactDir, "pom.properties");
				if (pomProps.isFile()) {
					try (InputStream is = new java.io.FileInputStream(pomProps)) {
						Properties props = new Properties();
						props.load(is);
						String gid = props.getProperty("groupId", "?");
						String aid = props.getProperty("artifactId", "?");
						String ver = props.getProperty("version", "?");
						result.add(gid + ":" + aid + " : " + ver);
					} catch (IOException e) {
						// skip
					}
				}
			}
		}
	}
}
