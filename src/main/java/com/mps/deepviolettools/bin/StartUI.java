package com.mps.deepviolettools.bin;

import java.awt.Image;
import java.awt.Taskbar;
import java.awt.Toolkit;
import java.net.URL;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import com.formdev.flatlaf.themes.FlatMacLightLaf;
import com.mps.deepviolettools.ui.MainFrm;
import com.mps.deepviolettools.util.FontPreferences;
import com.mps.deepviolettools.util.LogUtils;

/**
 * Entry point to start DeepViolet and display a user interface.
 *
 * @author Milton Smith
 */
public class StartUI {

	// Initialize logging before we do anything
	static {
		LogUtils.logInit();
	}

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolettools.bin.StartUI");
	private static final Logger scanlog = LoggerFactory.getLogger("scanlog");

	/**
	 * Main entry point
	 *
	 * @param args Command line arguments (not used for now)
	 */
	public static void main(String[] args) {

		// Let the JVM pick up the current macOS appearance (light/dark)
		if (isMacOs()) {
			System.setProperty("apple.awt.application.appearance", "system");
		}

		new StartUI().init(args);

	}

	/**
	 * Initialization
	 */
	private void init(String[] args) {

		logger.info("Starting UI via dvui");
		scanlog.info("DeepVioletUI started");

		FontPreferences.ensureEncryptionSeed();

		for (String arg : args) {
			if ("--reset-theme".equals(arg)) {
				FontPreferences.resetAppTheme();
				logger.info("Application theme reset to system default");
				break;
			}
		}

		Runtime.getRuntime().addShutdownHook(new Thread(() -> scanlog.info("DeepVioletUI stopped")));

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				try {
					boolean dark = isSystemDarkMode();
					// Set accent color BEFORE FlatLaf setup so it derives
					// all dependent colors (focus borders, etc.) from it
					java.awt.Color accent = FontPreferences.loadAccentForInit(dark);
					UIManager.put("@accentColor", accent);
					if (isMacOs()) {
						if (dark) {
							FlatMacDarkLaf.setup();
							logger.debug("Look and feel assigned: FlatMacDarkLaf");
						} else {
							FlatMacLightLaf.setup();
							logger.debug("Look and feel assigned: FlatMacLightLaf");
						}
					} else {
						if (dark) {
							FlatDarkLaf.setup();
							logger.debug("Look and feel assigned: FlatDarkLaf");
						} else {
							FlatLightLaf.setup();
							logger.debug("Look and feel assigned: FlatLightLaf");
						}
					}
				} catch (Exception e) {
					logger.warn("FlatLaf setup failed, falling back to system L&F: " + e.getMessage());
					try {
						UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
					} catch (Exception ex) {
						logger.error("Error setting fallback lookandfeel, msg=" + ex.getMessage());
					}
				}

				// Capture system L&F colors from real components before anything modifies UIManager
				FontPreferences.captureSystemDefaults();

				try {
					// Set dock/taskbar icon using modern Java API (Java 9+)
					if (Taskbar.isTaskbarSupported()) {
						Taskbar taskbar = Taskbar.getTaskbar();
						if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
							URL url = this.getClass().getClassLoader().getResource("deepviolet-logo.png");
							if (url != null) {
								Image image = Toolkit.getDefaultToolkit().getImage(url);
								taskbar.setIconImage(image);
								logger.debug("Taskbar icon assigned, url=" + url.toString());
							}
						}
					}
				} catch (Exception e) {
					logger.error("Error setting taskbar icon image, msg=" + e.getMessage());
				}

				MainFrm main = new MainFrm();
				main.initComponents();
				main.setVisible(true);
			}
		});

	}

	private static boolean isMacOs() {
		String os = System.getProperty("os.name", "").toLowerCase();
		return os.contains("mac");
	}

	/**
	 * Detect whether the system is in dark mode on the current platform.
	 * Returns false if the setting cannot be read or the platform is unsupported.
	 */
	private static boolean isSystemDarkMode() {
		String os = System.getProperty("os.name", "").toLowerCase();
		if (os.contains("mac")) {
			return isMacOsDarkMode();
		} else if (os.contains("win")) {
			return isWindowsDarkMode();
		} else {
			return isLinuxDarkMode();
		}
	}

	private static boolean isMacOsDarkMode() {
		try {
			Process p = Runtime.getRuntime().exec(
				new String[]{"defaults", "read", "-g", "AppleInterfaceStyle"});
			return p.waitFor() == 0; // exits 0 and prints "Dark" when dark mode is on
		} catch (Exception e) {
			return false;
		}
	}

	private static boolean isWindowsDarkMode() {
		try {
			Process p = Runtime.getRuntime().exec(new String[]{
				"reg", "query",
				"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
				"/v", "AppsUseLightTheme"});
			String output = new String(p.getInputStream().readAllBytes());
			p.waitFor();
			return output.contains("0x0"); // 0 = dark mode
		} catch (Exception e) {
			return false;
		}
	}

	private static boolean isLinuxDarkMode() {
		try {
			Process p = Runtime.getRuntime().exec(new String[]{
				"gsettings", "get", "org.gnome.desktop.interface", "color-scheme"});
			String output = new String(p.getInputStream().readAllBytes());
			p.waitFor();
			if (output.contains("prefer-dark")) {
				return true;
			}
		} catch (Exception e) {
			// gsettings not available, try GTK_THEME fallback
		}
		String gtkTheme = System.getenv("GTK_THEME");
		return gtkTheme != null && gtkTheme.toLowerCase().contains("dark");
	}

}
