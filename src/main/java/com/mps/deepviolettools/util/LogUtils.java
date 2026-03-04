package com.mps.deepviolettools.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;

/**
 * Helper class to initialize the logback logger.
 * @author Milton Smith
 *
 */
public class LogUtils {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolettools.util.LogUtils");

	private static final Path LOGS_DIR = FontPreferences.getHomeDir().toPath().resolve("ui").resolve("logs");
	private static final Path LOG_DATA_DIR = LOGS_DIR.resolve("data");
	private static final Path LOGBACK_FILE = LOGS_DIR.resolve("logback.xml");

	/**
	 * Initialize logback logging. Sets system properties for the working
	 * directory and default log level. Copies the default logback.xml to
	 * {@code ~/DeepVioletTools/ui/logs/} on first run, then loads config
	 * from that file so users can customize it. Log data files are written
	 * to {@code ~/DeepVioletTools/ui/logs/data/}.
	 */
	public static final void logInit() {

		// Assign some variables to the logback log
		System.setProperty("dv_user_level", "INFO");

		// Create log data directory if it doesn't exist
		try {
			Files.createDirectories(LOG_DATA_DIR);
		} catch (IOException ignored) {
		}

		// Copy default logback.xml to ui/logs/ if not present or stale.
		// The version marker (dv-logback-v3) lets us detect old configs.
		boolean needsCopy = !Files.exists(LOGBACK_FILE);
		if (!needsCopy) {
			try {
				String content = Files.readString(LOGBACK_FILE);
				needsCopy = !content.contains("dv-logback-v6");
			} catch (IOException ignored) {
				needsCopy = true;
			}
		}
		if (needsCopy) {
			try (InputStream in = LogUtils.class.getResourceAsStream("/logback-default.xml")) {
				if (in != null) {
					Files.deleteIfExists(LOGBACK_FILE);
					Files.copy(in, LOGBACK_FILE);
				}
			} catch (IOException ignored) {
			}
		}

		// Set log data directory for logback property substitution
		System.setProperty("dv.log.dir", LOG_DATA_DIR.toString());

		// Load logback config from external file (user-customizable)
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
		lc.reset();
		try {
			JoranConfigurator configurator = new JoranConfigurator();
			configurator.setContext(lc);
			configurator.doConfigure(LOGBACK_FILE.toFile());
		} catch (JoranException e) {
			logger.error("Logback configuration failed", e);
		}
	}
	
}
