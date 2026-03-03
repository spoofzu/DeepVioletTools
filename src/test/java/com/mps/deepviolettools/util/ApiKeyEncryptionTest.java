package com.mps.deepviolettools.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;

/**
 * Tests for API key encryption/decryption in {@link FontPreferences}.
 *
 * <p>When run via Maven Surefire the {@code deepviolet.home} and
 * {@code deepviolet.global} system properties redirect all file I/O
 * to {@code target/test-home/}, so the real user properties are never
 * touched.</p>
 */
@TestMethodOrder(MethodOrderer.MethodName.class)
class ApiKeyEncryptionTest {

	private static String originalApiKey;

	@BeforeAll
	static void backupApiKey() {
		FontPreferences.ensureEncryptionSeed();
		originalApiKey = FontPreferences.load().getAiApiKey();
	}

	@AfterAll
	static void restoreApiKey() {
		FontPreferences prefs = FontPreferences.load();
		prefs.setAiApiKey(originalApiKey != null ? originalApiKey : "");
		FontPreferences.save(prefs);
	}

	@Test
	void testEnsureEncryptionSeed_generatesOnce() {
		// ensureEncryptionSeed is idempotent
		assertDoesNotThrow(FontPreferences::ensureEncryptionSeed);

		// Seed should be in global properties, not local
		File globalFile = new File(FontPreferences.getGlobalDir(), "global.properties");
		assertTrue(globalFile.exists(), "global.properties should exist");
		Properties globalRaw = new Properties();
		try (FileInputStream in = new FileInputStream(globalFile)) {
			globalRaw.load(in);
		} catch (Exception e) {
			fail("Could not read global properties: " + e.getMessage());
		}
		assertNotNull(globalRaw.getProperty("security.encryptionSeed"),
				"Seed should be stored in global.properties");
	}

	@Test
	void testSaveAndLoad_roundTrip_encryptsApiKey() {
		String testKey = "sk-ant-test-key-1234567890";

		// Load existing prefs (fully initialized), set API key, save
		FontPreferences prefs = FontPreferences.load();
		prefs.setAiEnabled(true);
		prefs.setAiApiKey(testKey);
		FontPreferences.save(prefs);

		// Reload and verify plaintext round-trip
		FontPreferences loaded = FontPreferences.load();
		assertEquals(testKey, loaded.getAiApiKey());

		// Verify the raw properties file does NOT contain the plaintext key
		File propsFile = new File(FontPreferences.getHomeDir(), "deepviolet.properties");
		if (propsFile.exists()) {
			Properties raw = new Properties();
			try (FileInputStream in = new FileInputStream(propsFile)) {
				raw.load(in);
			} catch (Exception e) {
				fail("Could not read properties file: " + e.getMessage());
			}
			String storedValue = raw.getProperty("ai.apiKey");
			assertNotNull(storedValue);
			// The stored value should NOT be the plaintext key
			assertNotEquals(testKey, storedValue,
					"API key should be encrypted in the properties file");
		}
	}

	@Test
	void testSaveAndLoad_emptyApiKey() {
		FontPreferences prefs = FontPreferences.load();
		prefs.setAiApiKey("");
		FontPreferences.save(prefs);

		FontPreferences loaded = FontPreferences.load();
		assertEquals("", loaded.getAiApiKey());
	}

	@Test
	void sha256Hex_consistent() {
		byte[] data = "hello world".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		String hash1 = FontPreferences.sha256Hex(data);
		String hash2 = FontPreferences.sha256Hex(data);
		assertNotNull(hash1);
		assertEquals(64, hash1.length(), "SHA-256 hex should be 64 chars");
		assertEquals(hash1, hash1.toLowerCase(), "Should be lowercase");
		assertEquals(hash1, hash2, "Same data should produce same hash");
	}

	@Test
	void sha256Hex_differentData() {
		byte[] data1 = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] data2 = "world".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		String hash1 = FontPreferences.sha256Hex(data1);
		String hash2 = FontPreferences.sha256Hex(data2);
		assertNotNull(hash1);
		assertNotNull(hash2);
		assertNotEquals(hash1, hash2, "Different data should produce different hashes");
	}
}
