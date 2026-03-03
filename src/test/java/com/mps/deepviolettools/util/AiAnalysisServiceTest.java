package com.mps.deepviolettools.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AiAnalysisService}.
 */
class AiAnalysisServiceTest {

	@Test
	void testGetModelsForProvider_anthropic() {
		String[] models = AiAnalysisService.getModelsForProvider(AiAnalysisService.Provider.ANTHROPIC);
		assertNotNull(models);
		assertTrue(models.length > 0);
		assertEquals("claude-sonnet-4-5-20250929", models[0]);
	}

	@Test
	void testGetModelsForProvider_openai() {
		String[] models = AiAnalysisService.getModelsForProvider(AiAnalysisService.Provider.OPENAI);
		assertNotNull(models);
		assertTrue(models.length > 0);
		assertEquals("gpt-4o", models[0]);
	}

	@Test
	void testProviderFromDisplayName() {
		assertEquals(AiAnalysisService.Provider.ANTHROPIC,
				AiAnalysisService.Provider.fromDisplayName("Anthropic"));
		assertEquals(AiAnalysisService.Provider.OPENAI,
				AiAnalysisService.Provider.fromDisplayName("OpenAI"));
		// Case insensitive
		assertEquals(AiAnalysisService.Provider.ANTHROPIC,
				AiAnalysisService.Provider.fromDisplayName("anthropic"));
		// Unknown falls back to ANTHROPIC
		assertEquals(AiAnalysisService.Provider.ANTHROPIC,
				AiAnalysisService.Provider.fromDisplayName("unknown"));
	}

	@Test
	void testGetModelsForProvider_ollama() {
		String[] models = AiAnalysisService.getModelsForProvider(AiAnalysisService.Provider.OLLAMA);
		assertNotNull(models);
		assertTrue(models.length > 0);
		assertEquals("llama3.2:latest", models[0]);
	}

	@Test
	void testProviderFromDisplayName_ollama() {
		assertEquals(AiAnalysisService.Provider.OLLAMA,
				AiAnalysisService.Provider.fromDisplayName("Ollama"));
		assertEquals(AiAnalysisService.Provider.OLLAMA,
				AiAnalysisService.Provider.fromDisplayName("ollama"));
	}

	@Test
	void testAnalyze_missingApiKey_throws() {
		AiAnalysisService service = new AiAnalysisService();
		assertThrows(AiAnalysisService.AiAnalysisException.class,
				() -> service.analyze("test report", "", "Anthropic",
						"claude-sonnet-4-5-20250929", 4096, 0.3,
						AiAnalysisService.DEFAULT_SYSTEM_PROMPT));
		assertThrows(AiAnalysisService.AiAnalysisException.class,
				() -> service.analyze("test report", null, "Anthropic",
						"claude-sonnet-4-5-20250929", 4096, 0.3,
						AiAnalysisService.DEFAULT_SYSTEM_PROMPT));
		assertThrows(AiAnalysisService.AiAnalysisException.class,
				() -> service.analyze("test report", "   ", "OpenAI",
						"gpt-4o", 4096, 0.3,
						AiAnalysisService.DEFAULT_SYSTEM_PROMPT));
	}

	@Test
	void testAnalyze_ollama_blankKey_doesNotThrowKeyError() {
		AiAnalysisService service = new AiAnalysisService();
		// With Ollama, a blank API key should NOT throw "API key is required".
		// It should instead fail with a connection error (no Ollama server running).
		AiAnalysisService.AiAnalysisException ex = assertThrows(
				AiAnalysisService.AiAnalysisException.class,
				() -> service.analyze("test report", "", "Ollama",
						"llama3.2:latest", 4096, 0.3,
						AiAnalysisService.DEFAULT_SYSTEM_PROMPT,
						"http://localhost:99999"));
		assertFalse(ex.getMessage().contains("API key is required"),
				"Ollama should not require an API key");
	}

	@Test
	void testDefaultOllamaEndpoint() {
		assertEquals("http://localhost:11434", AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT);
	}

	@Test
	void testDefaultTemperature() {
		assertEquals(0.3, AiAnalysisService.DEFAULT_TEMPERATURE, 0.001);
	}

	@Test
	void testDefaultSystemPrompt_notBlank() {
		assertNotNull(AiAnalysisService.DEFAULT_SYSTEM_PROMPT);
		assertFalse(AiAnalysisService.DEFAULT_SYSTEM_PROMPT.isBlank());
		assertTrue(AiAnalysisService.DEFAULT_SYSTEM_PROMPT.contains("TLS"));
	}

	@Test
	void testProviderDisplayNames() {
		assertEquals("Anthropic", AiAnalysisService.Provider.ANTHROPIC.getDisplayName());
		assertEquals("OpenAI", AiAnalysisService.Provider.OPENAI.getDisplayName());
		assertEquals("Ollama", AiAnalysisService.Provider.OLLAMA.getDisplayName());
	}
}
