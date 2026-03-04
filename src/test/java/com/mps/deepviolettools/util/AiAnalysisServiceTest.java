package com.mps.deepviolettools.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.mps.deepviolettools.model.ScanNode;

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

	// ---- parseAiResponse tests ----

	@Test
	void testParseAiResponse_wellFormedSections() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		String response = """
				[Executive Summary]
				Overall TLS posture is good.
				[Recommendations]
				1. Enable HSTS.
				2. Upgrade TLS version.""";

		AiAnalysisService.parseAiResponse(section, response);

		List<ScanNode> children = section.getChildren();
		assertEquals(2, children.size());
		assertEquals("Executive Summary", children.get(0).getKey());
		assertEquals(ScanNode.NodeType.SUBSECTION, children.get(0).getType());
		assertEquals(1, children.get(0).getChildren().size());

		assertEquals("Recommendations", children.get(1).getKey());
		assertEquals(2, children.get(1).getChildren().size());
	}

	@Test
	void testParseAiResponse_criticalAndWarningRouting() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		String response = """
				[Findings]
				CRITICAL: Certificate expired
				WARNING: Weak cipher detected
				Normal content line""";

		AiAnalysisService.parseAiResponse(section, response);

		ScanNode findings = section.getChildren().get(0);
		assertEquals(3, findings.getChildren().size());
		assertEquals(ScanNode.NodeType.WARNING, findings.getChildren().get(0).getType());
		assertTrue(findings.getChildren().get(0).getKey().contains("CRITICAL:"));
		assertEquals(ScanNode.NodeType.WARNING, findings.getChildren().get(1).getType());
		assertTrue(findings.getChildren().get(1).getKey().contains("WARNING:"));
		assertEquals(ScanNode.NodeType.CONTENT, findings.getChildren().get(2).getType());
	}

	@Test
	void testParseAiResponse_noDelimiters() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		AiAnalysisService.parseAiResponse(section, "Line one\nLine two");

		// Content goes directly to parent section
		assertEquals(2, section.getChildren().size());
		assertEquals(ScanNode.NodeType.CONTENT, section.getChildren().get(0).getType());
		assertEquals("Line one", section.getChildren().get(0).getKey());
	}

	@Test
	void testParseAiResponse_riskFormatLines() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		String response = """
				[Security Findings]
				SYS-0040800 [LOW] Referrer-Policy header missing (score: 0.10)
				SYS-0010100 [HIGH] TLS 1.0 supported (score: 5.00)
				SYS-0050300 [CRITICAL] Certificate expired (score: 10.00)
				SYS-0030200 [MEDIUM] Weak cipher suite (score: 2.50)
				SYS-0060100 [INFO] OCSP stapling not detected (score: 0.05)
				Normal analysis text""";

		AiAnalysisService.parseAiResponse(section, response);

		ScanNode findings = section.getChildren().get(0);
		assertEquals(6, findings.getChildren().size());

		// Risk-format lines become WARNING nodes with severity
		ScanNode low = findings.getChildren().get(0);
		assertEquals(ScanNode.NodeType.WARNING, low.getType());
		assertEquals("LOW", low.getSeverity());
		assertTrue(low.getKey().contains("SYS-0040800"));

		ScanNode high = findings.getChildren().get(1);
		assertEquals(ScanNode.NodeType.WARNING, high.getType());
		assertEquals("HIGH", high.getSeverity());

		ScanNode critical = findings.getChildren().get(2);
		assertEquals(ScanNode.NodeType.WARNING, critical.getType());
		assertEquals("CRITICAL", critical.getSeverity());

		ScanNode medium = findings.getChildren().get(3);
		assertEquals(ScanNode.NodeType.WARNING, medium.getType());
		assertEquals("MEDIUM", medium.getSeverity());

		ScanNode info = findings.getChildren().get(4);
		assertEquals(ScanNode.NodeType.WARNING, info.getType());
		assertEquals("INFO", info.getSeverity());

		// Normal line remains CONTENT
		assertEquals(ScanNode.NodeType.CONTENT, findings.getChildren().get(5).getType());
	}

	@Test
	void testParseAiResponse_subsectionHeadersWithInlineSeverity() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		// AI produces headers like [SYS-0000900 [LOW] ALPN not negotiated]
		String response = """
				[Executive Summary]
				Overall score is 85/100.
				[SYS-0000900 [LOW] ALPN not negotiated]
				What it is: ALPN is a TLS extension.
				[SYS-0010100 [HIGH] TLS 1.0 supported]
				What it is: TLS 1.0 is deprecated.""";

		AiAnalysisService.parseAiResponse(section, response);

		assertEquals(3, section.getChildren().size());

		// Executive Summary has no severity
		ScanNode exec = section.getChildren().get(0);
		assertEquals(ScanNode.NodeType.SUBSECTION, exec.getType());
		assertNull(exec.getSeverity());

		// SYS-0000900 gets LOW severity from inline bracket
		ScanNode low = section.getChildren().get(1);
		assertEquals(ScanNode.NodeType.SUBSECTION, low.getType());
		assertEquals("LOW", low.getSeverity());
		assertTrue(low.getKey().contains("SYS-0000900"));

		// SYS-0010100 gets HIGH severity from inline bracket
		ScanNode high = section.getChildren().get(2);
		assertEquals(ScanNode.NodeType.SUBSECTION, high.getType());
		assertEquals("HIGH", high.getSeverity());
	}

	@Test
	void testParseAiResponse_subsectionHeadersWithSeverityMap() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		// Old-style headers without inline severity (fallback to map)
		String response = """
				[SYS-0000900 - ALPN not negotiated]
				What it is: ALPN is a TLS extension.
				[SYS-0010100 - TLS 1.0 supported]
				What it is: TLS 1.0 is deprecated.""";

		java.util.Map<String, String> severityMap = java.util.Map.of(
				"SYS-0000900", "LOW",
				"SYS-0010100", "HIGH");

		AiAnalysisService.parseAiResponse(section, response, severityMap);

		ScanNode low = section.getChildren().get(0);
		assertEquals(ScanNode.NodeType.SUBSECTION, low.getType());
		assertEquals("LOW", low.getSeverity());
		// Dash format reformatted to bracket style
		assertEquals("SYS-0000900 [LOW] ALPN not negotiated", low.getKey());

		ScanNode high = section.getChildren().get(1);
		assertEquals(ScanNode.NodeType.SUBSECTION, high.getType());
		assertEquals("HIGH", high.getSeverity());
		assertEquals("SYS-0010100 [HIGH] TLS 1.0 supported", high.getKey());
	}

	@Test
	void testParseAiResponse_emptyInput() {
		ScanNode root = ScanNode.createRoot();
		ScanNode section = root.addSection("AI Evaluation");

		AiAnalysisService.parseAiResponse(section, "");
		assertTrue(section.getChildren().isEmpty());

		AiAnalysisService.parseAiResponse(section, null);
		assertTrue(section.getChildren().isEmpty());
	}
}
