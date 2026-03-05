package com.mps.deepviolettools.util;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import java.util.List;

import com.mps.deepviolettools.model.ScanNode;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for Anthropic and OpenAI chat completion APIs.
 * Uses {@code java.net.http.HttpClient} (Java 21+) and Jackson for JSON.
 *
 * @author Milton Smith
 */
public class AiAnalysisService {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.util.AiAnalysisService");

	private static final Logger aiReportLog = LoggerFactory
			.getLogger("aiinlinereporting");

	private static final HttpClient httpClient = HttpClient.newBuilder()
			.connectTimeout(Duration.ofSeconds(30))
			.build();

	public enum Provider {
		ANTHROPIC("Anthropic"),
		OPENAI("OpenAI"),
		OLLAMA("Ollama");

		private final String displayName;

		Provider(String displayName) {
			this.displayName = displayName;
		}

		public String getDisplayName() {
			return displayName;
		}

		public static Provider fromDisplayName(String name) {
			for (Provider p : values()) {
				if (p.displayName.equalsIgnoreCase(name)) {
					return p;
				}
			}
			return ANTHROPIC;
		}
	}

	public record ChatMessage(String role, String content) {}

	public static final String[] ANTHROPIC_MODELS = {
		"claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"
	};

	public static final String[] OPENAI_MODELS = {
		"gpt-4o", "gpt-4o-mini"
	};

	public static final String[] OLLAMA_MODELS = {
		"llama3.2:latest", "mistral:latest", "gemma2:latest"
	};

	public static final String DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434";

	public static String[] getModelsForProvider(Provider provider) {
		return switch (provider) {
			case ANTHROPIC -> ANTHROPIC_MODELS;
			case OPENAI -> OPENAI_MODELS;
			case OLLAMA -> OLLAMA_MODELS;
		};
	}

	/**
	 * Fetch available models from an Ollama instance via GET /api/tags.
	 * Falls back to {@link #OLLAMA_MODELS} on failure.
	 *
	 * @param endpointUrl Ollama base URL (e.g. "http://localhost:11434")
	 * @return array of model names
	 */
	public static String[] fetchOllamaModels(String endpointUrl) {
		if (endpointUrl == null || endpointUrl.isBlank()) {
			endpointUrl = DEFAULT_OLLAMA_ENDPOINT;
		}
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(endpointUrl.replaceAll("/+$", "") + "/api/tags"))
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				JsonNode root = mapper.readTree(response.body());
				JsonNode models = root.path("models");
				if (models.isArray() && !models.isEmpty()) {
					java.util.List<String> names = new java.util.ArrayList<>();
					for (JsonNode model : models) {
						String name = model.path("name").asText("");
						if (!name.isEmpty()) {
							names.add(name);
						}
					}
					if (!names.isEmpty()) {
						return names.toArray(new String[0]);
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to fetch Ollama models, using defaults", e);
		}
		return OLLAMA_MODELS;
	}

	/**
	 * Fetch available models from the Anthropic API via GET /v1/models.
	 * Falls back to {@link #ANTHROPIC_MODELS} on failure.
	 *
	 * @param apiKey Anthropic API key
	 * @return array of model IDs
	 */
	public static String[] fetchAnthropicModels(String apiKey) {
		if (apiKey == null || apiKey.isBlank()) {
			return ANTHROPIC_MODELS;
		}
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.anthropic.com/v1/models"))
					.header("x-api-key", apiKey)
					.header("anthropic-version", "2023-06-01")
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				JsonNode root = mapper.readTree(response.body());
				JsonNode data = root.path("data");
				if (data.isArray() && !data.isEmpty()) {
					java.util.List<String> ids = new java.util.ArrayList<>();
					for (JsonNode model : data) {
						String id = model.path("id").asText("");
						if (!id.isEmpty()) {
							ids.add(id);
						}
					}
					if (!ids.isEmpty()) {
						java.util.Collections.sort(ids);
						return ids.toArray(new String[0]);
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to fetch Anthropic models, using defaults", e);
		}
		return ANTHROPIC_MODELS;
	}

	/**
	 * Fetch available chat models from the OpenAI API via GET /v1/models.
	 * Filters to chat-capable models (gpt-*, o1*, o3*, o4-mini*, chatgpt-*).
	 * Falls back to {@link #OPENAI_MODELS} on failure.
	 *
	 * @param apiKey OpenAI API key
	 * @return array of model IDs
	 */
	public static String[] fetchOpenAIModels(String apiKey) {
		if (apiKey == null || apiKey.isBlank()) {
			return OPENAI_MODELS;
		}
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.openai.com/v1/models"))
					.header("Authorization", "Bearer " + apiKey)
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				JsonNode root = mapper.readTree(response.body());
				JsonNode data = root.path("data");
				if (data.isArray() && !data.isEmpty()) {
					java.util.List<String> ids = new java.util.ArrayList<>();
					for (JsonNode model : data) {
						String id = model.path("id").asText("");
						if (!id.isEmpty() && isChatModel(id)) {
							ids.add(id);
						}
					}
					if (!ids.isEmpty()) {
						java.util.Collections.sort(ids);
						return ids.toArray(new String[0]);
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to fetch OpenAI models, using defaults", e);
		}
		return OPENAI_MODELS;
	}

	private static boolean isChatModel(String id) {
		return id.startsWith("gpt-") || id.startsWith("o1") || id.startsWith("o3")
				|| id.startsWith("o4-mini") || id.startsWith("chatgpt-");
	}

	public static final String DEFAULT_SYSTEM_PROMPT = """
			You are a TLS/SSL security expert analyzing a DeepViolet scan report. \
			The risk assessment lists findings identified by stable rule IDs \
			(e.g., "DV-R0000012 [HIGH] Strict-Transport-Security header missing \
			(-6 pts)"). Your job is to explain each finding so the reader \
			understands the technology involved, why it matters, and how to fix it.

			Respond using EXACTLY the section format below. Each section starts \
			with its name in square brackets on its own line. Write plain text \
			only — no markdown, no bullet characters (*, -, #), no bold/italic \
			markers (**).

			[Executive Summary]
			Write 2-4 sentences assessing the overall TLS security posture. \
			Reference the overall score, grade, and risk level. Identify the \
			single most impactful finding by its rule ID.

			Next, for EACH finding listed in the risk assessment, \
			write a section using exactly this format:

			[RULE-ID [SEVERITY] Brief description from the finding]
			What it is: One or two sentences explaining what the technology, \
			standard, or configuration does in plain language.
			Why it matters: One or two sentences explaining the security impact \
			of this specific finding — what attack or weakness it enables.
			Remediation: One sentence with a specific, actionable fix.

			After all item sections, include these two sections:

			[Positive Findings]
			One finding per line, prefixed with "OK: ". Note security measures \
			properly configured. Reference specific values from the scan.

			[Recommendations]
			Numbered list (1. 2. 3. ...) of prioritized action items. Reference \
			rule IDs where applicable. Each is one sentence. Limit to 5-8.

			Rules:
			- Address every finding from the risk assessment, not just critical ones.
			- Do not repeat the finding verbatim — add explanatory value.
			- Reference specific protocols, ciphers, scores, or certificates.
			- Keep each item analysis to 3-4 lines (What/Why/Remediation).
			- Keep the entire response under 1200 words.
			- Do not add sections beyond those defined above.""";

	public static final String DEFAULT_CHAT_SYSTEM_PROMPT = """
			You answer TLS/SSL questions about DeepViolet scan results. \
			HARD LIMIT: 5 sentences maximum. Never exceed 5 sentences. \
			Everything past the fifth sentence is silently discarded \
			and the user never sees it. Put your most important point \
			first. No markdown, no bold, no bullet lists, no numbered \
			lists, no headings, no line breaks. Plain sentences only.""";

	private static final ObjectMapper mapper = new ObjectMapper();

	public static final double DEFAULT_TEMPERATURE = 0.3;

	/**
	 * Analyze a TLS scan report using the configured AI provider.
	 * This method is synchronous and intended to be called from a background thread.
	 *
	 * @param scanReport  plain text of the scan report generated so far
	 * @param apiKey      API key for the provider (ignored for Ollama)
	 * @param provider    provider display name ("Anthropic", "OpenAI", or "Ollama")
	 * @param model       model identifier
	 * @param maxTokens   maximum tokens in the response
	 * @param temperature sampling temperature (0.0–1.0)
	 * @param systemPrompt system prompt for the AI
	 * @return the AI's analysis text
	 * @throws AiAnalysisException on any error (auth, rate limit, network, parse)
	 */
	public String analyze(String scanReport, String apiKey, String provider,
						  String model, int maxTokens, double temperature,
						  String systemPrompt) throws AiAnalysisException {
		return analyze(scanReport, apiKey, provider, model, maxTokens, temperature, systemPrompt, null);
	}

	/**
	 * Analyze a TLS scan report using the configured AI provider.
	 * This method is synchronous and intended to be called from a background thread.
	 *
	 * @param scanReport  plain text of the scan report generated so far
	 * @param apiKey      API key for the provider (ignored for Ollama)
	 * @param provider    provider display name ("Anthropic", "OpenAI", or "Ollama")
	 * @param model       model identifier
	 * @param maxTokens   maximum tokens in the response
	 * @param temperature sampling temperature (0.0–1.0)
	 * @param systemPrompt system prompt for the AI
	 * @param endpointUrl  endpoint URL for Ollama (ignored for other providers)
	 * @return the AI's analysis text
	 * @throws AiAnalysisException on any error (auth, rate limit, network, parse)
	 */
	public String analyze(String scanReport, String apiKey, String provider,
						  String model, int maxTokens, double temperature,
						  String systemPrompt, String endpointUrl) throws AiAnalysisException {

		Provider p = Provider.fromDisplayName(provider);
		if (p != Provider.OLLAMA && (apiKey == null || apiKey.isBlank())) {
			throw new AiAnalysisException("API key is required for AI analysis");
		}

		aiReportLog.info("AI inline report request: provider={}, model={}, maxTokens={}, temperature={}, reportLength={} chars",
				p.getDisplayName(), model, maxTokens, temperature, scanReport == null ? 0 : scanReport.length());
		aiReportLog.debug("AI inline report full request body:\n--- SYSTEM PROMPT ---\n{}\n--- SCAN REPORT ---\n{}",
				systemPrompt, scanReport);

		long startTime = System.currentTimeMillis();
		String result;
		try {
			result = switch (p) {
				case ANTHROPIC -> callAnthropic(scanReport, apiKey, model, maxTokens, temperature, systemPrompt);
				case OPENAI -> callOpenAI(scanReport, apiKey, model, maxTokens, temperature, systemPrompt);
				case OLLAMA -> callOllama(scanReport, model, maxTokens, temperature, systemPrompt, endpointUrl);
			};
		} catch (AiAnalysisException e) {
			long elapsed = System.currentTimeMillis() - startTime;
			aiReportLog.info("AI inline report failed after {}ms: {}", elapsed, e.getMessage());
			throw e;
		}

		long elapsed = System.currentTimeMillis() - startTime;
		aiReportLog.info("AI inline report response: provider={}, model={}, elapsed={}ms, responseLength={} chars",
				p.getDisplayName(), model, elapsed, result == null ? 0 : result.length());
		aiReportLog.debug("AI inline report full response:\n{}", result);

		return result;
	}

	private String callAnthropic(String scanReport, String apiKey, String model,
								 int maxTokens, double temperature,
								 String systemPrompt) throws AiAnalysisException {
		try {
			ObjectNode body = mapper.createObjectNode();
			body.put("model", model);
			body.put("max_tokens", maxTokens);
			body.put("temperature", temperature);
			body.put("system", systemPrompt);

			ArrayNode messages = body.putArray("messages");
			ObjectNode userMsg = messages.addObject();
			userMsg.put("role", "user");
			userMsg.put("content", scanReport);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.anthropic.com/v1/messages"))
					.header("Content-Type", "application/json")
					.header("x-api-key", apiKey)
					.header("anthropic-version", "2023-06-01")
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleAnthropicResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("Anthropic API call failed", e);
			throw new AiAnalysisException("Anthropic API call failed: " + e.getMessage());
		}
	}

	private String handleAnthropicResponse(HttpResponse<String> response) throws AiAnalysisException {
		int status = response.statusCode();

		if (status == 401) {
			throw new AiAnalysisException("Invalid API key for Anthropic");
		} else if (status == 429) {
			throw new AiAnalysisException("Rate limit exceeded for Anthropic API");
		} else if (status >= 500) {
			throw new AiAnalysisException("Anthropic server error (HTTP " + status + ")");
		} else if (status != 200) {
			throw new AiAnalysisException("Anthropic API error (HTTP " + status + "): " + response.body());
		}

		try {
			JsonNode root = mapper.readTree(response.body());
			JsonNode content = root.path("content");
			if (content.isArray() && !content.isEmpty()) {
				return content.get(0).path("text").asText("");
			}
			throw new AiAnalysisException("Unexpected Anthropic response format");
		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			throw new AiAnalysisException("Failed to parse Anthropic response: " + e.getMessage());
		}
	}

	private String callOpenAI(String scanReport, String apiKey, String model,
							  int maxTokens, double temperature,
							  String systemPrompt) throws AiAnalysisException {
		try {
			ObjectNode body = mapper.createObjectNode();
			body.put("model", model);
			body.put("max_tokens", maxTokens);
			body.put("temperature", temperature);

			ArrayNode messages = body.putArray("messages");
			ObjectNode sysMsg = messages.addObject();
			sysMsg.put("role", "system");
			sysMsg.put("content", systemPrompt);
			ObjectNode userMsg = messages.addObject();
			userMsg.put("role", "user");
			userMsg.put("content", scanReport);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.openai.com/v1/chat/completions"))
					.header("Content-Type", "application/json")
					.header("Authorization", "Bearer " + apiKey)
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOpenAIResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("OpenAI API call failed", e);
			throw new AiAnalysisException("OpenAI API call failed: " + e.getMessage());
		}
	}

	private String handleOpenAIResponse(HttpResponse<String> response) throws AiAnalysisException {
		int status = response.statusCode();

		if (status == 401) {
			throw new AiAnalysisException("Invalid API key for OpenAI");
		} else if (status == 429) {
			throw new AiAnalysisException("Rate limit exceeded for OpenAI API");
		} else if (status >= 500) {
			throw new AiAnalysisException("OpenAI server error (HTTP " + status + ")");
		} else if (status != 200) {
			throw new AiAnalysisException("OpenAI API error (HTTP " + status + "): " + response.body());
		}

		try {
			JsonNode root = mapper.readTree(response.body());
			JsonNode choices = root.path("choices");
			if (choices.isArray() && !choices.isEmpty()) {
				return choices.get(0).path("message").path("content").asText("");
			}
			throw new AiAnalysisException("Unexpected OpenAI response format");
		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			throw new AiAnalysisException("Failed to parse OpenAI response: " + e.getMessage());
		}
	}

	/**
	 * Multi-turn chat with the AI. Sends the full conversation history.
	 * Synchronous — call from a background thread.
	 */
	public String chat(List<ChatMessage> messages, String apiKey, String provider,
					   String model, int maxTokens, double temperature,
					   String systemPrompt) throws AiAnalysisException {
		return chat(messages, apiKey, provider, model, maxTokens, temperature, systemPrompt, null);
	}

	/**
	 * Multi-turn chat with the AI. Sends the full conversation history.
	 * Synchronous — call from a background thread.
	 *
	 * @param endpointUrl endpoint URL for Ollama (ignored for other providers)
	 */
	public String chat(List<ChatMessage> messages, String apiKey, String provider,
					   String model, int maxTokens, double temperature,
					   String systemPrompt, String endpointUrl) throws AiAnalysisException {
		Provider p = Provider.fromDisplayName(provider);
		if (p != Provider.OLLAMA && (apiKey == null || apiKey.isBlank())) {
			throw new AiAnalysisException("API key is required for AI chat");
		}
		return switch (p) {
			case ANTHROPIC -> callAnthropicChat(messages, apiKey, model, maxTokens, temperature, systemPrompt);
			case OPENAI -> callOpenAIChat(messages, apiKey, model, maxTokens, temperature, systemPrompt);
			case OLLAMA -> callOllamaChat(messages, model, maxTokens, temperature, systemPrompt, endpointUrl);
		};
	}

	private String callAnthropicChat(List<ChatMessage> messages, String apiKey,
									  String model, int maxTokens, double temperature,
									  String systemPrompt) throws AiAnalysisException {
		try {
			ObjectNode body = mapper.createObjectNode();
			body.put("model", model);
			body.put("max_tokens", maxTokens);
			body.put("temperature", temperature);
			body.put("system", systemPrompt);

			ArrayNode msgArray = body.putArray("messages");
			for (ChatMessage msg : messages) {
				ObjectNode m = msgArray.addObject();
				m.put("role", msg.role());
				m.put("content", msg.content());
			}

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.anthropic.com/v1/messages"))
					.header("Content-Type", "application/json")
					.header("x-api-key", apiKey)
					.header("anthropic-version", "2023-06-01")
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleAnthropicResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("Anthropic chat API call failed", e);
			throw new AiAnalysisException("Anthropic API call failed: " + e.getMessage());
		}
	}

	private String callOpenAIChat(List<ChatMessage> messages, String apiKey,
								   String model, int maxTokens, double temperature,
								   String systemPrompt) throws AiAnalysisException {
		try {
			ObjectNode body = mapper.createObjectNode();
			body.put("model", model);
			body.put("max_tokens", maxTokens);
			body.put("temperature", temperature);

			ArrayNode msgArray = body.putArray("messages");
			ObjectNode sysMsg = msgArray.addObject();
			sysMsg.put("role", "system");
			sysMsg.put("content", systemPrompt);
			for (ChatMessage msg : messages) {
				ObjectNode m = msgArray.addObject();
				m.put("role", msg.role());
				m.put("content", msg.content());
			}

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.openai.com/v1/chat/completions"))
					.header("Content-Type", "application/json")
					.header("Authorization", "Bearer " + apiKey)
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOpenAIResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("OpenAI chat API call failed", e);
			throw new AiAnalysisException("OpenAI API call failed: " + e.getMessage());
		}
	}

	private String callOllama(String scanReport, String model,
							   int maxTokens, double temperature,
							   String systemPrompt, String endpointUrl) throws AiAnalysisException {
		try {
			String baseUrl = (endpointUrl != null && !endpointUrl.isBlank())
					? endpointUrl : DEFAULT_OLLAMA_ENDPOINT;

			ObjectNode body = mapper.createObjectNode();
			body.put("model", model);
			body.put("stream", false);

			ObjectNode options = body.putObject("options");
			options.put("temperature", temperature);
			options.put("num_predict", maxTokens);

			ArrayNode messages = body.putArray("messages");
			ObjectNode sysMsg = messages.addObject();
			sysMsg.put("role", "system");
			sysMsg.put("content", systemPrompt);
			ObjectNode userMsg = messages.addObject();
			userMsg.put("role", "user");
			userMsg.put("content", scanReport);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl.replaceAll("/+$", "") + "/api/chat"))
					.header("Content-Type", "application/json")
					.timeout(Duration.ofSeconds(300))
					.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOllamaResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.debug("Ollama API call failed", e);
			throw new AiAnalysisException("Ollama API call failed: " + e.getMessage());
		}
	}

	private String callOllamaChat(List<ChatMessage> messages, String model,
								   int maxTokens, double temperature,
								   String systemPrompt, String endpointUrl) throws AiAnalysisException {
		try {
			String baseUrl = (endpointUrl != null && !endpointUrl.isBlank())
					? endpointUrl : DEFAULT_OLLAMA_ENDPOINT;

			ObjectNode body = mapper.createObjectNode();
			body.put("model", model);
			body.put("stream", false);

			ObjectNode options = body.putObject("options");
			options.put("temperature", temperature);
			options.put("num_predict", maxTokens);

			ArrayNode msgArray = body.putArray("messages");
			ObjectNode sysMsg = msgArray.addObject();
			sysMsg.put("role", "system");
			sysMsg.put("content", systemPrompt);
			for (ChatMessage msg : messages) {
				ObjectNode m = msgArray.addObject();
				m.put("role", msg.role());
				m.put("content", msg.content());
			}

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl.replaceAll("/+$", "") + "/api/chat"))
					.header("Content-Type", "application/json")
					.timeout(Duration.ofSeconds(300))
					.POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOllamaResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.debug("Ollama chat API call failed", e);
			throw new AiAnalysisException("Ollama API call failed: " + e.getMessage());
		}
	}

	private String handleOllamaResponse(HttpResponse<String> response) throws AiAnalysisException {
		int status = response.statusCode();

		if (status == 404) {
			throw new AiAnalysisException("Ollama model not found (HTTP 404). Pull the model first with 'ollama pull <model>'");
		} else if (status >= 500) {
			throw new AiAnalysisException("Ollama server error (HTTP " + status + ")");
		} else if (status != 200) {
			throw new AiAnalysisException("Ollama API error (HTTP " + status + "): " + response.body());
		}

		try {
			JsonNode root = mapper.readTree(response.body());
			JsonNode message = root.path("message");
			if (message.has("content")) {
				return message.path("content").asText("");
			}
			throw new AiAnalysisException("Unexpected Ollama response format");
		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			throw new AiAnalysisException("Failed to parse Ollama response: " + e.getMessage());
		}
	}

	/**
	 * Parse a structured AI response into the given parent section node.
	 * Detects {@code [Section Name]} delimiters and routes lines prefixed
	 * with {@code CRITICAL:} or {@code WARNING:} to WARNING nodes.
	 *
	 * @param parentSection the section node to populate (e.g. "AI Evaluation")
	 * @param analysis      the raw AI response text
	 */
	public static void parseAiResponse(ScanNode parentSection, String analysis) {
		parseAiResponse(parentSection, analysis, java.util.Map.of());
	}

	/**
	 * Parse a structured AI response into the given parent section node,
	 * using a severity map to color-code subsection headers that reference
	 * risk rule IDs.
	 *
	 * @param parentSection the section node to populate (e.g. "AI Evaluation")
	 * @param analysis      the raw AI response text
	 * @param severityMap   mapping of rule ID prefix (e.g. "SYS-0000900") to severity
	 */
	public static void parseAiResponse(ScanNode parentSection, String analysis,
			java.util.Map<String, String> severityMap) {
		if (analysis == null || analysis.isEmpty()) {
			return;
		}

		// Pattern: ID [SEVERITY] description — used for both headers and content lines
		java.util.regex.Pattern riskPattern = java.util.regex.Pattern.compile(
				"^(\\S+)\\s+\\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)]\\s+(.+)$");

		// Pattern to extract a bare rule ID (no inline severity) at the start
		java.util.regex.Pattern ruleIdPattern = java.util.regex.Pattern.compile(
				"^(\\S+-\\S+)\\s.*");

		ScanNode currentSub = null;
		for (String line : analysis.split("\n")) {
			String trimmed = line.trim();

			if (trimmed.isEmpty()) {
				continue;
			}

			// Detect [Section Name] delimiter
			if (trimmed.startsWith("[") && trimmed.endsWith("]") && trimmed.length() > 2) {
				String name = trimmed.substring(1, trimmed.length() - 1).trim();
				if (!name.isEmpty()) {
					// Try inline severity first: "SYS-0000900 [LOW] description"
					String severity = null;
					java.util.regex.Matcher inlineMatcher = riskPattern.matcher(name);
					if (inlineMatcher.matches()) {
						severity = inlineMatcher.group(2);
					} else {
						// Fall back to severity map lookup by rule ID
						java.util.regex.Matcher idMatcher = ruleIdPattern.matcher(name);
						if (idMatcher.matches()) {
							severity = severityMap.get(idMatcher.group(1));
							// Reformat "ID - description" to "ID [SEVERITY] description"
							if (severity != null) {
								String ruleId = idMatcher.group(1);
								String rest = name.substring(ruleId.length()).trim();
								if (rest.startsWith("-")) {
									rest = rest.substring(1).trim();
								}
								name = ruleId + " [" + severity + "] " + rest;
							}
						}
					}
					currentSub = parentSection.addSubsection(name, severity);
					continue;
				}
			}

			// Route content to current subsection, or section if no delimiter yet
			ScanNode target = currentSub != null ? currentSub : parentSection;

			// Match risk-format lines with severity for colored rendering
			java.util.regex.Matcher riskMatcher = riskPattern.matcher(trimmed);
			if (riskMatcher.matches()) {
				String severity = riskMatcher.group(2);
				target.addWarning(trimmed, severity);
			} else if (trimmed.startsWith("CRITICAL:") || trimmed.startsWith("WARNING:")) {
				target.addWarning(trimmed);
			} else {
				target.addContent(trimmed);
			}
		}
	}

	/**
	 * Exception for AI analysis failures (auth, rate limit, network, parse).
	 */
	public static class AiAnalysisException extends Exception {
		public AiAnalysisException(String message) {
			super(message);
		}

		public AiAnalysisException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
