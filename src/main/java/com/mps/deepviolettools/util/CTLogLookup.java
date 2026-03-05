package com.mps.deepviolettools.util;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Looks up CT (Certificate Transparency) log metadata by LogID.
 * Downloads Google's published CT log list and builds an in-memory
 * index keyed by Base64-encoded LogID.
 *
 * @author Milton Smith
 */
public class CTLogLookup {

	private static final Logger logger = LoggerFactory.getLogger(CTLogLookup.class);

	private static final String LOG_LIST_URL =
			"https://www.gstatic.com/ct/log_list/v3/log_list.json";

	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

	/**
	 * Metadata about a single CT log.
	 */
	public record CTLogInfo(String description, String url, String state, String keyBase64) {

		/**
		 * Format the log description for display.
		 */
		public String toDisplayString() {
			return description;
		}

		/**
		 * Decode the Base64-encoded public key into a {@link PublicKey}.
		 * Tries EC first (most CT logs use ECDSA), then RSA.
		 *
		 * @return the public key, or null if parsing fails
		 */
		public PublicKey getPublicKey() {
			if (keyBase64 == null) {
				return null;
			}
			try {
				byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
				X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
				try {
					return KeyFactory.getInstance("EC").generatePublic(spec);
				} catch (Exception e) {
					return KeyFactory.getInstance("RSA").generatePublic(spec);
				}
			} catch (Exception e) {
				logger.debug("Failed to parse CT log public key for {}: {}", description, e.getMessage());
				return null;
			}
		}
	}

	private final Map<String, CTLogInfo> logIndex;

	/**
	 * Create a new CTLogLookup, immediately downloading and parsing the log list.
	 * If the download fails, the lookup will return null for all queries.
	 */
	public CTLogLookup() {
		this.logIndex = downloadAndParse();
	}

	/**
	 * Look up a CT log by its Base64-encoded LogID.
	 *
	 * @param logId Base64-encoded LogID (e.g. "DleUvPOuqT4z...")
	 * @return log info, or null if not found or log list unavailable
	 */
	public CTLogInfo lookup(String logId) {
		if (logId == null || logIndex == null) {
			return null;
		}
		return logIndex.get(logId);
	}

	/**
	 * @return true if the log list was successfully loaded
	 */
	public boolean isLoaded() {
		return logIndex != null;
	}

	/**
	 * Download Google's CT log list and build the LogID index.
	 *
	 * @return map of Base64 LogID to CTLogInfo, or null on failure
	 */
	private static Map<String, CTLogInfo> downloadAndParse() {
		try {
			HttpClient client = HttpClient.newBuilder()
					.connectTimeout(CONNECT_TIMEOUT)
					.build();

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(LOG_LIST_URL))
					.timeout(REQUEST_TIMEOUT)
					.GET()
					.build();

			HttpResponse<String> response = client.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() != 200) {
				logger.warn("CT log list download failed, HTTP {}", response.statusCode());
				return null;
			}

			return parseLogList(response.body());

		} catch (Exception e) {
			logger.warn("Failed to download CT log list: {}", e.getMessage());
			return null;
		}
	}

	/**
	 * Parse the JSON log list into a LogID-keyed map.
	 */
	private static Map<String, CTLogInfo> parseLogList(String json) {
		Map<String, CTLogInfo> index = new HashMap<>();
		try {
			JsonObject root = JsonParser.parseString(json).getAsJsonObject();
			if (!root.has("operators") || !root.get("operators").isJsonArray()) {
				return index;
			}
			JsonArray operators = root.getAsJsonArray("operators");

			for (JsonElement operator : operators) {
				JsonObject op = operator.getAsJsonObject();
				parseLogArray(op.has("logs") ? op.getAsJsonArray("logs") : null, index);
				parseLogArray(op.has("tiled_logs") ? op.getAsJsonArray("tiled_logs") : null, index);
			}

			logger.info("CT log list loaded: {} logs indexed", index.size());

		} catch (Exception e) {
			logger.warn("Failed to parse CT log list: {}", e.getMessage());
		}
		return index;
	}

	/**
	 * Parse a "logs" or "tiled_logs" JSON array and add entries to the index.
	 */
	private static void parseLogArray(JsonArray logsNode, Map<String, CTLogInfo> index) {
		if (logsNode == null) {
			return;
		}
		for (JsonElement elem : logsNode) {
			JsonObject log = elem.getAsJsonObject();
			String logId = textOrNull(log, "log_id");
			String description = textOrNull(log, "description");
			String url = textOrNull(log, "url");
			String state = extractState(log.has("state") ? log.getAsJsonObject("state") : null);
			String key = textOrNull(log, "key");

			if (logId != null && description != null) {
				index.put(logId, new CTLogInfo(description, url, state, key));
			}
		}
	}

	/**
	 * Extract the state name from the state object.
	 * The state is an object with a single key that is the state name,
	 * e.g. {"usable": {"timestamp": "..."}}.
	 */
	private static String extractState(JsonObject stateNode) {
		if (stateNode == null) {
			return "unknown";
		}
		var keys = stateNode.keySet();
		if (!keys.isEmpty()) {
			return keys.iterator().next();
		}
		return "unknown";
	}

	/**
	 * Safely extract a text value from a JSON object field.
	 */
	private static String textOrNull(JsonObject node, String field) {
		if (!node.has(field) || node.get(field).isJsonNull()) {
			return null;
		}
		JsonElement child = node.get(field);
		return child.isJsonPrimitive() ? child.getAsString() : null;
	}
}
