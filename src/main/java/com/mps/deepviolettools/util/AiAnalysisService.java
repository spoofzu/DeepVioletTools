package com.mps.deepviolettools.util;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.mps.deepviolettools.model.ScanNode;

/**
 * DVT-local AI response parsing utilities.
 * <p>
 * The AI HTTP client, model discovery, and configuration have moved to
 * the DeepViolet API ({@code com.mps.deepviolet.api.ai.AiAnalysisService}).
 * This class retains only the {@code parseAiResponse()} methods which
 * depend on the DVT-specific {@link ScanNode} model.
 *
 * @author Milton Smith
 */
public class AiAnalysisService {

	/**
	 * Parse a structured AI response into the given parent section node.
	 * Detects {@code [Section Name]} delimiters and routes lines prefixed
	 * with {@code CRITICAL:} or {@code WARNING:} to WARNING nodes.
	 *
	 * @param parentSection the section node to populate (e.g. "AI Evaluation")
	 * @param analysis      the raw AI response text
	 */
	public static void parseAiResponse(ScanNode parentSection, String analysis) {
		parseAiResponse(parentSection, analysis, Map.of());
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
			Map<String, String> severityMap) {
		if (analysis == null || analysis.isEmpty()) {
			return;
		}

		// Pattern: ID [SEVERITY] description — used for both headers and content lines
		Pattern riskPattern = Pattern.compile(
				"^(\\S+)\\s+\\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)]\\s+(.+)$");

		// Pattern to extract a bare rule ID (no inline severity) at the start
		Pattern ruleIdPattern = Pattern.compile(
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
					Matcher inlineMatcher = riskPattern.matcher(name);
					if (inlineMatcher.matches()) {
						severity = inlineMatcher.group(2);
					} else {
						// Fall back to severity map lookup by rule ID
						Matcher idMatcher = ruleIdPattern.matcher(name);
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
			Matcher riskMatcher = riskPattern.matcher(trimmed);
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
}
