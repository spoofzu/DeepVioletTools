package com.mps.deepviolettools.util;

import java.awt.Color;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolettools.job.UIBackgroundScanTask;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.model.CipherDelta;
import com.mps.deepviolettools.model.DeltaDirection;
import com.mps.deepviolettools.model.DeltaHeatMapBuilder;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.model.FingerprintDelta;
import com.mps.deepviolettools.model.HostDelta;
import com.mps.deepviolettools.model.MapDelta;
import com.mps.deepviolettools.model.RiskDelta;
import com.mps.deepviolettools.model.ScanNode;
import com.mps.deepviolettools.model.SharedRiskAnalysis;

/**
 * Shared report export logic for text, HTML, and PDF formats.
 * Used by both the GUI (MainFrm) and CLI (StartCMD).
 *
 * @author Milton Smith
 */
public class ReportExporter {

	private static final String[] BANNER_LINES = {
		"",
		"  ██████  ███████ ███████ ██████  ██    ██ ██  ██████  ██      ███████ ████████",
		"  ██   ██ ██      ██      ██   ██ ██    ██ ██ ██    ██ ██      ██         ██   ",
		"  ██   ██ █████   █████   ██████  ██    ██ ██ ██    ██ ██      █████      ██   ",
		"  ██   ██ ██      ██      ██       ██  ██  ██ ██    ██ ██      ██         ██   ",
		"  ██████  ███████ ███████ ██        ████   ██  ██████  ███████ ███████    ██    ",
		"",
	};

	/** Magic header bytes for encrypted .dvscan files: "DVSC". */
	static final byte[] DVSCAN_MAGIC = { 0x44, 0x56, 0x53, 0x43 };

	/** Current format version for encrypted .dvscan files. */
	static final byte DVSCAN_VERSION = 0x01;

	/** Header size: 4 (magic) + 1 (version) = 5 bytes. */
	static final int DVSCAN_HEADER_SIZE = 5;

	private ReportExporter() {
	}

	/**
	 * Build the standard report banner as plain text lines.
	 * Matches the single-scan notice header produced by UIBackgroundScanTask.
	 */
	public static String buildBannerText(String reportType) {
		StringBuilder sb = new StringBuilder();
		for (String line : BANNER_LINES) {
			sb.append(line).append('\n');
		}
		sb.append("  ").append(reportType).append('\n');
		sb.append("  Report Generated On ").append(new java.util.Date()).append('\n');
		sb.append('\n');
		sb.append("  This software is provided for research purposes.").append('\n');
		sb.append("  See project information on GitHub for further details:").append('\n');
		sb.append("    https://github.com/spoofzu/DeepVioletTools").append('\n');
		sb.append("    https://github.com/spoofzu/DeepViolet").append('\n');
		sb.append('\n');
		return sb.toString();
	}

	/**
	 * Write the standard report banner to a PDF document (themed).
	 */
	private static void writePdfBanner(com.lowagie.text.Document pdfDoc,
			String reportType, float fontSize, float leading,
			FontPreferences prefs) throws com.lowagie.text.DocumentException {
		writePdfBanner(pdfDoc, reportType, fontSize, leading,
				prefs.getNotice(), prefs);
	}

	/**
	 * Write the standard report banner to a PDF document with explicit color.
	 */
	private static void writePdfBanner(com.lowagie.text.Document pdfDoc,
			String reportType, float fontSize, float leading,
			Color noticeColor, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		for (String line : BANNER_LINES) {
			addPdfLine(pdfDoc, line, fontSize, leading, noticeColor, true);
		}
		addPdfLine(pdfDoc, "  " + reportType, fontSize, leading, noticeColor, false);
		addPdfLine(pdfDoc, "  Report Generated On " + new java.util.Date(),
				fontSize, leading, noticeColor, false);
		if (prefs != null) {
			addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
		} else {
			addPdfLine(pdfDoc, " ", fontSize, leading, noticeColor, false);
		}
		addPdfLine(pdfDoc, "  This software is provided for research purposes.",
				fontSize, leading, noticeColor, false);
		addPdfLine(pdfDoc, "  See project information on GitHub for further details:",
				fontSize, leading, noticeColor, false);
		addPdfLine(pdfDoc, "    https://github.com/spoofzu/DeepVioletTools",
				fontSize, leading, noticeColor, false);
		addPdfLine(pdfDoc, "    https://github.com/spoofzu/DeepViolet",
				fontSize, leading, noticeColor, false);
		if (prefs != null) {
			addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
		} else {
			addPdfLine(pdfDoc, " ", fontSize, leading, noticeColor, false);
		}
	}

	/**
	 * Write the standard report banner as HTML.
	 */
	private static void writeHtmlBanner(PrintWriter p, String reportType,
			String noticeColor) {
		for (String line : BANNER_LINES) {
			p.println("<span style=\"color:" + noticeColor + ";font-weight:bold\">"
					+ escapeHtml(line) + "</span>");
		}
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "  " + escapeHtml(reportType) + "</span>");
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "  Report Generated On " + escapeHtml(new java.util.Date().toString())
				+ "</span>");
		p.println("");
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "  This software is provided for research purposes.</span>");
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "  See project information on GitHub for further details:</span>");
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "    https://github.com/spoofzu/DeepVioletTools</span>");
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "    https://github.com/spoofzu/DeepViolet</span>");
		p.println("");
	}

	/**
	 * Save the scan result tree as plain ASCII text.
	 */
	public static void saveAsText(File file, ScanNode root) throws IOException {
		try (PrintWriter p = new PrintWriter(file)) {
			p.print(toPlainText(root));
		}
	}

	/**
	 * Render a ScanNode tree to plain text.
	 */
	public static String toPlainText(ScanNode root) {
		StringBuilder sb = new StringBuilder();
		root.walkVisible(node -> {
			String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
			switch (node.getType()) {
				case SECTION:
					sb.append("\n[").append(node.getKey()).append("]\n");
					break;
				case SUBSECTION:
					sb.append(indent).append(node.getKey()).append(":\n");
					break;
				case KEY_VALUE:
					sb.append(indent).append(node.getKey()).append("=")
					  .append(node.getValue()).append("\n");
					break;
				case WARNING:
					sb.append(indent).append(node.getKey()).append("\n");
					break;
				case NOTICE:
					sb.append(node.getKey()).append("\n");
					break;
				case CONTENT:
					sb.append(indent).append(node.getKey()).append("\n");
					break;
				case BLANK:
					sb.append("\n");
					break;
				default:
					break;
			}
		});
		return sb.toString();
	}

	// ---- JSON export ----

	/**
	 * Save the scan result tree as structured JSON.
	 */
	public static void saveAsJson(File file, ScanNode root) throws IOException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (FileWriter writer = new FileWriter(file)) {
			gson.toJson(toJsonMap(root), writer);
		}
	}

	/**
	 * Render a ScanNode tree to a JSON string.
	 */
	public static String toJsonString(ScanNode root) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		return gson.toJson(toJsonMap(root));
	}

	/**
	 * Convert a ScanNode tree to a nested Map structure suitable for
	 * JSON serialization. Sections become top-level keys, subsections
	 * become nested objects, key-value pairs become properties, and
	 * warnings/content become arrays.
	 */
	public static Map<String, Object> toJsonMap(ScanNode root) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("report_version", UIBackgroundScanTask.REPORT_VERSION);

		// Save top-level NOTICE and BLANK nodes (banner) so they survive round-trip
		List<Map<String, String>> preamble = new ArrayList<>();
		for (ScanNode child : root.getChildren()) {
			if (child.getType() == ScanNode.NodeType.NOTICE) {
				Map<String, String> entry = new LinkedHashMap<>();
				entry.put("type", "NOTICE");
				entry.put("text", child.getKey());
				preamble.add(entry);
			} else if (child.getType() == ScanNode.NodeType.BLANK) {
				Map<String, String> entry = new LinkedHashMap<>();
				entry.put("type", "BLANK");
				preamble.add(entry);
			}
		}
		if (!preamble.isEmpty()) {
			result.put("_preamble", preamble);
		}

		for (ScanNode section : root.getChildren()) {
			if (section.getType() == ScanNode.NodeType.SECTION) {
				result.put(section.getKey(), buildSectionMap(section));
			}
		}
		return result;
	}

	private static Map<String, Object> buildSectionMap(ScanNode section) {
		Map<String, Object> map = new LinkedHashMap<>();
		List<Object> warnings = new ArrayList<>();
		List<String> content = new ArrayList<>();

		for (ScanNode child : section.getChildren()) {
			switch (child.getType()) {
				case KEY_VALUE:
					map.put(child.getKey(), child.getValue());
					break;
				case SUBSECTION:
					map.put(child.getKey(), buildSectionMap(child));
					break;
				case WARNING:
					if (child.getSeverity() != null) {
						Map<String, String> warnObj = new LinkedHashMap<>();
						warnObj.put("text", child.getKey());
						warnObj.put("severity", child.getSeverity());
						warnings.add(warnObj);
					} else {
						warnings.add(child.getKey());
					}
					break;
				case NOTICE:
				case CONTENT:
					content.add(child.getKey());
					break;
				default:
					break;
			}
		}

		if (!warnings.isEmpty()) {
			map.put("_warnings", warnings);
		}
		if (!content.isEmpty()) {
			map.put("_content", content);
		}
		return map;
	}

	// ---- HTML export ----

	/**
	 * Save the scan result tree as a themed HTML file.
	 */
	public static void saveAsHtml(File file, ScanNode root,
			FontPreferences prefs) throws IOException {
		try (PrintWriter p = new PrintWriter(file, "UTF-8")) {
			p.println("<!DOCTYPE html>");
			p.println("<html>");
			p.println("<head>");
			p.println("<meta charset=\"UTF-8\">");
			p.println("<title>DeepViolet Scan Report</title>");
			p.println("<style>");
			p.println("body { font-family: " + prefs.getFont().getFamily() + ", monospace; ");
			p.println("       font-size: " + prefs.getFont().getSize() + "px;");
			p.println("       background-color: " + toHtmlColor(prefs.getBackground()) + ";");
			p.println("       color: " + toHtmlColor(prefs.getDefaultText()) + "; }");
			p.println("pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; }");
			p.println(".heading { color: " + toHtmlColor(prefs.getHeading()) + "; font-weight: bold; }");
			p.println(".notice { color: " + toHtmlColor(prefs.getNotice()) + "; font-weight: bold; }");
			p.println(".warning { color: " + toHtmlColor(prefs.getWarning()) + "; font-weight: bold; }");
			p.println(".key { color: " + toHtmlColor(prefs.getKey()) + "; }");
			p.println(".value { color: " + toHtmlColor(prefs.getValue()) + "; }");
			p.println(".subsection { color: " + toHtmlColor(prefs.getSubsection()) + "; font-weight: bold; }");
			p.println(".content { color: " + toHtmlColor(prefs.getContent()) + "; }");
			p.println(".bar-pass { color: " + toHtmlColor(prefs.getRiskPass()) + "; }");
			p.println(".bar-inconclusive { color: " + toHtmlColor(prefs.getRiskInconclusive()) + "; }");
			p.println(".bar-fail { color: " + toHtmlColor(prefs.getRiskFail()) + "; }");
			p.println("</style>");
			p.println("</head>");
			p.println("<body>");
			p.println("<pre>");

			boolean wrap = prefs.isHardwrapEnabled();
			int wrapWidth = prefs.getHardwrapWidth();

			root.walkVisible(node -> {
				String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
				switch (node.getType()) {
					case NOTICE:
						p.println("<span class=\"notice\">" + escapeHtml(node.getKey()) + "</span>");
						break;
					case SECTION:
						p.println("");
						p.println("<span class=\"heading\">[" + escapeHtml(node.getKey()) + "]</span>");
						break;
					case SUBSECTION:
						p.print(htmlWrappedSingle(indent + node.getKey() + ":",
							indent + "   ", wrap, wrapWidth, "subsection"));
						break;
					case KEY_VALUE:
						String kvLine = indent + node.getKey() + "=" + node.getValue();
						if (wrap && kvLine.length() > wrapWidth) {
							p.print(htmlWrappedKeyValue(indent, node.getKey(),
									node.getValue(), indent + "   ", wrapWidth));
						} else {
							p.println("<span class=\"key\">" + indent + escapeHtml(node.getKey())
									+ "</span>=<span class=\"value\">"
									+ escapeHtml(node.getValue()) + "</span>");
						}
						break;
					case WARNING:
						p.print(htmlWrappedSingle(indent + node.getKey(),
								indent + "   ", wrap, wrapWidth, "warning"));
						break;
					case CONTENT:
						String contentLine = indent + node.getKey();
						if (containsBarChars(contentLine)) {
							p.println(htmlBarLine(contentLine));
						} else {
							p.print(htmlWrappedSingle(contentLine,
									indent + "   ", wrap, wrapWidth, "content"));
						}
						break;
					case BLANK:
						p.println("");
						break;
					default:
						break;
				}
			});

			p.println("</pre>");
			p.println("</body>");
			p.println("</html>");
		}
	}

	// ---- PDF export ----

	/**
	 * Save the scan result tree as a themed PDF file.
	 */
	public static void saveAsPdf(File file, ScanNode root,
			FontPreferences prefs) throws IOException {
		com.lowagie.text.Document pdfDoc = new com.lowagie.text.Document(
				com.lowagie.text.PageSize.A4, 36, 36, 36, 36);
		try {
			Color bgColor = prefs.getBackground();
			com.lowagie.text.pdf.PdfWriter writer =
					com.lowagie.text.pdf.PdfWriter.getInstance(pdfDoc,
							new java.io.FileOutputStream(file));

			writer.setPageEvent(new com.lowagie.text.pdf.PdfPageEventHelper() {
				@Override
				public void onStartPage(com.lowagie.text.pdf.PdfWriter w,
						com.lowagie.text.Document d) {
					com.lowagie.text.pdf.PdfContentByte cb = w.getDirectContentUnder();
					cb.setColorFill(bgColor);
					cb.rectangle(0, 0,
							d.getPageSize().getWidth(), d.getPageSize().getHeight());
					cb.fill();
				}
			});

			pdfDoc.open();

			boolean wrap = prefs.isHardwrapEnabled();
			int wrapWidth = prefs.getHardwrapWidth();

			float availableWidth = com.lowagie.text.PageSize.A4.getWidth() - 72;
			int targetChars = wrap ? wrapWidth : 120;
			final float fontSize = Math.max(availableWidth / (targetChars * 0.6f), 6f);
			final float leading = fontSize * 1.15f;

			root.walkVisible(node -> {
				try {
					String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
					switch (node.getType()) {
						case NOTICE:
							addPdfWrappedSingle(pdfDoc, node.getKey(), "   ",
									wrap, wrapWidth, fontSize, leading,
									prefs.getNotice(), true);
							break;
						case SECTION:
							addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
							addPdfLine(pdfDoc, "[" + node.getKey() + "]", fontSize,
									leading, prefs.getHeading(), true);
							break;
						case SUBSECTION:
							addPdfWrappedSingle(pdfDoc, indent + node.getKey() + ":",
									indent + "   ", wrap, wrapWidth, fontSize, leading,
									prefs.getSubsection(), true);
							break;
						case KEY_VALUE:
							String kvLine = indent + node.getKey() + "=" + node.getValue();
							if (wrap && kvLine.length() > wrapWidth) {
								String prefix = indent + node.getKey() + "=";
								addPdfWrappedKeyValue(pdfDoc, prefix,
										node.getValue(), indent + "   ",
										wrapWidth, fontSize, leading, prefs);
							} else {
								addPdfKeyValue(pdfDoc, indent + node.getKey(),
										node.getValue(), fontSize, leading, prefs);
							}
							break;
						case WARNING:
							addPdfWrappedSingle(pdfDoc, indent + node.getKey(),
									indent + "   ", wrap, wrapWidth, fontSize, leading,
									prefs.getWarning(), true);
							break;
						case CONTENT:
							String pdfContent = indent + node.getKey();
							if (containsBarChars(pdfContent)) {
								addPdfBarLine(pdfDoc, pdfContent, fontSize, leading, prefs);
							} else {
								addPdfWrappedSingle(pdfDoc, pdfContent,
										indent + "   ", wrap, wrapWidth, fontSize, leading,
										prefs.getContent(), false);
							}
							break;
						case BLANK:
							addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
							break;
						default:
							break;
					}
				} catch (com.lowagie.text.DocumentException e) {
					throw new RuntimeException(e);
				}
			});
		} catch (com.lowagie.text.DocumentException e) {
			throw new IOException("Failed to write PDF: " + e.getMessage(), e);
		} catch (RuntimeException e) {
			if (e.getCause() instanceof com.lowagie.text.DocumentException) {
				throw new IOException("Failed to write PDF: " + e.getCause().getMessage(), e.getCause());
			}
			throw e;
		} finally {
			pdfDoc.close();
		}
	}

	// ---- bar helpers ----

	private static boolean containsBarChars(String text) {
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c == '\u2588' || c == '\u2590' || c == '\u2591') return true;
		}
		return false;
	}

	static String htmlBarLine(String text) {
		StringBuilder sb = new StringBuilder();
		int i = 0;
		while (i < text.length()) {
			char c = text.charAt(i);
			if (c == '\u2588' || c == '\u2590' || c == '\u2591') {
				int start = i;
				while (i < text.length() && text.charAt(i) == c) i++;
				String cssClass;
				if (c == '\u2588') {
					cssClass = "bar-pass";
				} else if (c == '\u2590') {
					cssClass = "bar-inconclusive";
				} else {
					cssClass = "bar-fail";
				}
				String solid = "\u2588".repeat(i - start);
				sb.append("<span class=\"").append(cssClass).append("\">")
				  .append(escapeHtml(solid)).append("</span>");
			} else {
				int start = i;
				while (i < text.length() && text.charAt(i) != '\u2588'
						&& text.charAt(i) != '\u2590' && text.charAt(i) != '\u2591') {
					i++;
				}
				sb.append("<span class=\"content\">")
				  .append(escapeHtml(text.substring(start, i))).append("</span>");
			}
		}
		return sb.toString();
	}

	// ---- HTML helpers ----

	static String toHtmlColor(Color c) {
		return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
	}

	static String escapeHtml(String text) {
		return text.replace("&", "&amp;")
				   .replace("<", "&lt;")
				   .replace(">", "&gt;")
				   .replace("\"", "&quot;");
	}

	static String htmlWrappedSingle(String text, String contIndent,
			boolean wrap, int wrapWidth, String cssClass) {
		StringBuilder sb = new StringBuilder();
		if (!wrap || text.length() <= wrapWidth) {
			sb.append("<span class=\"").append(cssClass).append("\">")
			  .append(escapeHtml(text)).append("</span>\n");
			return sb.toString();
		}
		int pos = 0;
		boolean first = true;
		while (pos < text.length()) {
			int available = first ? wrapWidth : wrapWidth - contIndent.length();
			if (available <= 0) available = 20;
			int remaining = text.length() - pos;
			int end;
			if (remaining <= available) {
				end = text.length();
			} else {
				end = pos + findBreakPoint(text.substring(pos), available);
			}
			String segment = text.substring(pos, end);
			if (!first) {
				segment = contIndent + segment.trim();
			}
			sb.append("<span class=\"").append(cssClass).append("\">")
			  .append(escapeHtml(segment)).append("</span>\n");
			pos = end;
			first = false;
		}
		return sb.toString();
	}

	static String htmlWrappedKeyValue(String indent, String key, String value,
			String contIndent, int wrapWidth) {
		StringBuilder sb = new StringBuilder();
		String prefix = indent + key + "=";
		String fullLine = prefix + value;

		if (fullLine.length() <= wrapWidth) {
			sb.append("<span class=\"key\">").append(escapeHtml(indent + key))
			  .append("</span>=<span class=\"value\">").append(escapeHtml(value))
			  .append("</span>\n");
			return sb.toString();
		}

		int firstValueLen = wrapWidth - prefix.length();
		if (firstValueLen <= 0) {
			sb.append("<span class=\"key\">").append(escapeHtml(indent + key))
			  .append("</span>=\n");
			htmlValueContinuation(sb, value, contIndent, wrapWidth);
			return sb.toString();
		}

		int end = findBreakPoint(value, firstValueLen);
		sb.append("<span class=\"key\">").append(escapeHtml(indent + key))
		  .append("</span>=<span class=\"value\">").append(escapeHtml(value.substring(0, end)))
		  .append("</span>\n");

		if (end < value.length()) {
			htmlValueContinuation(sb, value.substring(end).trim(), contIndent, wrapWidth);
		}
		return sb.toString();
	}

	static void htmlValueContinuation(StringBuilder sb, String text,
			String contIndent, int wrapWidth) {
		int pos = 0;
		int lineLen = wrapWidth - contIndent.length();
		if (lineLen <= 0) lineLen = 20;
		while (pos < text.length()) {
			int remaining = text.length() - pos;
			int end;
			if (remaining <= lineLen) {
				end = text.length();
			} else {
				end = pos + findBreakPoint(text.substring(pos), lineLen);
			}
			String segment = text.substring(pos, end).trim();
			if (!segment.isEmpty()) {
				sb.append("<span class=\"value\">")
				  .append(escapeHtml(contIndent + segment))
				  .append("</span>\n");
			}
			pos = end;
		}
	}

	// ---- PDF helpers ----

	/**
	 * Render a bar line in PDF with per-character coloring for pass/inconclusive/fail blocks.
	 * Uses the sanitized ASCII equivalents since Courier doesn't support Unicode blocks.
	 */
	private static void addPdfBarLine(com.lowagie.text.Document pdfDoc, String text,
			float fontSize, float leading, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		com.lowagie.text.Paragraph para = new com.lowagie.text.Paragraph(leading);
		para.setSpacingBefore(0);
		para.setSpacingAfter(0);

		int i = 0;
		while (i < text.length()) {
			char c = text.charAt(i);
			if (c == '\u2588' || c == '\u2590' || c == '\u2591') {
				int start = i;
				while (i < text.length() && text.charAt(i) == c) i++;
				Color color;
				if (c == '\u2588') {
					color = prefs.getRiskPass();         // pass
				} else if (c == '\u2590') {
					color = prefs.getRiskInconclusive(); // inconclusive
				} else {
					color = prefs.getRiskFail();         // fail
				}
				com.lowagie.text.Font font = new com.lowagie.text.Font(
						com.lowagie.text.Font.COURIER, fontSize,
						com.lowagie.text.Font.NORMAL, color);
				String solid = "\u2588".repeat(i - start);
				para.add(new com.lowagie.text.Chunk(
						sanitizeForPdf(solid), font));
			} else {
				int start = i;
				while (i < text.length() && text.charAt(i) != '\u2588'
						&& text.charAt(i) != '\u2590' && text.charAt(i) != '\u2591') {
					i++;
				}
				com.lowagie.text.Font font = new com.lowagie.text.Font(
						com.lowagie.text.Font.COURIER, fontSize,
						com.lowagie.text.Font.NORMAL, prefs.getContent());
				para.add(new com.lowagie.text.Chunk(text.substring(start, i), font));
			}
		}
		pdfDoc.add(para);
	}

	/**
	 * Replace Unicode block-drawing characters with ASCII equivalents for PDF.
	 * The built-in Courier font does not support these characters, causing
	 * garbled output. Uses visually distinct substitutions so risk graph
	 * pass/fail bars remain distinguishable.
	 */
	private static String sanitizeForPdf(String text) {
		return text.replace('\u2588', '#')  // █ (pass)         → #
				   .replace('\u2590', '?')  // ▐ (inconclusive) → ?
				   .replace('\u2591', '-')  // ░ (fail)         → -
				   .replace('\u2593', '='); // ▓ (banner)
	}

	private static void addPdfLine(com.lowagie.text.Document pdfDoc, String text,
			float fontSize, float leading, Color color, boolean bold)
			throws com.lowagie.text.DocumentException {
		int style = bold ? com.lowagie.text.Font.BOLD : com.lowagie.text.Font.NORMAL;
		com.lowagie.text.Font font = new com.lowagie.text.Font(
				com.lowagie.text.Font.COURIER, fontSize, style, color);
		com.lowagie.text.Paragraph para = new com.lowagie.text.Paragraph(
				leading, sanitizeForPdf(text), font);
		para.setSpacingBefore(0);
		para.setSpacingAfter(0);
		pdfDoc.add(para);
	}

	private static void addPdfBlankLine(com.lowagie.text.Document pdfDoc,
			float fontSize, float leading, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		com.lowagie.text.Font font = new com.lowagie.text.Font(
				com.lowagie.text.Font.COURIER, fontSize, com.lowagie.text.Font.NORMAL,
				prefs.getDefaultText());
		com.lowagie.text.Paragraph para = new com.lowagie.text.Paragraph(leading, " ", font);
		para.setSpacingBefore(0);
		para.setSpacingAfter(0);
		pdfDoc.add(para);
	}

	private static void addPdfKeyValue(com.lowagie.text.Document pdfDoc, String key,
			String value, float fontSize, float leading, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		com.lowagie.text.Font keyFont = new com.lowagie.text.Font(
				com.lowagie.text.Font.COURIER, fontSize, com.lowagie.text.Font.NORMAL,
				prefs.getKey());
		com.lowagie.text.Font eqFont = new com.lowagie.text.Font(
				com.lowagie.text.Font.COURIER, fontSize, com.lowagie.text.Font.NORMAL,
				prefs.getContent());
		com.lowagie.text.Font valFont = new com.lowagie.text.Font(
				com.lowagie.text.Font.COURIER, fontSize, com.lowagie.text.Font.NORMAL,
				prefs.getValue());

		com.lowagie.text.Paragraph para = new com.lowagie.text.Paragraph(leading);
		para.setSpacingBefore(0);
		para.setSpacingAfter(0);
		para.add(new com.lowagie.text.Chunk(key, keyFont));
		para.add(new com.lowagie.text.Chunk("=", eqFont));
		para.add(new com.lowagie.text.Chunk(value, valFont));
		pdfDoc.add(para);
	}

	private static void addPdfWrappedSingle(com.lowagie.text.Document pdfDoc,
			String text, String contIndent, boolean wrap, int wrapWidth,
			float fontSize, float leading, Color color, boolean bold)
			throws com.lowagie.text.DocumentException {
		if (!wrap || text.length() <= wrapWidth) {
			addPdfLine(pdfDoc, text, fontSize, leading, color, bold);
			return;
		}
		int pos = 0;
		boolean first = true;
		while (pos < text.length()) {
			int available = first ? wrapWidth : wrapWidth - contIndent.length();
			if (available <= 0) available = 20;
			int remaining = text.length() - pos;
			int end;
			if (remaining <= available) {
				end = text.length();
			} else {
				end = pos + findBreakPoint(text.substring(pos), available);
			}
			String segment = text.substring(pos, end);
			if (!first) {
				segment = contIndent + segment.trim();
			}
			addPdfLine(pdfDoc, segment, fontSize, leading, color, bold);
			pos = end;
			first = false;
		}
	}

	private static void addPdfWrappedKeyValue(com.lowagie.text.Document pdfDoc,
			String prefix, String value, String contIndent, int wrapWidth,
			float fontSize, float leading, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		String keyPart = prefix.substring(0, prefix.length() - 1);

		int firstValueLen = wrapWidth - prefix.length();
		if (firstValueLen <= 0) {
			addPdfKeyValue(pdfDoc, keyPart, "", fontSize, leading, prefs);
			addPdfValueContinuation(pdfDoc, value, contIndent, wrapWidth,
					fontSize, leading, prefs);
			return;
		}

		int end = findBreakPoint(value, firstValueLen);
		addPdfKeyValue(pdfDoc, keyPart, value.substring(0, end), fontSize, leading, prefs);

		if (end < value.length()) {
			addPdfValueContinuation(pdfDoc, value.substring(end).trim(),
					contIndent, wrapWidth, fontSize, leading, prefs);
		}
	}

	private static void addPdfValueContinuation(com.lowagie.text.Document pdfDoc,
			String text, String contIndent, int wrapWidth,
			float fontSize, float leading, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		int pos = 0;
		int lineLen = wrapWidth - contIndent.length();
		if (lineLen <= 0) lineLen = 20;
		while (pos < text.length()) {
			int remaining = text.length() - pos;
			int end;
			if (remaining <= lineLen) {
				end = text.length();
			} else {
				end = pos + findBreakPoint(text.substring(pos), lineLen);
			}
			String segment = text.substring(pos, end).trim();
			if (!segment.isEmpty()) {
				addPdfLine(pdfDoc, contIndent + segment, fontSize, leading,
						prefs.getValue(), false);
			}
			pos = end;
		}
	}

	// ---- shared wrapping helpers ----

	/**
	 * Find a suitable break point within maxLen characters of text.
	 * Prefers breaking at comma or space boundaries. For colon-delimited
	 * hex strings, breaks after a complete octet boundary.
	 */
	static int findBreakPoint(String text, int maxLen) {
		if (text.length() <= maxLen) {
			return text.length();
		}
		int lastComma = text.lastIndexOf(',', maxLen);
		int lastSpace = text.lastIndexOf(' ', maxLen);
		int breakAt = Math.max(lastComma, lastSpace);
		if (breakAt > 20) {
			return breakAt + 1;
		}
		int lastColon = text.lastIndexOf(':', maxLen);
		if (lastColon > 0) {
			char before = text.charAt(lastColon - 1);
			if (isHexDigit(before)) {
				return lastColon + 1;
			}
		}
		return maxLen;
	}

	private static boolean isHexDigit(char c) {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	}

	// ---- Scan export methods ----

	/**
	 * Render a HeatMapData object to plain text using percentage display.
	 */
	public static String heatMapToText(com.mps.deepviolettools.model.HeatMapData heatMap) {
		StringBuilder sb = new StringBuilder();
		if (heatMap == null || heatMap.getRows().isEmpty()) {
			sb.append("  (no data)\n");
			return sb.toString();
		}

		int nBlocks = heatMap.getNBlocks();
		int colWidth = 7;

		// Fixed label column width so all sections align
		int maxLabelLen = 50;

		// Column numbers header row
		sb.append("  ");
		for (int pad = 0; pad < maxLabelLen; pad++) sb.append(' ');
		sb.append("  ");
		for (int c = 1; c <= nBlocks; c++) {
			sb.append(String.format("%" + colWidth + "d", c));
		}
		sb.append('\n');

		// Precompute host-start columns for '.' boundary logic
		int totalHosts = heatMap.getTotalHosts();
		java.util.Set<Integer> hostStartCols = new java.util.HashSet<>();
		if (totalHosts > 0 && totalHosts < nBlocks) {
			for (int h = 0; h < totalHosts; h++) {
				hostStartCols.add(h * nBlocks / totalHosts);
			}
		}

		com.mps.deepviolettools.model.HeatMapData.MapType mapType = heatMap.getMapType();

		for (com.mps.deepviolettools.model.HeatMapData.HeatMapRow row : heatMap.getRows()) {
			// Row label
			String label = row.getDescription() != null ? row.getDescription() : row.getId();
			if (row.getQualifier() != null) {
				label = label + " (" + row.getQualifier() + ")";
			}
			if (label.length() > 50) label = label.substring(0, 47) + "...";
			sb.append("  ");
			sb.append(label);
			for (int pad = label.length(); pad < maxLabelLen; pad++) sb.append(' ');
			sb.append("  ");

			// Cells — percentage display; use '.' for repeated values
			com.mps.deepviolettools.model.HeatMapData.HeatMapCell[] cells = row.getCells();
			String prevDisplay = null;
			for (int col = 0; col < nBlocks; col++) {
				boolean isErrorCol = heatMap.hasErrorColumn(col);
				String display = com.mps.deepviolettools.model.HeatMapData.cellPercentageText(
						cells[col], mapType, isErrorCol);
				boolean isHostBoundary = col > 0 && hostStartCols.contains(col);
				if (col > 0 && display.equals(prevDisplay) && !isHostBoundary) {
					sb.append(String.format("%" + colWidth + "s", "."));
				} else {
					sb.append(String.format("%" + colWidth + "s", display));
				}
				prevDisplay = display;
			}
			sb.append('\n');
		}

		// Legend
		String legend = com.mps.deepviolettools.model.HeatMapData.legendText(
				mapType, totalHosts, nBlocks,
				heatMap.getHostsPerBlock(), heatMap.getBlocksPerHost());
		sb.append("\n").append(legend).append("\n");

		return sb.toString();
	}

	// ---- Host Index helpers ----

	/**
	 * Extract a compact display name from a target URL by stripping the
	 * {@code https://} scheme, trailing {@code /}, and the default port
	 * {@code :443}. Non-default ports are preserved.
	 *
	 * @param targetUrl the full URL (e.g. {@code https://example.com:443/})
	 * @return compact form (e.g. {@code example.com})
	 */
	public static String displayName(String targetUrl) {
		if (targetUrl == null) return "";
		String s = targetUrl;
		if (s.startsWith("https://")) s = s.substring(8);
		else if (s.startsWith("http://")) s = s.substring(7);
		if (s.endsWith("/")) s = s.substring(0, s.length() - 1);
		if (s.endsWith(":443")) s = s.substring(0, s.length() - 4);
		return s;
	}

	/**
	 * Build the body text (without the {@code [Host Index]} header) of the
	 * host-to-column mapping for a scan result.
	 *
	 * @param result  the scan result
	 * @param nBlocks the number of heat map columns
	 * @return formatted body text, or empty string if there are no results
	 */
	public static String buildHostIndexBody(
			com.mps.deepviolettools.model.ScanResult result, int nBlocks) {
		List<com.mps.deepviolettools.model.ScanResult.HostResult> hosts =
				result.getResults();
		int totalHosts = hosts.size();
		if (totalHosts == 0) return "";

		StringBuilder sb = new StringBuilder();

		if (totalHosts <= nBlocks) {
			// Case A — few hosts: each host owns a column range
			int colWidth = String.valueOf(nBlocks).length();
			for (int i = 0; i < totalHosts; i++) {
				int[] range = com.mps.deepviolettools.model.HeatMapData
						.assignBlockRange(i, totalHosts, nBlocks);
				int startCol = range[0] + 1; // 1-based
				int endCol = range[1] + 1;
				String name = displayName(hosts.get(i).getTargetUrl());
				if (startCol == endCol) {
					sb.append(String.format("  Col %" + colWidth + "d  %s%n",
							startCol, name));
				} else {
					sb.append(String.format("  Col %" + colWidth + "d-%"
							+ colWidth + "d  %s%n", startCol, endCol, name));
				}
			}
		} else {
			// Case B — many hosts: column mapping + host directory
			sb.append(String.format(
					"  Column Mapping (%d hosts across %d columns):%n",
					totalHosts, nBlocks));

			// Column mapping — 4 entries per line
			int colsPerLine = 4;
			StringBuilder lineBuf = new StringBuilder();
			for (int col = 0; col < nBlocks; col++) {
				// Find host range for this column
				int firstHost = -1, lastHost = -1;
				for (int h = 0; h < totalHosts; h++) {
					int block = com.mps.deepviolettools.model.HeatMapData
							.assignBlock(h, totalHosts, nBlocks);
					if (block == col) {
						if (firstHost == -1) firstHost = h + 1; // 1-based
						lastHost = h + 1;
					}
				}
				String entry;
				if (firstHost == -1) {
					entry = String.format("Col %2d: (empty)", col + 1);
				} else if (firstHost == lastHost) {
					entry = String.format("Col %2d: #%d", col + 1, firstHost);
				} else {
					entry = String.format("Col %2d: #%d-#%d",
							col + 1, firstHost, lastHost);
				}
				if (lineBuf.length() > 0) lineBuf.append("      ");
				lineBuf.append(String.format("%-20s", entry));

				if ((col + 1) % colsPerLine == 0 || col == nBlocks - 1) {
					sb.append("  ").append(lineBuf.toString().stripTrailing())
					  .append('\n');
					lineBuf.setLength(0);
				}
			}

			// Host directory
			sb.append('\n');
			sb.append("  Host Directory:\n");

			int maxNameLen = 0;
			for (com.mps.deepviolettools.model.ScanResult.HostResult hr : hosts) {
				maxNameLen = Math.max(maxNameLen, displayName(hr.getTargetUrl()).length());
			}

			int dirCols;
			if (maxNameLen <= 15) dirCols = 4;
			else if (maxNameLen <= 25) dirCols = 3;
			else dirCols = 2;

			int idWidth = String.valueOf(totalHosts).length();
			int entryWidth = idWidth + 1 + maxNameLen + 3; // "#NNN hostname   "

			lineBuf.setLength(0);
			for (int i = 0; i < totalHosts; i++) {
				String name = displayName(hosts.get(i).getTargetUrl());
				String entry = String.format("#%-" + idWidth + "d %s", i + 1, name);
				if (lineBuf.length() > 0) lineBuf.append("   ");
				lineBuf.append(String.format("%-" + entryWidth + "s", entry));

				if ((i + 1) % dirCols == 0 || i == totalHosts - 1) {
					sb.append("  ").append(lineBuf.toString().stripTrailing())
					  .append('\n');
					lineBuf.setLength(0);
				}
			}
		}

		return sb.toString();
	}

	/**
	 * Build the full host index section including the
	 * {@code [Host Index]} header.
	 *
	 * @param result  the scan result
	 * @param nBlocks the number of heat map columns
	 * @return the complete section text, or empty string if no results
	 */
	public static String buildHostIndex(
			com.mps.deepviolettools.model.ScanResult result, int nBlocks) {
		String body = buildHostIndexBody(result, nBlocks);
		if (body.isEmpty()) return "";
		return "[Host Index]\n" + body;
	}

	/**
	 * Save scan results as plain text with all sections (CLI usage).
	 */
	public static void saveScanAsText(File file,
			com.mps.deepviolettools.model.ScanResult result,
			int nBlocks) throws IOException {
		saveScanAsText(file, result, nBlocks, FontPreferences.load());
	}

	/**
	 * Save scan results as plain text, respecting section preferences.
	 */
	public static void saveScanAsText(File file,
			com.mps.deepviolettools.model.ScanResult result,
			int nBlocks, FontPreferences prefs) throws IOException {
		List<String> titles = new ArrayList<>();
		List<com.mps.deepviolettools.model.HeatMapData> maps = new ArrayList<>();
		buildFilteredSections(result, nBlocks, prefs, titles, maps);

		try (PrintWriter p = new PrintWriter(file)) {
			p.print(buildBannerText("DeepViolet Scan Report"));
			p.print(buildProvenanceText(result));
			p.println("Total targets: " + result.getTotalTargets());
			p.println("Successful: " + result.getSuccessCount());
			p.println("Errors: " + result.getErrorCount());
			p.println();

			String hostIndex = buildHostIndex(result, nBlocks);
			if (!hostIndex.isEmpty()) {
				p.print(hostIndex);
				p.println();
			}

			for (int i = 0; i < titles.size(); i++) {
				p.println(titles.get(i));
				p.println("-".repeat(titles.get(i).length()));
				p.print(heatMapToText(maps.get(i)));
				p.println();
			}

			// Error summary
			boolean hasErrors = false;
			for (com.mps.deepviolettools.model.ScanResult.HostResult hr : result.getResults()) {
				if (!hr.isSuccess()) {
					if (!hasErrors) {
						p.println("Error Summary");
						p.println("-------------");
						hasErrors = true;
					}
					p.println("  " + hr.getTargetUrl() + ": " + hr.getErrorMessage());
				}
			}
		}
	}

	/**
	 * Build filtered section titles and heat maps based on preferences.
	 */
	private static void buildFilteredSections(
			com.mps.deepviolettools.model.ScanResult result, int nBlocks,
			FontPreferences prefs,
			List<String> titles,
			List<com.mps.deepviolettools.model.HeatMapData> maps) {
		if (prefs.isScanSectionRiskAssessment()) {
			titles.add("TLS Risk Assessment");
			maps.add(result.toRiskHeatMap(nBlocks));
		}
		if (prefs.isScanSectionSecurityHeaders()) {
			titles.add("Security Headers Analysis");
			maps.add(result.toSecurityHeadersHeatMap(nBlocks));
		}
		if (prefs.isScanSectionHttpResponse()) {
			titles.add("HTTP Response Headers");
			maps.add(result.toHttpResponseHeatMap(nBlocks));
		}
		if (prefs.isScanSectionConnection()) {
			titles.add("Connection Characteristics");
			maps.add(result.toConnectionHeatMap(nBlocks));
		}
		if (prefs.isScanSectionCipherSuites()) {
			titles.add("Cipher Suites");
			maps.add(result.toCipherHeatMap(nBlocks));
		}
		if (prefs.isScanSectionRevocation()) {
			titles.add("Revocation Status");
			maps.add(result.toRevocationHeatMap(nBlocks));
		}
		if (prefs.isScanSectionTlsFingerprint()) {
			titles.add("TLS Fingerprint");
			maps.add(result.toFingerprintHeatMap(nBlocks));
		}
	}

	/**
	 * Save scan results as HTML with colored heat map tables.
	 */
	public static void saveScanAsHtml(File file,
			com.mps.deepviolettools.model.ScanResult result,
			int nBlocks) throws IOException {
		FontPreferences prefs = FontPreferences.load();
		try (PrintWriter p = new PrintWriter(file, "UTF-8")) {
			p.println("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">");
			p.println("<title>DeepViolet Scan Report</title>");
			p.println("<style>");
			p.println("body { font-family: monospace; background: " + toHtmlColor(prefs.getBackground()) + "; color: " + toHtmlColor(prefs.getDefaultText()) + "; }");
			p.println("table.heatmap { border-collapse: collapse; margin: 10px 0; }");
			p.println("table.heatmap td { width: 20px; height: 18px; border: 1px solid #333; }");
			p.println("table.heatmap th { text-align: left; padding: 2px 8px; font-size: 11px; }");
			p.println(".cat-header { background: #333; color: #fff; font-weight: bold; padding: 4px 8px; }");
			p.println("h2 { color: " + toHtmlColor(prefs.getHeading()) + "; }");
			p.println(".error { color: " + toHtmlColor(prefs.getWarning()) + "; }");
			p.println("</style></head><body>");
			p.println("<pre>");
			writeHtmlBanner(p, "DeepViolet Scan Report",
					toHtmlColor(prefs.getNotice()));
			writeHtmlProvenance(p, result, toHtmlColor(prefs.getNotice()));
			p.println("</pre>");
			p.println("<p>Total: " + result.getTotalTargets() + " | Success: " + result.getSuccessCount() + " | Errors: " + result.getErrorCount() + "</p>");

			String hostIdxBody = buildHostIndexBody(result, nBlocks);
			if (!hostIdxBody.isEmpty()) {
				p.println("<h2>Host Index</h2>");
				p.println("<pre>" + escapeHtml(hostIdxBody) + "</pre>");
			}

			Color passColor = prefs.getRiskPass();
			Color failColor = prefs.getRiskFail();
			Color incColor = prefs.getRiskInconclusive();

			writeHtmlHeatMap(p, "TLS Risk Assessment", result.toRiskHeatMap(nBlocks), passColor, failColor, incColor);
			writeHtmlHeatMap(p, "Security Headers Analysis", result.toSecurityHeadersHeatMap(nBlocks), passColor, failColor, incColor);
			writeHtmlHeatMap(p, "HTTP Response Headers", result.toHttpResponseHeatMap(nBlocks), passColor, failColor, incColor);
			writeHtmlHeatMap(p, "Connection Characteristics", result.toConnectionHeatMap(nBlocks), passColor, failColor, incColor);
			writeHtmlHeatMap(p, "Cipher Suites", result.toCipherHeatMap(nBlocks), passColor, failColor, incColor);
			writeHtmlHeatMap(p, "Revocation Status", result.toRevocationHeatMap(nBlocks), passColor, failColor, incColor);
			writeHtmlHeatMap(p, "TLS Fingerprint", result.toFingerprintHeatMap(nBlocks), passColor, failColor, incColor);

			// Error summary
			boolean hasErrors = false;
			for (com.mps.deepviolettools.model.ScanResult.HostResult hr : result.getResults()) {
				if (!hr.isSuccess()) {
					if (!hasErrors) {
						p.println("<h2>Errors</h2><ul>");
						hasErrors = true;
					}
					p.println("<li class=\"error\">" + escapeHtml(hr.getTargetUrl()) + ": " + escapeHtml(hr.getErrorMessage()) + "</li>");
				}
			}
			if (hasErrors) p.println("</ul>");

			p.println("</body></html>");
		}
	}

	private static void writeHtmlHeatMap(PrintWriter p, String title,
			com.mps.deepviolettools.model.HeatMapData heatMap,
			Color passColor, Color failColor, Color incColor) {
		p.println("<h2>" + escapeHtml(title) + "</h2>");
		if (heatMap == null || heatMap.getRows().isEmpty()) {
			p.println("<p>(no data)</p>");
			return;
		}
		p.println("<table class=\"heatmap\">");
		String lastCat = null;
		int nBlocks = heatMap.getNBlocks();
		for (int rowIdx = 0; rowIdx < heatMap.getRows().size(); rowIdx++) {
			com.mps.deepviolettools.model.HeatMapData.HeatMapRow row = heatMap.getRows().get(rowIdx);
			if (row.getCategory() != null && !row.getCategory().equals(lastCat)) {
				lastCat = row.getCategory();
				p.println("<tr><td colspan=\"" + (nBlocks + 1) + "\" class=\"cat-header\">" + escapeHtml(lastCat) + "</td></tr>");
			}
			p.print("<tr><th>" + escapeHtml(row.getDescription() != null ? row.getDescription() : row.getId()));
			if (row.getQualifier() != null) p.print(" <small>(" + escapeHtml(row.getQualifier()) + ")</small>");
			p.print("</th>");
			com.mps.deepviolettools.model.HeatMapData.MapType mapType = heatMap.getMapType();
			for (int col = 0; col < nBlocks; col++) {
				Color c = heatMap.getCellColor(rowIdx, col, passColor, failColor, incColor);
				com.mps.deepviolettools.model.HeatMapData.HeatMapCell cell = row.getCells()[col];
				boolean isErrorCol = heatMap.hasErrorColumn(col);
				String pctText = com.mps.deepviolettools.model.HeatMapData.cellPercentageText(cell, mapType, isErrorCol);
				String tooltip = pctText + " (P:" + cell.getPassCount() + " F:" + cell.getFailCount() + " I:" + cell.getInconclusiveCount() + ")";
				p.print("<td style=\"background:" + toHtmlColor(c) + "\" title=\"" + escapeHtml(tooltip) + "\"></td>");
			}
			p.println("</tr>");
		}
		p.println("</table>");
	}

	/**
	 * Write a heat map section in HTML &lt;pre&gt; format with colored percentage display.
	 */
	private static void writeHtmlHeatMapScored(PrintWriter p, String title,
			com.mps.deepviolettools.model.HeatMapData heatMap) {
		p.println("");
		p.println("<span class=\"heading\">[" + escapeHtml(title) + "]</span>");
		if (heatMap == null || heatMap.getRows().isEmpty()) {
			p.println("<span class=\"content\">  (no data)</span>");
			return;
		}

		int nBlocks = heatMap.getNBlocks();
		int colWidth = 7;

		// Fixed label column width so all sections align
		int maxLabelLen = 50;

		// Column numbers header
		StringBuilder colHeader = new StringBuilder("  ");
		for (int pad = 0; pad < maxLabelLen; pad++) colHeader.append(' ');
		colHeader.append("  ");
		for (int c = 1; c <= nBlocks; c++) colHeader.append(String.format("%" + colWidth + "d", c));
		p.println("<span class=\"content\">" + escapeHtml(colHeader.toString()) + "</span>");

		// Precompute host-start columns for '.' boundary logic
		int totalHosts = heatMap.getTotalHosts();
		java.util.Set<Integer> hostStartCols = new java.util.HashSet<>();
		if (totalHosts > 0 && totalHosts < nBlocks) {
			for (int h = 0; h < totalHosts; h++) {
				hostStartCols.add(h * nBlocks / totalHosts);
			}
		}

		com.mps.deepviolettools.model.HeatMapData.MapType mapType = heatMap.getMapType();

		for (com.mps.deepviolettools.model.HeatMapData.HeatMapRow row : heatMap.getRows()) {
			String label = row.getDescription() != null ? row.getDescription() : row.getId();
			if (row.getQualifier() != null) label = label + " (" + row.getQualifier() + ")";
			if (label.length() > 50) label = label.substring(0, 47) + "...";
			StringBuilder rowBuf = new StringBuilder("  ");
			rowBuf.append(label);
			for (int pad = label.length(); pad < maxLabelLen; pad++) rowBuf.append(' ');
			rowBuf.append("  ");
			p.print("<span class=\"content\">" + escapeHtml(rowBuf.toString()) + "</span>");

			com.mps.deepviolettools.model.HeatMapData.HeatMapCell[] cells = row.getCells();
			String prevDisplay = null;
			for (int col = 0; col < nBlocks; col++) {
				boolean isErrorCol = heatMap.hasErrorColumn(col);
				String display = com.mps.deepviolettools.model.HeatMapData.cellPercentageText(
						cells[col], mapType, isErrorCol);
				boolean isHostBoundary = col > 0 && hostStartCols.contains(col);

				int pct = 0;
				try { pct = Integer.parseInt(display.replaceAll("[^0-9]", "")); } catch (NumberFormatException ignored) {}
				boolean hasInconclusive = display.contains("I");
				Color sc = com.mps.deepviolettools.model.HeatMapData.percentageColor(pct, hasInconclusive, mapType);

				String formatted;
				if (col > 0 && display.equals(prevDisplay) && !isHostBoundary) {
					formatted = String.format("%" + colWidth + "s", ".");
				} else {
					formatted = String.format("%" + colWidth + "s", display);
				}
				p.print("<span style=\"color:" + toHtmlColor(sc) + "\">"
						+ escapeHtml(formatted) + "</span>");
				prevDisplay = display;
			}
			p.println("");
		}

		String legend = com.mps.deepviolettools.model.HeatMapData.legendText(
				mapType, totalHosts, nBlocks,
				heatMap.getHostsPerBlock(), heatMap.getBlocksPerHost());
		p.println("<span class=\"content\">");
		p.println(escapeHtml(legend) + "</span>");
	}

	/**
	 * Save scan results as a themed HTML file with colored heat map scores.
	 */
	public static void saveScanHostsAsHtml(File file,
			com.mps.deepviolettools.model.ScanResult result,
			FontPreferences prefs) throws IOException {
		int nBlocks = 20;
		try (PrintWriter p = new PrintWriter(file, "UTF-8")) {
			p.println("<!DOCTYPE html>");
			p.println("<html>");
			p.println("<head>");
			p.println("<meta charset=\"UTF-8\">");
			p.println("<title>DeepViolet Scan Report</title>");
			p.println("<style>");
			p.println("body { font-family: " + prefs.getFont().getFamily() + ", monospace; ");
			p.println("       font-size: " + prefs.getFont().getSize() + "px;");
			p.println("       background-color: " + toHtmlColor(prefs.getBackground()) + ";");
			p.println("       color: " + toHtmlColor(prefs.getDefaultText()) + "; }");
			p.println("pre { white-space: pre-wrap; word-wrap: break-word; margin: 0; }");
			p.println(".heading { color: " + toHtmlColor(prefs.getHeading()) + "; font-weight: bold; }");
			p.println(".subsection { color: " + toHtmlColor(prefs.getSubsection()) + "; font-weight: bold; }");
			p.println(".content { color: " + toHtmlColor(prefs.getContent()) + "; }");
			p.println(".warning { color: " + toHtmlColor(prefs.getWarning()) + "; font-weight: bold; }");
			p.println("</style>");
			p.println("</head>");
			p.println("<body>");
			p.println("<pre>");

			// Banner + summary header
			writeHtmlBanner(p, "DeepViolet Scan Report",
					toHtmlColor(prefs.getNotice()));
			String provText = buildProvenanceText(result);
			if (!provText.isEmpty()) {
				p.print("<span class=\"content\">" + escapeHtml(provText) + "</span>");
			}
			p.println("<span class=\"content\">Total targets: " + result.getTotalTargets()
					+ " | Successful: " + result.getSuccessCount()
					+ " | Errors: " + result.getErrorCount() + "</span>");
			p.println("");

			String hostIdxBody = buildHostIndexBody(result, nBlocks);
			if (!hostIdxBody.isEmpty()) {
				p.println("<span class=\"heading\">[Host Index]</span>");
				p.println("<span class=\"content\">" + escapeHtml(hostIdxBody) + "</span>");
			}

			List<String> titles = new ArrayList<>();
			List<com.mps.deepviolettools.model.HeatMapData> maps = new ArrayList<>();
			buildFilteredSections(result, nBlocks, prefs, titles, maps);

			for (int m = 0; m < titles.size(); m++) {
				writeHtmlHeatMapScored(p, titles.get(m), maps.get(m));
			}

			// Error summary
			boolean hasErrors = false;
			for (com.mps.deepviolettools.model.ScanResult.HostResult hr : result.getResults()) {
				if (!hr.isSuccess()) {
					if (!hasErrors) {
						p.println("");
						p.println("<span class=\"heading\">[Error Summary]</span>");
						hasErrors = true;
					}
					p.println("<span class=\"warning\">  " + escapeHtml(hr.getTargetUrl())
							+ ": " + escapeHtml(hr.getErrorMessage()) + "</span>");
				}
			}

			p.println("</pre>");
			p.println("</body>");
			p.println("</html>");
		}
	}

	/**
	 * Write tree nodes as HTML (shared by single-host and multi-host export).
	 */
	private static void writeHtmlTreeNodes(PrintWriter p, ScanNode root,
			boolean wrap, int wrapWidth) {
		root.walkVisible(node -> {
			String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
			switch (node.getType()) {
				case NOTICE:
					p.println("<span class=\"notice\">" + escapeHtml(node.getKey()) + "</span>");
					break;
				case SECTION:
					p.println("");
					p.println("<span class=\"heading\">[" + escapeHtml(node.getKey()) + "]</span>");
					break;
				case SUBSECTION:
					p.print(htmlWrappedSingle(indent + node.getKey() + ":",
						indent + "   ", wrap, wrapWidth, "subsection"));
					break;
				case KEY_VALUE:
					String kvLine = indent + node.getKey() + "=" + node.getValue();
					if (wrap && kvLine.length() > wrapWidth) {
						p.print(htmlWrappedKeyValue(indent, node.getKey(),
								node.getValue(), indent + "   ", wrapWidth));
					} else {
						p.println("<span class=\"key\">" + indent + escapeHtml(node.getKey())
								+ "</span>=<span class=\"value\">"
								+ escapeHtml(node.getValue()) + "</span>");
					}
					break;
				case WARNING:
					p.print(htmlWrappedSingle(indent + node.getKey(),
							indent + "   ", wrap, wrapWidth, "warning"));
					break;
				case CONTENT:
					String contentLine = indent + node.getKey();
					if (containsBarChars(contentLine)) {
						p.println(htmlBarLine(contentLine));
					} else {
						p.print(htmlWrappedSingle(contentLine,
								indent + "   ", wrap, wrapWidth, "content"));
					}
					break;
				case BLANK:
					p.println("");
					break;
				default:
					break;
			}
		});
	}

	/**
	 * Save scan results as a themed PDF file with colored heat map scores.
	 */
	public static void saveScanHostsAsPdf(File file,
			com.mps.deepviolettools.model.ScanResult result,
			FontPreferences prefs) throws IOException {
		int nBlocks = 20;
		com.lowagie.text.Document pdfDoc = new com.lowagie.text.Document(
				com.lowagie.text.PageSize.A4, 36, 36, 36, 36);
		try {
			Color bgColor = prefs.getBackground();
			com.lowagie.text.pdf.PdfWriter writer =
					com.lowagie.text.pdf.PdfWriter.getInstance(pdfDoc,
							new java.io.FileOutputStream(file));

			writer.setPageEvent(new com.lowagie.text.pdf.PdfPageEventHelper() {
				@Override
				public void onStartPage(com.lowagie.text.pdf.PdfWriter w,
						com.lowagie.text.Document d) {
					com.lowagie.text.pdf.PdfContentByte cb = w.getDirectContentUnder();
					cb.setColorFill(bgColor);
					cb.rectangle(0, 0,
							d.getPageSize().getWidth(), d.getPageSize().getHeight());
					cb.fill();
				}
			});

			pdfDoc.open();

			float availableWidth = com.lowagie.text.PageSize.A4.getWidth() - 72;
			final float fontSize = Math.max(availableWidth / (120 * 0.6f), 6f);
			final float leading = fontSize * 1.15f;

			// Banner + summary header
			writePdfBanner(pdfDoc, "DeepViolet Scan Report",
					fontSize, leading, prefs);
			writePdfProvenance(pdfDoc, result, fontSize, leading);
			addPdfLine(pdfDoc, "Total targets: " + result.getTotalTargets()
					+ " | Successful: " + result.getSuccessCount()
					+ " | Errors: " + result.getErrorCount(),
					fontSize, leading, prefs.getContent(), false);
			addPdfBlankLine(pdfDoc, fontSize, leading, prefs);

			String hostIdxBody = buildHostIndexBody(result, nBlocks);
			if (!hostIdxBody.isEmpty()) {
				addPdfLine(pdfDoc, "[Host Index]", fontSize, leading,
						prefs.getHeading(), true);
				for (String line : hostIdxBody.split("\n")) {
					addPdfLine(pdfDoc, line, fontSize, leading,
							prefs.getContent(), false);
				}
				addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
			}

			List<String> titles = new ArrayList<>();
			List<com.mps.deepviolettools.model.HeatMapData> maps = new ArrayList<>();
			buildFilteredSections(result, nBlocks, prefs, titles, maps);

			for (int m = 0; m < titles.size(); m++) {
				writePdfHeatMapScored(pdfDoc, titles.get(m), maps.get(m), fontSize, leading, prefs);
			}

			// Error summary
			boolean hasErrors = false;
			for (com.mps.deepviolettools.model.ScanResult.HostResult hr : result.getResults()) {
				if (!hr.isSuccess()) {
					if (!hasErrors) {
						addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
						addPdfLine(pdfDoc, "[Error Summary]", fontSize, leading,
								prefs.getHeading(), true);
						hasErrors = true;
					}
					addPdfLine(pdfDoc, "  " + hr.getTargetUrl() + ": " + hr.getErrorMessage(),
							fontSize, leading, prefs.getWarning(), false);
				}
			}
		} catch (com.lowagie.text.DocumentException e) {
			throw new IOException("Failed to write PDF: " + e.getMessage(), e);
		} catch (RuntimeException e) {
			if (e.getCause() instanceof com.lowagie.text.DocumentException) {
				throw new IOException("Failed to write PDF: " + e.getCause().getMessage(), e.getCause());
			}
			throw e;
		} finally {
			pdfDoc.close();
		}
	}

	/**
	 * Write tree nodes as PDF (shared by single-host and multi-host export).
	 */
	private static void writePdfTreeNodes(com.lowagie.text.Document pdfDoc, ScanNode root,
			boolean wrap, int wrapWidth, float fontSize, float leading,
			FontPreferences prefs) {
		root.walkVisible(node -> {
			try {
				String indent = "   ".repeat(Math.max(0, node.getLevel() - 1));
				switch (node.getType()) {
					case NOTICE:
						addPdfWrappedSingle(pdfDoc, node.getKey(), "   ",
								wrap, wrapWidth, fontSize, leading,
								prefs.getNotice(), true);
						break;
					case SECTION:
						addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
						addPdfLine(pdfDoc, "[" + node.getKey() + "]", fontSize,
								leading, prefs.getHeading(), true);
						break;
					case SUBSECTION:
						addPdfWrappedSingle(pdfDoc, indent + node.getKey() + ":",
								indent + "   ", wrap, wrapWidth, fontSize, leading,
								prefs.getSubsection(), true);
						break;
					case KEY_VALUE:
						String kvLine = indent + node.getKey() + "=" + node.getValue();
						if (wrap && kvLine.length() > wrapWidth) {
							String prefix = indent + node.getKey() + "=";
							addPdfWrappedKeyValue(pdfDoc, prefix,
									node.getValue(), indent + "   ",
									wrapWidth, fontSize, leading, prefs);
						} else {
							addPdfKeyValue(pdfDoc, indent + node.getKey(),
									node.getValue(), fontSize, leading, prefs);
						}
						break;
					case WARNING:
						addPdfWrappedSingle(pdfDoc, indent + node.getKey(),
								indent + "   ", wrap, wrapWidth, fontSize, leading,
								prefs.getWarning(), true);
						break;
					case CONTENT:
						String pdfContent = indent + node.getKey();
						if (containsBarChars(pdfContent)) {
							addPdfBarLine(pdfDoc, pdfContent, fontSize, leading, prefs);
						} else {
							addPdfWrappedSingle(pdfDoc, pdfContent,
									indent + "   ", wrap, wrapWidth, fontSize, leading,
									prefs.getContent(), false);
						}
						break;
					case BLANK:
						addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
						break;
					default:
						break;
				}
			} catch (com.lowagie.text.DocumentException e) {
				throw new RuntimeException(e);
			}
		});
	}

	/**
	 * Write a heat map section in PDF with colored percentage display.
	 */
	private static void writePdfHeatMapScored(com.lowagie.text.Document pdfDoc,
			String title, com.mps.deepviolettools.model.HeatMapData heatMap,
			float fontSize, float leading, FontPreferences prefs)
			throws com.lowagie.text.DocumentException {
		addPdfBlankLine(pdfDoc, fontSize, leading, prefs);
		addPdfLine(pdfDoc, "[" + title + "]", fontSize, leading, prefs.getHeading(), true);

		if (heatMap == null || heatMap.getRows().isEmpty()) {
			addPdfLine(pdfDoc, "  (no data)", fontSize, leading, prefs.getContent(), false);
			return;
		}

		int nBlocks = heatMap.getNBlocks();
		int colWidth = 7;

		// Precompute host-start columns for '.' boundary logic
		int totalHosts = heatMap.getTotalHosts();
		java.util.Set<Integer> hostStartCols = new java.util.HashSet<>();
		if (totalHosts > 0 && totalHosts < nBlocks) {
			for (int h = 0; h < totalHosts; h++) {
				hostStartCols.add(h * nBlocks / totalHosts);
			}
		}

		com.mps.deepviolettools.model.HeatMapData.MapType mapType = heatMap.getMapType();
		int maxLabelLen = 50;

		// Column numbers header row
		StringBuilder colHeader = new StringBuilder("  ");
		for (int pad = 0; pad < maxLabelLen; pad++) colHeader.append(' ');
		colHeader.append("  ");
		for (int c = 1; c <= nBlocks; c++) colHeader.append(String.format("%" + colWidth + "d", c));
		addPdfLine(pdfDoc, colHeader.toString(), fontSize, leading, prefs.getContent(), false);

		// Build the text as paragraphs with per-cell coloring
		for (com.mps.deepviolettools.model.HeatMapData.HeatMapRow row : heatMap.getRows()) {
			String label = row.getDescription() != null ? row.getDescription() : row.getId();
			if (row.getQualifier() != null) label = label + " (" + row.getQualifier() + ")";
			if (label.length() > 50) label = label.substring(0, 47) + "...";

			// Right-pad label to fixed width
			StringBuilder paddedLabel = new StringBuilder("  ");
			paddedLabel.append(label);
			for (int pad = label.length(); pad < maxLabelLen; pad++) paddedLabel.append(' ');
			paddedLabel.append("  ");

			com.lowagie.text.Paragraph para = new com.lowagie.text.Paragraph(leading);
			para.setSpacingBefore(0);
			para.setSpacingAfter(0);

			// Label
			com.lowagie.text.Font labelFont = new com.lowagie.text.Font(
					com.lowagie.text.Font.COURIER, fontSize,
					com.lowagie.text.Font.NORMAL, prefs.getContent());
			para.add(new com.lowagie.text.Chunk(paddedLabel.toString(), labelFont));

			// Cells — percentage display with '.' for repeated values
			com.mps.deepviolettools.model.HeatMapData.HeatMapCell[] cells = row.getCells();
			String prevDisplay = null;
			for (int col = 0; col < nBlocks; col++) {
				boolean isErrorCol = heatMap.hasErrorColumn(col);
				String display = com.mps.deepviolettools.model.HeatMapData.cellPercentageText(
						cells[col], mapType, isErrorCol);
				boolean isHostBoundary = col > 0 && hostStartCols.contains(col);

				int pct = 0;
				try { pct = Integer.parseInt(display.replaceAll("[^0-9]", "")); } catch (NumberFormatException ignored) {}
				boolean hasInconclusive = display.contains("I");
				Color sc = com.mps.deepviolettools.model.HeatMapData.percentageColor(pct, hasInconclusive, mapType);

				com.lowagie.text.Font scoreFont = new com.lowagie.text.Font(
						com.lowagie.text.Font.COURIER, fontSize,
						com.lowagie.text.Font.NORMAL, sc);

				String formatted;
				if (col > 0 && display.equals(prevDisplay) && !isHostBoundary) {
					formatted = String.format("%" + colWidth + "s", ".");
				} else {
					formatted = String.format("%" + colWidth + "s", display);
				}
				para.add(new com.lowagie.text.Chunk(formatted, scoreFont));
				prevDisplay = display;
			}
			pdfDoc.add(para);
		}

		String legend = com.mps.deepviolettools.model.HeatMapData.legendText(
				mapType, totalHosts, nBlocks,
				heatMap.getHostsPerBlock(), heatMap.getBlocksPerHost());
		addPdfLine(pdfDoc, legend, fontSize, leading, prefs.getContent(), false);
	}

	/**
	 * Save scan results as structured JSON.
	 */
	public static void saveScanAsJson(File file,
			com.mps.deepviolettools.model.ScanResult result) throws IOException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (FileWriter writer = new FileWriter(file)) {
			writer.write(buildScanJsonString(result, gson));
		}
	}

	/**
	 * Build the scan JSON string from a ScanResult.
	 */
	private static String buildScanJsonString(
			com.mps.deepviolettools.model.ScanResult result, Gson gson) {
		Map<String, Object> jsonMap = new LinkedHashMap<>();
		jsonMap.put("report_type", "scan");
		jsonMap.put("total_targets", result.getTotalTargets());
		jsonMap.put("success_count", result.getSuccessCount());
		jsonMap.put("error_count", result.getErrorCount());

		if (result.getScanId() != null) {
			jsonMap.put("scan_id", result.getScanId());
		}

		List<Map<String, Object>> hosts = new ArrayList<>();
		for (com.mps.deepviolettools.model.ScanResult.HostResult hr : result.getResults()) {
			Map<String, Object> hostMap = new LinkedHashMap<>();
			hostMap.put("target_url", hr.getTargetUrl());
			hostMap.put("success", hr.isSuccess());
			if (hr.getErrorMessage() != null) {
				hostMap.put("error", hr.getErrorMessage());
			}
			if (hr.getSecurityHeaders() != null) {
				hostMap.put("security_headers", hr.getSecurityHeaders());
			}
			if (hr.getConnProperties() != null) {
				hostMap.put("connection_properties", hr.getConnProperties());
			}
			if (hr.getHttpHeaders() != null) {
				hostMap.put("http_headers", hr.getHttpHeaders());
			}
			if (hr.getTlsFingerprint() != null) {
				hostMap.put("tls_fingerprint", hr.getTlsFingerprint());
			}
			if (hr.getRiskScore() != null) {
				Map<String, Object> risk = new LinkedHashMap<>();
				risk.put("total_score", hr.getRiskScore().getTotalScore());
				risk.put("letter_grade", hr.getRiskScore().getLetterGrade().name());
				risk.put("risk_level", hr.getRiskScore().getRiskLevel().name());

				IRiskScore.ICategoryScore[] catScores =
						hr.getRiskScore().getCategoryScores();
				if (catScores != null && catScores.length > 0) {
					List<Map<String, Object>> categories = new ArrayList<>();
					for (IRiskScore.ICategoryScore cs : catScores) {
						Map<String, Object> catMap = new LinkedHashMap<>();
						catMap.put("category_key", cs.getCategoryKey());
						catMap.put("display_name", cs.getDisplayName());
						catMap.put("score", cs.getScore());
						catMap.put("risk_level", cs.getRiskLevel().name());
						catMap.put("summary", cs.getSummary());

						IRiskScore.IDeduction[] deds = cs.getDeductions();
						if (deds != null && deds.length > 0) {
							List<Map<String, Object>> dedList = new ArrayList<>();
							for (IRiskScore.IDeduction d : deds) {
								Map<String, Object> dedMap = new LinkedHashMap<>();
								dedMap.put("rule_id", d.getRuleId());
								dedMap.put("description", d.getDescription());
								dedMap.put("score", d.getScore());
								dedMap.put("severity", d.getSeverity());
								dedMap.put("inconclusive", d.isInconclusive());
								dedList.add(dedMap);
							}
							catMap.put("deductions", dedList);
						}
						categories.add(catMap);
					}
					risk.put("categories", categories);
				}

				hostMap.put("risk_score", risk);
			}
			if (hr.getCiphers() != null) {
				List<Map<String, String>> cipherList = new ArrayList<>();
				for (ICipherSuite cs : hr.getCiphers()) {
					Map<String, String> c = new LinkedHashMap<>();
					c.put("name", cs.getSuiteName());
					c.put("strength", cs.getStrengthEvaluation());
					c.put("protocol", cs.getHandshakeProtocol());
					cipherList.add(c);
				}
				hostMap.put("ciphers", cipherList);
			}
			if (hr.getScanTree() != null) {
				hostMap.put("scan_report", toJsonMap(hr.getScanTree()));
			}
			if (hr.getRuleContextMap() != null) {
				hostMap.put("rule_context", hr.getRuleContextMap());
			}
			hosts.add(hostMap);
		}
		jsonMap.put("hosts", hosts);

		int nBlocks = 20;
		List<Map<String, Object>> hostIndex = new ArrayList<>();
		for (int i = 0; i < result.getResults().size(); i++) {
			Map<String, Object> entry = new LinkedHashMap<>();
			entry.put("index", i + 1);
			entry.put("host", displayName(result.getResults().get(i).getTargetUrl()));
			int[] range = com.mps.deepviolettools.model.HeatMapData
					.assignBlockRange(i, result.getResults().size(), nBlocks);
			if (range[0] == range[1]) {
				entry.put("columns", List.of(range[0] + 1));
			} else {
				entry.put("columns", List.of(range[0] + 1, range[1] + 1));
			}
			hostIndex.add(entry);
		}
		jsonMap.put("host_index", hostIndex);

		return gson.toJson(jsonMap);
	}

	/**
	 * Save scan results as a PDF with colored heat map tables.
	 */
	public static void saveScanAsPdf(File file,
			com.mps.deepviolettools.model.ScanResult result,
			int nBlocks, Color passColor, Color failColor,
			Color inconclusiveColor) throws IOException {
		com.lowagie.text.Document pdfDoc = new com.lowagie.text.Document(
				com.lowagie.text.PageSize.A4.rotate(), 36, 36, 36, 36);
		try {
			com.lowagie.text.pdf.PdfWriter.getInstance(pdfDoc,
					new java.io.FileOutputStream(file));
			pdfDoc.open();

			float fontSize = 8f;
			float leading = 10f;

			writePdfBanner(pdfDoc, "DeepViolet Scan Report",
					fontSize, leading, Color.BLACK, null);
			writePdfProvenance(pdfDoc, result, fontSize, leading);
			addPdfLine(pdfDoc, "Total: " + result.getTotalTargets()
					+ " | Success: " + result.getSuccessCount()
					+ " | Errors: " + result.getErrorCount(),
					fontSize, leading, Color.DARK_GRAY, false);

			String hostIdxBody = buildHostIndexBody(result, nBlocks);
			if (!hostIdxBody.isEmpty()) {
				addPdfLine(pdfDoc, "[Host Index]", 10f, 12f, Color.BLACK, true);
				for (String line : hostIdxBody.split("\n")) {
					addPdfLine(pdfDoc, line, fontSize, leading,
							Color.DARK_GRAY, false);
				}
			}

			String[] titles = {
				"TLS Risk Assessment", "Security Headers Analysis",
				"HTTP Response Headers", "Connection Characteristics", "Cipher Suites",
				"Revocation Status", "TLS Fingerprint"
			};
			com.mps.deepviolettools.model.HeatMapData[] maps = {
				result.toRiskHeatMap(nBlocks),
				result.toSecurityHeadersHeatMap(nBlocks),
				result.toHttpResponseHeatMap(nBlocks),
				result.toConnectionHeatMap(nBlocks),
				result.toCipherHeatMap(nBlocks),
				result.toRevocationHeatMap(nBlocks),
				result.toFingerprintHeatMap(nBlocks)
			};

			for (int m = 0; m < titles.length; m++) {
				pdfDoc.newPage();
				addPdfLine(pdfDoc, titles[m], 12f, 14f, Color.BLACK, true);
				addPdfHeatMapTable(pdfDoc, maps[m], passColor, failColor, inconclusiveColor);
			}

		} catch (com.lowagie.text.DocumentException e) {
			throw new IOException("Failed to write scan PDF: " + e.getMessage(), e);
		} finally {
			pdfDoc.close();
		}
	}

	private static void addPdfHeatMapTable(com.lowagie.text.Document pdfDoc,
			com.mps.deepviolettools.model.HeatMapData heatMap,
			Color passColor, Color failColor, Color incColor)
			throws com.lowagie.text.DocumentException {
		if (heatMap == null || heatMap.getRows().isEmpty()) {
			addPdfLine(pdfDoc, "(no data)", 8f, 10f, Color.GRAY, false);
			return;
		}

		int nBlocks = heatMap.getNBlocks();
		int cols = nBlocks + 1; // label + data columns
		com.lowagie.text.pdf.PdfPTable table = new com.lowagie.text.pdf.PdfPTable(cols);
		table.setWidthPercentage(100);

		// Set relative column widths: label column wider
		float[] widths = new float[cols];
		widths[0] = 40f;
		for (int i = 1; i < cols; i++) widths[i] = 1f;
		table.setWidths(widths);

		String lastCat = null;
		for (int rowIdx = 0; rowIdx < heatMap.getRows().size(); rowIdx++) {
			com.mps.deepviolettools.model.HeatMapData.HeatMapRow row = heatMap.getRows().get(rowIdx);

			if (row.getCategory() != null && !row.getCategory().equals(lastCat)) {
				lastCat = row.getCategory();
				com.lowagie.text.pdf.PdfPCell catCell = new com.lowagie.text.pdf.PdfPCell(
						new com.lowagie.text.Phrase(lastCat,
								new com.lowagie.text.Font(com.lowagie.text.Font.COURIER, 7f,
										com.lowagie.text.Font.BOLD, Color.WHITE)));
				catCell.setColspan(cols);
				catCell.setBackgroundColor(Color.DARK_GRAY);
				catCell.setPadding(3);
				table.addCell(catCell);
			}

			// Label cell
			String label = row.getDescription() != null ? row.getDescription() : row.getId();
			if (label.length() > 40) label = label.substring(0, 37) + "...";
			com.lowagie.text.pdf.PdfPCell labelCell = new com.lowagie.text.pdf.PdfPCell(
					new com.lowagie.text.Phrase(label,
							new com.lowagie.text.Font(com.lowagie.text.Font.COURIER, 6f)));
			labelCell.setPadding(1);
			table.addCell(labelCell);

			// Data cells
			for (int col = 0; col < nBlocks; col++) {
				Color c = heatMap.getCellColor(rowIdx, col, passColor, failColor, incColor);
				com.lowagie.text.pdf.PdfPCell dataCell = new com.lowagie.text.pdf.PdfPCell(
						new com.lowagie.text.Phrase(" "));
				dataCell.setBackgroundColor(c);
				dataCell.setPadding(0);
				table.addCell(dataCell);
			}
		}
		pdfDoc.add(table);
	}

	// ---- Scan load from JSON ----

	/**
	 * Load scan results from a JSON file previously saved by
	 * {@link #saveScanAsJson(File, ScanResult)}.
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO#fromJson(String)}.
	 */
	public static ScanResult loadScanFromJson(File file) throws IOException {
		String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
		com.mps.deepviolet.persist.ScanSnapshot snapshot =
				com.mps.deepviolet.persist.ScanFileIO.fromJson(json);
		return ScanResult.fromSnapshot(snapshot);
	}

	/**
	 * Load scan results from a JSON input stream (e.g. classpath resource).
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO#fromJson(java.io.InputStream)}.
	 */
	public static ScanResult loadScanFromJson(java.io.InputStream in) throws IOException {
		com.mps.deepviolet.persist.ScanSnapshot snapshot =
				com.mps.deepviolet.persist.ScanFileIO.fromJson(in);
		return ScanResult.fromSnapshot(snapshot);
	}

	// ---- Provenance ----

	/**
	 * Build a plain-text provenance section for scan reports.
	 * Returns an empty string if no provenance is available.
	 */
	public static String buildProvenanceText(ScanResult result) {
		String scanId = result.getScanId();
		if (scanId == null) return "";

		StringBuilder sb = new StringBuilder();
		sb.append("Provenance\n");
		sb.append("----------\n");
		sb.append("  Scan ID: ").append(scanId).append('\n');
		sb.append('\n');
		return sb.toString();
	}

	/**
	 * Write provenance information as HTML spans inside a {@code <pre>} block.
	 */
	static void writeHtmlProvenance(PrintWriter p,
			ScanResult result, String noticeColor) {
		String scanId = result.getScanId();
		if (scanId == null) return;

		p.println("<span style=\"color:" + noticeColor + ";font-weight:bold\">"
				+ "Provenance</span>");
		p.println("<span style=\"color:" + noticeColor + "\">"
				+ "  Scan ID: " + escapeHtml(scanId) + "</span>");
		p.println("");
	}

	/**
	 * Write provenance information as PDF lines.
	 */
	static void writePdfProvenance(com.lowagie.text.Document pdfDoc,
			ScanResult result, float fontSize, float leading)
			throws com.lowagie.text.DocumentException {
		String scanId = result.getScanId();
		if (scanId == null) return;

		addPdfLine(pdfDoc, "Provenance", fontSize, leading, Color.BLACK, true);
		addPdfLine(pdfDoc, "  Scan ID: " + scanId,
				fontSize, leading, Color.DARK_GRAY, false);
		addPdfLine(pdfDoc, " ", fontSize, leading, Color.DARK_GRAY, false);
	}

	// ---- Scan file (.dvscan) ----

	/**
	 * Save scan results using the specified encryption mode.
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO}.
	 *
	 * @param file     output file
	 * @param result   scan data to save
	 * @param mode     encryption mode (PLAIN_TEXT, HOST_LOCKED, PASSWORD_LOCKED)
	 * @param password transfer password (required for PASSWORD_LOCKED, ignored otherwise)
	 * @return scanId (SHA-256 hex of the written file)
	 * @throws IOException on write or encryption failure
	 */
	public static String saveScanFile(File file, ScanResult result,
			com.mps.deepviolet.persist.ScanFileMode mode, char[] password)
			throws IOException {
		byte[] key = null;
		if (mode != com.mps.deepviolet.persist.ScanFileMode.PLAIN_TEXT) {
			key = FontPreferences.getEncryptionSeed();
			if (key == null) {
				throw new IOException("Encryption seed not available. "
						+ "Call FontPreferences.ensureEncryptionSeed() first.");
			}
		}

		com.mps.deepviolet.persist.ScanSnapshot snapshot = result.toSnapshot();
		String scanId = com.mps.deepviolet.persist.ScanFileIO.save(
				file, snapshot, mode, key, password);
		result.setScanId(scanId);
		return scanId;
	}

	/**
	 * Save scan results as a host-locked .dvscan file (machine key only).
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO}.
	 *
	 * @return scanId (SHA-256 hex of the written file)
	 * @throws IOException if the encryption seed is not available or writing fails
	 */
	public static String saveScanFile(File file,
			ScanResult result) throws IOException {
		return saveScanFile(file, result,
				com.mps.deepviolet.persist.ScanFileMode.HOST_LOCKED, null);
	}

	/**
	 * Save scan results as an encrypted .dvscan file with optional
	 * password protection.
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO}.
	 *
	 * @return scanId (SHA-256 hex of the written file)
	 * @throws IOException if the encryption seed is not available or writing fails
	 */
	public static String saveScanFile(File file,
			ScanResult result, char[] password) throws IOException {
		com.mps.deepviolet.persist.ScanFileMode mode =
				(password != null && password.length > 0)
				? com.mps.deepviolet.persist.ScanFileMode.PASSWORD_LOCKED
				: com.mps.deepviolet.persist.ScanFileMode.HOST_LOCKED;
		return saveScanFile(file, result, mode, password);
	}

	/**
	 * Load scan results from an encrypted binary .dvscan file
	 * previously saved by {@link #saveScanFile(File, ScanResult)}.
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO}.
	 *
	 * @throws IOException if the file is invalid, tampered, or decryption fails
	 */
	public static ScanResult loadScanFile(File file) throws IOException {
		return loadScanFile(file, null);
	}

	/**
	 * Load scan results from an encrypted binary .dvscan file with optional
	 * password callback.
	 * Delegates to {@link com.mps.deepviolet.persist.ScanFileIO}.
	 *
	 * @throws IOException if the file is invalid, tampered, or decryption fails
	 */
	public static ScanResult loadScanFile(File file,
			com.mps.deepviolet.persist.ScanFileIO.PasswordCallback passwordCallback)
			throws IOException {
		byte[] key = FontPreferences.getEncryptionSeed();
		// key can be null — ScanFileIO handles null machine key for cross-machine load

		com.mps.deepviolet.persist.ScanSnapshot snapshot;
		if (passwordCallback != null) {
			snapshot = com.mps.deepviolet.persist.ScanFileIO.load(file, key, passwordCallback);
		} else {
			snapshot = com.mps.deepviolet.persist.ScanFileIO.load(file, key);
		}

		ScanResult result = ScanResult.fromSnapshot(snapshot);
		return result;
	}

	/**
	 * Reconstruct a {@link ScanNode} tree from a JSON map structure
	 * produced by {@link #toJsonMap(ScanNode)}.
	 */
	@SuppressWarnings("unchecked")
	public static ScanNode fromJsonMap(Map<String, Object> jsonMap) {
		ScanNode root = ScanNode.createRoot();

		// Restore preamble (banner NOTICE/BLANK nodes) if present
		Object preambleObj = jsonMap.get("_preamble");
		if (preambleObj instanceof List) {
			for (Object item : (List<?>) preambleObj) {
				if (item instanceof Map) {
					Map<String, String> entry = (Map<String, String>) item;
					String type = entry.get("type");
					if ("NOTICE".equals(type)) {
						root.addNotice(entry.getOrDefault("text", ""));
					} else if ("BLANK".equals(type)) {
						root.addBlank();
					}
				}
			}
		}

		for (Map.Entry<String, Object> entry : jsonMap.entrySet()) {
			String key = entry.getKey();
			if ("report_version".equals(key) || "_preamble".equals(key)) continue;

			if (entry.getValue() instanceof Map) {
				ScanNode section = root.addSection(key);
				populateSection(section, (Map<String, Object>) entry.getValue());
			}
		}
		return root;
	}

	@SuppressWarnings("unchecked")
	private static void populateSection(ScanNode parent, Map<String, Object> map) {
		for (Map.Entry<String, Object> entry : map.entrySet()) {
			String key = entry.getKey();
			Object val = entry.getValue();

			if ("_warnings".equals(key)) {
				for (Object item : (List<?>) val) {
					if (item instanceof Map) {
						@SuppressWarnings("unchecked")
						Map<String, Object> warnMap = (Map<String, Object>) item;
						String text = String.valueOf(warnMap.get("text"));
						String severity = warnMap.containsKey("severity")
								? String.valueOf(warnMap.get("severity")) : null;
						parent.addWarning(text, severity);
					} else {
						parent.addWarning(String.valueOf(item));
					}
				}
			} else if ("_content".equals(key)) {
				for (String c : (List<String>) val) {
					parent.addContent(c);
				}
			} else if (val instanceof Map) {
				ScanNode sub = parent.addSubsection(key);
				populateSection(sub, (Map<String, Object>) val);
			} else if (val instanceof String) {
				parent.addKeyValue(key, (String) val);
			} else if (val != null) {
				parent.addKeyValue(key, String.valueOf(val));
			}
		}
	}

	// ---- Card summary export ----

	/**
	 * Save a summary of visible host cards as plain text.
	 */
	public static void saveCardsAsText(File file, List<HostResult> hosts) throws IOException {
		try (PrintWriter pw = new PrintWriter(file)) {
			pw.print(buildBannerText("DeepViolet Card Summary"));
			pw.println("Hosts: " + hosts.size());
			pw.println();
			for (HostResult hr : hosts) {
				String host = displayName(hr.getTargetUrl());
				if (!hr.isSuccess()) {
					pw.println(host + "  [ERROR]  " + hr.getErrorMessage());
				} else {
					IRiskScore rs = hr.getRiskScore();
					String grade = (rs != null) ? rs.getLetterGrade().toDisplayString() : "?";
					String score = (rs != null) ? String.valueOf(rs.getTotalScore()) : "?";
					pw.println(host + "  Grade: " + grade + "  Score: " + score);
				}
			}
		}
	}

	/**
	 * Save a summary of visible host cards as an HTML file.
	 */
	public static void saveCardsAsHtml(File file, List<HostResult> hosts) throws IOException {
		try (PrintWriter p = new PrintWriter(file, "UTF-8")) {
			p.println("<!DOCTYPE html>");
			p.println("<html><head><meta charset=\"UTF-8\">");
			p.println("<title>DeepViolet Card Summary</title>");
			p.println("<style>");
			p.println("body { font-family: sans-serif; margin: 20px; }");
			p.println("table { border-collapse: collapse; width: 100%; }");
			p.println("th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }");
			p.println("th { background-color: #f0f0f0; }");
			p.println(".error { color: #c00; }");
			p.println("</style>");
			p.println("</head><body>");
			p.println("<h1>DeepViolet Card Summary</h1>");
			p.println("<p>Hosts: " + hosts.size() + " &mdash; Generated: "
					+ escapeHtml(new java.util.Date().toString()) + "</p>");
			p.println("<table>");
			p.println("<tr><th>Host</th><th>Grade</th><th>Score</th></tr>");
			for (HostResult hr : hosts) {
				String host = escapeHtml(displayName(hr.getTargetUrl()));
				if (!hr.isSuccess()) {
					p.println("<tr><td>" + host + "</td><td class=\"error\" colspan=\"2\">"
							+ escapeHtml(hr.getErrorMessage()) + "</td></tr>");
				} else {
					IRiskScore rs = hr.getRiskScore();
					String grade = (rs != null) ? escapeHtml(rs.getLetterGrade().toDisplayString()) : "?";
					String score = (rs != null) ? String.valueOf(rs.getTotalScore()) : "?";
					p.println("<tr><td>" + host + "</td><td>" + grade + "</td><td>"
							+ score + "</td></tr>");
				}
			}
			p.println("</table>");
			p.println("</body></html>");
		}
	}

	/**
	 * Save a summary of visible host cards as a PDF file.
	 */
	public static void saveCardsAsPdf(File file, List<HostResult> hosts) throws IOException {
		com.lowagie.text.Document pdfDoc = new com.lowagie.text.Document(
				com.lowagie.text.PageSize.A4, 36, 36, 36, 36);
		try {
			com.lowagie.text.pdf.PdfWriter.getInstance(pdfDoc,
					new java.io.FileOutputStream(file));
			pdfDoc.open();

			float fontSize = 10f;
			float leading = fontSize * 1.3f;

			// Title
			addPdfLine(pdfDoc, "DeepViolet Card Summary", fontSize + 4, leading + 4,
					java.awt.Color.BLACK, true);
			addPdfLine(pdfDoc, "Hosts: " + hosts.size() + "  Generated: "
					+ new java.util.Date(), fontSize, leading,
					java.awt.Color.DARK_GRAY, false);
			addPdfLine(pdfDoc, " ", fontSize, leading, java.awt.Color.BLACK, false);

			// Table
			com.lowagie.text.pdf.PdfPTable table = new com.lowagie.text.pdf.PdfPTable(3);
			table.setWidthPercentage(100);
			table.setWidths(new float[]{60, 15, 25});

			// Header row
			for (String header : new String[]{"Host", "Grade", "Score"}) {
				com.lowagie.text.pdf.PdfPCell cell = new com.lowagie.text.pdf.PdfPCell(
						new com.lowagie.text.Phrase(header,
								new com.lowagie.text.Font(
										com.lowagie.text.Font.COURIER, fontSize,
										com.lowagie.text.Font.BOLD)));
				cell.setBackgroundColor(new java.awt.Color(240, 240, 240));
				cell.setPadding(4);
				table.addCell(cell);
			}

			// Data rows
			for (HostResult hr : hosts) {
				String host = displayName(hr.getTargetUrl());
				if (!hr.isSuccess()) {
					table.addCell(new com.lowagie.text.Phrase(host,
							new com.lowagie.text.Font(
									com.lowagie.text.Font.COURIER, fontSize)));
					com.lowagie.text.pdf.PdfPCell errCell = new com.lowagie.text.pdf.PdfPCell(
							new com.lowagie.text.Phrase(hr.getErrorMessage(),
									new com.lowagie.text.Font(
											com.lowagie.text.Font.COURIER, fontSize,
											com.lowagie.text.Font.NORMAL,
											java.awt.Color.RED)));
					errCell.setColspan(2);
					table.addCell(errCell);
				} else {
					IRiskScore rs = hr.getRiskScore();
					String grade = (rs != null) ? rs.getLetterGrade().toDisplayString() : "?";
					String score = (rs != null) ? String.valueOf(rs.getTotalScore()) : "?";
					com.lowagie.text.Font cellFont = new com.lowagie.text.Font(
							com.lowagie.text.Font.COURIER, fontSize);
					table.addCell(new com.lowagie.text.Phrase(host, cellFont));
					table.addCell(new com.lowagie.text.Phrase(grade, cellFont));
					table.addCell(new com.lowagie.text.Phrase(score, cellFont));
				}
			}

			pdfDoc.add(table);
		} catch (com.lowagie.text.DocumentException e) {
			throw new IOException("Failed to write PDF: " + e.getMessage(), e);
		} finally {
			pdfDoc.close();
		}
	}

	// ---- Delta scan report methods ----

	/**
	 * Build the delta report banner with base and target scan file information.
	 */
	public static String buildDeltaBanner(DeltaScanResult result) {
		StringBuilder sb = new StringBuilder();
		for (String line : BANNER_LINES) {
			sb.append(line).append('\n');
		}
		sb.append("  DeepViolet Delta Scan Report\n");
		sb.append("  Report Generated On ").append(new java.util.Date()).append('\n');
		sb.append('\n');
		sb.append("  Base Scan:   ");
		if (result.getBaseFile() != null) {
			sb.append(result.getBaseFile().getName());
		}
		sb.append(" (").append(result.getBaseHostCount()).append(" hosts)\n");
		sb.append("  Target Scan: ");
		if (result.getTargetFile() != null) {
			sb.append(result.getTargetFile().getName());
		}
		sb.append(" (").append(result.getTargetHostCount()).append(" hosts)\n");
		sb.append('\n');
		return sb.toString();
	}

	/**
	 * Render a full delta scan report as plain text.
	 */
	public static String deltaToPlainText(DeltaScanResult result) {
		FontPreferences prefs = FontPreferences.load();
		StringBuilder sb = new StringBuilder();
		sb.append(buildDeltaBanner(result));

		// Shared risks (always shown, matches on-screen rendering)
		appendSharedRisksText(sb, result);

		// Workbench-only sections: detailed per-host deltas
		if (prefs.isWorkbenchMode()) {
			sb.append("[Delta Summary]\n");
			sb.append("   Hosts Changed:   ").append(result.getChangedCount()).append('\n');
			sb.append("   Hosts Added:     ").append(result.getAddedCount()).append('\n');
			sb.append("   Hosts Removed:   ").append(result.getRemovedCount()).append('\n');
			sb.append("   Hosts Unchanged: ").append(result.getUnchangedCount()).append('\n');
			sb.append('\n');

			List<HostDelta> added = result.getHostDeltas(HostDelta.HostStatus.ADDED);
			if (!added.isEmpty()) {
				sb.append("[Hosts Added]\n");
				for (HostDelta hd : added) {
					sb.append("   + ").append(hd.getNormalizedUrl()).append('\n');
				}
				sb.append('\n');
			}

			List<HostDelta> removed = result.getHostDeltas(HostDelta.HostStatus.REMOVED);
			if (!removed.isEmpty()) {
				sb.append("[Hosts Removed]\n");
				for (HostDelta hd : removed) {
					sb.append("   - ").append(hd.getNormalizedUrl()).append('\n');
				}
				sb.append('\n');
			}

			int nBlocks = 20;
			com.mps.deepviolettools.model.HeatMapData overview =
					DeltaHeatMapBuilder.buildOverviewHeatMap(result, nBlocks);
			if (!overview.getRows().isEmpty()) {
				sb.append("[Delta Heat Map]\n");
				sb.append(heatMapToText(overview));
				List<HostDelta> changedHosts = result.getHostDeltas(
						HostDelta.HostStatus.CHANGED);
				sb.append(DeltaHeatMapBuilder.deltaLegendText(
						changedHosts.size(), nBlocks));
				sb.append('\n');
				sb.append('\n');
			}

			List<HostDelta> changed = result.getHostDeltas(HostDelta.HostStatus.CHANGED);
			if (!changed.isEmpty()) {
				sb.append("[Changed Hosts]\n\n");
				for (HostDelta hd : changed) {
					String host = hd.getNormalizedUrl();
					sb.append("   --- ").append(host)
					  .append(" (").append(hd.getOverallDirection().name())
					  .append(") ---\n\n");
					appendRiskDeltaText(sb, hd.getRiskDelta(), host);
					appendCipherDeltaText(sb, hd.getCipherDelta(), host);
					appendMapDeltaText(sb, hd.getSecurityHeadersDelta(), host);
					appendMapDeltaText(sb, hd.getConnectionDelta(), host);
					appendMapDeltaText(sb, hd.getHttpHeadersDelta(), host);
					appendFingerprintDeltaText(sb, hd.getFingerprintDelta(), host);
				}
			}
		}

		return sb.toString();
	}

	/**
	 * Append shared risk analysis as plain text, matching the on-screen
	 * rendering from {@code DeltaResultsPanel}.
	 */
	private static void appendSharedRisksText(StringBuilder sb,
			DeltaScanResult result) {
		SharedRiskAnalysis analysis = SharedRiskAnalysis.analyze(result);
		if (analysis.getTotalHostCount() == 0) {
			sb.append("[Shared Risks]\n");
			sb.append("   No shared risks found.\n\n");
			return;
		}

		// Universal shared risks
		sb.append("[Shared Risks]\n");
		sb.append("   Base scan: ");
		sb.append(result.getBaseFile() != null
				? result.getBaseFile().getAbsolutePath() : "(unknown)");
		sb.append('\n');
		sb.append("   Target scan: ");
		sb.append(result.getTargetFile() != null
				? result.getTargetFile().getAbsolutePath() : "(unknown)");
		sb.append('\n');

		List<RiskDelta.DeductionInfo> universal = analysis.getUniversalDeductions();
		if (!universal.isEmpty()) {
			for (RiskDelta.DeductionInfo di : universal) {
				sb.append("   ").append(di.getRuleId())
				  .append(" [").append(di.getSeverity()).append("] ")
				  .append(di.getDescription())
				  .append(" (score: ").append(formatDeductionScore(di.getScore()))
				  .append(")\n");
			}
		} else {
			sb.append("   No risks shared across all hosts.\n");
		}
		sb.append('\n');

		// Per-host-group shared risks
		for (SharedRiskAnalysis.SharedRiskGroup group : analysis.getHostGroups()) {
			sb.append("[Shared Risks]\n");
			sb.append("   Hosts: ").append(String.join(", ", group.getHostUrls()));
			sb.append('\n');
			for (RiskDelta.DeductionInfo di : group.getDeductions()) {
				sb.append("   ").append(di.getRuleId())
				  .append(" [").append(di.getSeverity()).append("] ")
				  .append(di.getDescription())
				  .append(" (score: ").append(formatDeductionScore(di.getScore()))
				  .append(")\n");
			}
			sb.append('\n');
		}
	}

	private static String formatDeductionScore(double score) {
		if (score == (int) score) {
			return String.valueOf((int) score);
		}
		return String.format("%.2f", score);
	}

	private static void appendRiskDeltaText(StringBuilder sb, RiskDelta delta,
			String host) {
		sb.append("   [TLS Risk Assessment (").append(host).append(")]\n");
		if (delta == null || !delta.hasChanges()) {
			sb.append("      Status=No changes\n\n");
			return;
		}
		sb.append("      Score: ").append(delta.getBaseScore())
		  .append(" \u2192 ").append(delta.getTargetScore());
		if (delta.getScoreDiff() != 0) {
			sb.append(" (").append(delta.getScoreDiff() > 0 ? "+" : "")
			  .append(delta.getScoreDiff()).append(')');
		}
		sb.append('\n');
		sb.append("      Grade: ").append(delta.getBaseGrade())
		  .append(" \u2192 ").append(delta.getTargetGrade()).append('\n');
		for (RiskDelta.DeductionInfo d : delta.getAddedDeductions()) {
			sb.append("      + ").append(d.getRuleId()).append(' ')
			  .append(d.getDescription())
			  .append(" (").append(d.getSeverity())
			  .append(", score=").append(d.getScore()).append(")\n");
		}
		for (RiskDelta.DeductionInfo d : delta.getRemovedDeductions()) {
			sb.append("      - ").append(d.getRuleId()).append(' ')
			  .append(d.getDescription())
			  .append(" (was score=").append(d.getScore()).append(")\n");
		}
		sb.append('\n');
	}

	private static void appendCipherDeltaText(StringBuilder sb, CipherDelta delta,
			String host) {
		sb.append("   [Server cipher suites (").append(host).append(")]\n");
		if (delta == null || !delta.hasChanges()) {
			sb.append("      Status=No changes\n\n");
			return;
		}
		for (CipherDelta.CipherInfo c : delta.getAddedCiphers()) {
			sb.append("      + ").append(c.getName())
			  .append(" (").append(c.getStrength())
			  .append(", ").append(c.getProtocol()).append(")\n");
		}
		for (CipherDelta.CipherInfo c : delta.getRemovedCiphers()) {
			sb.append("      - ").append(c.getName())
			  .append(" (").append(c.getStrength())
			  .append(", ").append(c.getProtocol()).append(")\n");
		}
		sb.append('\n');
	}

	private static void appendMapDeltaText(StringBuilder sb, MapDelta delta,
			String host) {
		if (delta == null) return;
		sb.append("   [").append(delta.getSectionName()).append(" (").append(host).append(")]\n");
		if (!delta.hasChanges()) {
			sb.append("      Status=No changes\n\n");
			return;
		}
		for (Map.Entry<String, String> e : delta.getAddedEntries().entrySet()) {
			sb.append("      + ").append(e.getKey()).append(": ")
			  .append(e.getValue()).append('\n');
		}
		for (Map.Entry<String, String[]> e : delta.getChangedEntries().entrySet()) {
			sb.append("      ~ ").append(e.getKey()).append(": \"")
			  .append(e.getValue()[0]).append("\" \u2192 \"")
			  .append(e.getValue()[1]).append("\"\n");
		}
		for (Map.Entry<String, String> e : delta.getRemovedEntries().entrySet()) {
			sb.append("      - ").append(e.getKey()).append(": ")
			  .append(e.getValue()).append('\n');
		}
		sb.append('\n');
	}

	private static void appendFingerprintDeltaText(StringBuilder sb,
			FingerprintDelta delta, String host) {
		sb.append("   [TLS Probe Fingerprint (").append(host).append(")]\n");
		if (delta == null || !delta.hasChanges()) {
			sb.append("      Status=No changes\n\n");
			return;
		}
		if (delta.getBaseHash() != null && delta.getTargetHash() != null) {
			sb.append("      Hash: ").append(delta.getBaseHash())
			  .append(" \u2192 ").append(delta.getTargetHash()).append('\n');
		}
		for (FingerprintDelta.ProbeDiff pd : delta.getProbeDiffs()) {
			sb.append("      ~ Probe ").append(pd.getProbeNumber())
			  .append(": ").append(pd.getBaseCode())
			  .append(" \u2192 ").append(pd.getTargetCode()).append('\n');
		}
		sb.append('\n');
	}

	/**
	 * Save a delta scan report as plain text.
	 */
	public static void saveDeltaAsText(File file, DeltaScanResult result)
			throws IOException {
		try (PrintWriter p = new PrintWriter(file)) {
			p.print(deltaToPlainText(result));
		}
	}

	/**
	 * Save a delta scan report as structured JSON.
	 */
	public static void saveDeltaAsJson(File file, DeltaScanResult result)
			throws IOException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (FileWriter writer = new FileWriter(file)) {
			writer.write(deltaToJsonString(result, gson));
		}
	}

	/**
	 * Render a delta scan report as a JSON string.
	 */
	static String deltaToJsonString(DeltaScanResult result, Gson gson) {
		FontPreferences prefs = FontPreferences.load();
		Map<String, Object> jsonMap = new LinkedHashMap<>();
		jsonMap.put("report_type", "delta");
		jsonMap.put("comparison_date", result.getComparisonDate().toString());
		if (result.getBaseFile() != null)
			jsonMap.put("base_file", result.getBaseFile().getName());
		if (result.getTargetFile() != null)
			jsonMap.put("target_file", result.getTargetFile().getName());
		jsonMap.put("base_host_count", result.getBaseHostCount());
		jsonMap.put("target_host_count", result.getTargetHostCount());

		// Shared risks (always included, matches on-screen rendering)
		SharedRiskAnalysis analysis = SharedRiskAnalysis.analyze(result);
		Map<String, Object> sharedRisks = new LinkedHashMap<>();
		sharedRisks.put("total_host_count", analysis.getTotalHostCount());

		List<Map<String, Object>> universalList = new ArrayList<>();
		for (RiskDelta.DeductionInfo di : analysis.getUniversalDeductions()) {
			Map<String, Object> d = new LinkedHashMap<>();
			d.put("rule_id", di.getRuleId());
			d.put("severity", di.getSeverity());
			d.put("description", di.getDescription());
			d.put("score", di.getScore());
			universalList.add(d);
		}
		sharedRisks.put("universal", universalList);

		List<Map<String, Object>> groupsList = new ArrayList<>();
		for (SharedRiskAnalysis.SharedRiskGroup group : analysis.getHostGroups()) {
			Map<String, Object> g = new LinkedHashMap<>();
			g.put("hosts", new ArrayList<>(group.getHostUrls()));
			List<Map<String, Object>> groupDeds = new ArrayList<>();
			for (RiskDelta.DeductionInfo di : group.getDeductions()) {
				Map<String, Object> d = new LinkedHashMap<>();
				d.put("rule_id", di.getRuleId());
				d.put("severity", di.getSeverity());
				d.put("description", di.getDescription());
				d.put("score", di.getScore());
				groupDeds.add(d);
			}
			g.put("deductions", groupDeds);
			groupsList.add(g);
		}
		sharedRisks.put("host_groups", groupsList);
		jsonMap.put("shared_risks", sharedRisks);

		// Workbench-only sections: summary counts and per-host delta details
		if (prefs.isWorkbenchMode()) {
			Map<String, Integer> summary = new LinkedHashMap<>();
			summary.put("changed", result.getChangedCount());
			summary.put("added", result.getAddedCount());
			summary.put("removed", result.getRemovedCount());
			summary.put("unchanged", result.getUnchangedCount());
			jsonMap.put("summary", summary);

			List<Map<String, Object>> hosts = new ArrayList<>();
			for (HostDelta hd : result.getHostDeltas()) {
				Map<String, Object> hostMap = new LinkedHashMap<>();
				hostMap.put("host", hd.getNormalizedUrl());
				hostMap.put("status", hd.getStatus().name());
				hostMap.put("direction", hd.getOverallDirection().name());

				if (hd.getRiskDelta() != null && hd.getRiskDelta().hasChanges()) {
					Map<String, Object> risk = new LinkedHashMap<>();
					risk.put("base_score", hd.getRiskDelta().getBaseScore());
					risk.put("target_score", hd.getRiskDelta().getTargetScore());
					risk.put("score_diff", hd.getRiskDelta().getScoreDiff());
					risk.put("base_grade", hd.getRiskDelta().getBaseGrade());
					risk.put("target_grade", hd.getRiskDelta().getTargetGrade());
					hostMap.put("risk_delta", risk);
				}
				if (hd.getCipherDelta() != null && hd.getCipherDelta().hasChanges()) {
					Map<String, Object> cipher = new LinkedHashMap<>();
					List<String> ca = new ArrayList<>();
					for (CipherDelta.CipherInfo c : hd.getCipherDelta().getAddedCiphers())
						ca.add(c.getName());
					List<String> cr = new ArrayList<>();
					for (CipherDelta.CipherInfo c : hd.getCipherDelta().getRemovedCiphers())
						cr.add(c.getName());
					cipher.put("added", ca);
					cipher.put("removed", cr);
					hostMap.put("cipher_delta", cipher);
				}
				addMapDeltaJson(hostMap, "security_headers_delta", hd.getSecurityHeadersDelta());
				addMapDeltaJson(hostMap, "connection_delta", hd.getConnectionDelta());
				addMapDeltaJson(hostMap, "http_headers_delta", hd.getHttpHeadersDelta());
				if (hd.getFingerprintDelta() != null && hd.getFingerprintDelta().hasChanges()) {
					Map<String, Object> fp = new LinkedHashMap<>();
					fp.put("base", hd.getFingerprintDelta().getBaseFingerprint());
					fp.put("target", hd.getFingerprintDelta().getTargetFingerprint());
					fp.put("probe_diffs", hd.getFingerprintDelta().getProbeDiffs().size());
					hostMap.put("fingerprint_delta", fp);
				}

				hosts.add(hostMap);
			}
			jsonMap.put("hosts", hosts);
		}

		return gson.toJson(jsonMap);
	}

	private static void addMapDeltaJson(Map<String, Object> hostMap,
			String key, MapDelta delta) {
		if (delta == null || !delta.hasChanges()) return;
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("added", delta.getAddedEntries());
		m.put("removed", delta.getRemovedEntries());
		Map<String, String> changed = new LinkedHashMap<>();
		for (Map.Entry<String, String[]> e : delta.getChangedEntries().entrySet()) {
			changed.put(e.getKey(), e.getValue()[0] + " -> " + e.getValue()[1]);
		}
		m.put("changed", changed);
		hostMap.put(key, m);
	}

	/**
	 * Save a delta scan report as HTML with color-coded diff styling.
	 */
	public static void saveDeltaAsHtml(File file, DeltaScanResult result)
			throws IOException {
		FontPreferences prefs = FontPreferences.load();
		try (PrintWriter p = new PrintWriter(file, "UTF-8")) {
			p.println("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">");
			p.println("<title>DeepViolet Delta Scan Report</title>");
			p.println("<style>");
			p.println("body { font-family: monospace; background: "
					+ toHtmlColor(prefs.getBackground()) + "; color: "
					+ toHtmlColor(prefs.getDefaultText()) + "; }");
			p.println("h2 { color: " + toHtmlColor(prefs.getHeading()) + "; }");
			p.println(".added { color: #4CAF50; }");
			p.println(".removed { color: #F44336; }");
			p.println(".changed { color: #FFC107; }");
			p.println(".section { color: " + toHtmlColor(prefs.getHeading()) + "; font-weight: bold; }");
			p.println("pre { font-size: 13px; }");
			p.println("</style></head><body>");
			p.println("<pre>");

			writeHtmlBanner(p, "DeepViolet Delta Scan Report",
					toHtmlColor(prefs.getNotice()));

			// Shared risks (always shown, matches on-screen rendering)
			writeHtmlSharedRisks(p, result, prefs);

			// Workbench-only sections: detailed per-host deltas
			if (prefs.isWorkbenchMode()) {
				p.println("<span class=\"section\">[Delta Summary]</span>");
				p.println("   Hosts Changed:   " + result.getChangedCount());
				p.println("   Hosts Added:     " + result.getAddedCount());
				p.println("   Hosts Removed:   " + result.getRemovedCount());
				p.println("   Hosts Unchanged: " + result.getUnchangedCount());
				p.println();

				List<HostDelta> added = result.getHostDeltas(HostDelta.HostStatus.ADDED);
				if (!added.isEmpty()) {
					p.println("<span class=\"section\">[Hosts Added]</span>");
					for (HostDelta hd : added)
						p.println("<span class=\"added\">   + " + escapeHtml(hd.getNormalizedUrl()) + "</span>");
					p.println();
				}

				List<HostDelta> removed = result.getHostDeltas(HostDelta.HostStatus.REMOVED);
				if (!removed.isEmpty()) {
					p.println("<span class=\"section\">[Hosts Removed]</span>");
					for (HostDelta hd : removed)
						p.println("<span class=\"removed\">   - " + escapeHtml(hd.getNormalizedUrl()) + "</span>");
					p.println();
				}

				List<HostDelta> changed = result.getHostDeltas(HostDelta.HostStatus.CHANGED);
				if (!changed.isEmpty()) {
					p.println("<span class=\"section\">[Changed Hosts]</span>");
					p.println();
					for (HostDelta hd : changed) {
						p.println("<span class=\"section\">   --- "
								+ escapeHtml(hd.getNormalizedUrl()) + " ("
								+ hd.getOverallDirection().name() + ") ---</span>");
						p.println();
						writeHtmlDeltaSections(p, hd);
					}
				}
			}

			p.println("</pre></body></html>");
		}
	}

	private static void writeHtmlSharedRisks(PrintWriter p,
			DeltaScanResult result, FontPreferences prefs) {
		SharedRiskAnalysis analysis = SharedRiskAnalysis.analyze(result);
		if (analysis.getTotalHostCount() == 0) {
			p.println("<span class=\"section\">[Shared Risks]</span>");
			p.println("   No shared risks found.");
			p.println();
			return;
		}

		// Universal section
		p.println("<span class=\"section\">[Shared Risks]</span>");
		String basePath = result.getBaseFile() != null
				? escapeHtml(result.getBaseFile().getAbsolutePath()) : "(unknown)";
		String targetPath = result.getTargetFile() != null
				? escapeHtml(result.getTargetFile().getAbsolutePath()) : "(unknown)";
		p.println("   <b>Base scan:</b> " + basePath);
		p.println("   <b>Target scan:</b> " + targetPath);

		List<RiskDelta.DeductionInfo> universal = analysis.getUniversalDeductions();
		if (!universal.isEmpty()) {
			for (RiskDelta.DeductionInfo di : universal) {
				String sevColor = toHtmlColor(prefs.getColorForSeverity(di.getSeverity()));
				p.println("   <span style=\"color:" + sevColor + ";font-weight:bold\">"
						+ escapeHtml(di.getRuleId() + " [" + di.getSeverity() + "] "
						+ di.getDescription()
						+ " (score: " + formatDeductionScore(di.getScore()) + ")")
						+ "</span>");
			}
		} else {
			p.println("   No risks shared across all hosts.");
		}
		p.println();

		// Per-group sections
		for (SharedRiskAnalysis.SharedRiskGroup group : analysis.getHostGroups()) {
			p.println("<span class=\"section\">[Shared Risks]</span>");
			p.println("   <b>Hosts:</b> " + escapeHtml(String.join(", ", group.getHostUrls())));
			for (RiskDelta.DeductionInfo di : group.getDeductions()) {
				String sevColor = toHtmlColor(prefs.getColorForSeverity(di.getSeverity()));
				p.println("   <span style=\"color:" + sevColor + ";font-weight:bold\">"
						+ escapeHtml(di.getRuleId() + " [" + di.getSeverity() + "] "
						+ di.getDescription()
						+ " (score: " + formatDeductionScore(di.getScore()) + ")")
						+ "</span>");
			}
			p.println();
		}
	}

	private static void writeHtmlDeltaSections(PrintWriter p, HostDelta hd) {
		String host = hd.getNormalizedUrl();
		writeHtmlRiskDelta(p, hd.getRiskDelta(), host);
		writeHtmlCipherDelta(p, hd.getCipherDelta(), host);
		writeHtmlMapDelta(p, hd.getSecurityHeadersDelta(), host);
		writeHtmlMapDelta(p, hd.getConnectionDelta(), host);
		writeHtmlMapDelta(p, hd.getHttpHeadersDelta(), host);
		writeHtmlFingerprintDelta(p, hd.getFingerprintDelta(), host);
	}

	private static void writeHtmlRiskDelta(PrintWriter p, RiskDelta delta,
			String host) {
		p.println("   <span class=\"section\">[TLS Risk Assessment (" + escapeHtml(host) + ")]</span>");
		if (delta == null || !delta.hasChanges()) {
			p.println("      Status=No changes");
			p.println();
			return;
		}
		String scoreDir = delta.getScoreDiff() > 0 ? "added" : delta.getScoreDiff() < 0 ? "removed" : "changed";
		p.println("      <span class=\"" + scoreDir + "\">Score: " + delta.getBaseScore()
				+ " \u2192 " + delta.getTargetScore()
				+ (delta.getScoreDiff() != 0 ? " (" + (delta.getScoreDiff() > 0 ? "+" : "")
				+ delta.getScoreDiff() + ")" : "") + "</span>");
		p.println("      Grade: " + escapeHtml(delta.getBaseGrade())
				+ " \u2192 " + escapeHtml(delta.getTargetGrade()));
		for (RiskDelta.DeductionInfo d : delta.getAddedDeductions())
			p.println("      <span class=\"added\">+ " + escapeHtml(d.getRuleId()
					+ " " + d.getDescription()) + "</span>");
		for (RiskDelta.DeductionInfo d : delta.getRemovedDeductions())
			p.println("      <span class=\"removed\">- " + escapeHtml(d.getRuleId()
					+ " " + d.getDescription()) + "</span>");
		p.println();
	}

	private static void writeHtmlCipherDelta(PrintWriter p, CipherDelta delta,
			String host) {
		p.println("   <span class=\"section\">[Server cipher suites (" + escapeHtml(host) + ")]</span>");
		if (delta == null || !delta.hasChanges()) {
			p.println("      Status=No changes");
			p.println();
			return;
		}
		for (CipherDelta.CipherInfo c : delta.getAddedCiphers())
			p.println("      <span class=\"added\">+ " + escapeHtml(c.getName()
					+ " (" + c.getStrength() + ", " + c.getProtocol() + ")") + "</span>");
		for (CipherDelta.CipherInfo c : delta.getRemovedCiphers())
			p.println("      <span class=\"removed\">- " + escapeHtml(c.getName()
					+ " (" + c.getStrength() + ", " + c.getProtocol() + ")") + "</span>");
		p.println();
	}

	private static void writeHtmlMapDelta(PrintWriter p, MapDelta delta,
			String host) {
		if (delta == null) return;
		p.println("   <span class=\"section\">[" + escapeHtml(delta.getSectionName()) + " (" + escapeHtml(host) + ")]</span>");
		if (!delta.hasChanges()) {
			p.println("      Status=No changes");
			p.println();
			return;
		}
		for (Map.Entry<String, String> e : delta.getAddedEntries().entrySet())
			p.println("      <span class=\"added\">+ " + escapeHtml(e.getKey()
					+ ": " + e.getValue()) + "</span>");
		for (Map.Entry<String, String[]> e : delta.getChangedEntries().entrySet())
			p.println("      <span class=\"changed\">~ " + escapeHtml(e.getKey()
					+ ": \"" + e.getValue()[0] + "\" \u2192 \"" + e.getValue()[1] + "\"") + "</span>");
		for (Map.Entry<String, String> e : delta.getRemovedEntries().entrySet())
			p.println("      <span class=\"removed\">- " + escapeHtml(e.getKey()
					+ ": " + e.getValue()) + "</span>");
		p.println();
	}

	private static void writeHtmlFingerprintDelta(PrintWriter p,
			FingerprintDelta delta, String host) {
		p.println("   <span class=\"section\">[TLS Probe Fingerprint (" + escapeHtml(host) + ")]</span>");
		if (delta == null || !delta.hasChanges()) {
			p.println("      Status=No changes");
			p.println();
			return;
		}
		if (delta.getBaseHash() != null && delta.getTargetHash() != null) {
			p.println("      <span class=\"changed\">Hash: " + escapeHtml(delta.getBaseHash())
					+ " \u2192 " + escapeHtml(delta.getTargetHash()) + "</span>");
		}
		for (FingerprintDelta.ProbeDiff pd : delta.getProbeDiffs())
			p.println("      <span class=\"changed\">~ Probe " + pd.getProbeNumber()
					+ ": " + escapeHtml(pd.getBaseCode()) + " \u2192 "
					+ escapeHtml(pd.getTargetCode()) + "</span>");
		p.println();
	}

	/**
	 * Save a delta scan report as PDF via OpenPDF.
	 */
	public static void saveDeltaAsPdf(File file, DeltaScanResult result)
			throws IOException {
		com.lowagie.text.Document pdfDoc = new com.lowagie.text.Document(
				com.lowagie.text.PageSize.A4, 36, 36, 36, 36);
		try {
			com.lowagie.text.pdf.PdfWriter.getInstance(pdfDoc,
					new java.io.FileOutputStream(file));
			pdfDoc.open();

			float fontSize = 8f;
			float leading = 10f;

			writePdfBanner(pdfDoc, "DeepViolet Delta Scan Report",
					fontSize, leading, Color.BLACK, null);

			addPdfLine(pdfDoc, "Base Scan:   "
					+ (result.getBaseFile() != null ? result.getBaseFile().getName() : "")
					+ " (" + result.getBaseHostCount() + " hosts)",
					fontSize, leading, Color.DARK_GRAY, false);
			addPdfLine(pdfDoc, "Target Scan: "
					+ (result.getTargetFile() != null ? result.getTargetFile().getName() : "")
					+ " (" + result.getTargetHostCount() + " hosts)",
					fontSize, leading, Color.DARK_GRAY, false);
			addPdfLine(pdfDoc, " ", fontSize, leading, Color.DARK_GRAY, false);

			// Shared risks (always shown, matches on-screen rendering)
			writePdfSharedRisks(pdfDoc, result, fontSize, leading);

			// Workbench-only sections: detailed per-host deltas
			FontPreferences prefs = FontPreferences.load();
			if (prefs.isWorkbenchMode()) {
				addPdfLine(pdfDoc, "[Delta Summary]", 10f, 12f, Color.BLACK, true);
				addPdfLine(pdfDoc, "  Changed: " + result.getChangedCount()
						+ "  Added: " + result.getAddedCount()
						+ "  Removed: " + result.getRemovedCount()
						+ "  Unchanged: " + result.getUnchangedCount(),
						fontSize, leading, Color.DARK_GRAY, false);

				// Changed hosts
				Color green = new Color(76, 175, 80);
				Color red = new Color(244, 67, 54);
				Color yellow = new Color(255, 193, 7);

				for (HostDelta hd : result.getHostDeltas(HostDelta.HostStatus.CHANGED)) {
					pdfDoc.newPage();
					addPdfLine(pdfDoc, "--- " + hd.getNormalizedUrl()
							+ " (" + hd.getOverallDirection().name() + ") ---",
							10f, 12f, Color.BLACK, true);

					// Flatten delta text for this host
					String host = hd.getNormalizedUrl();
					StringBuilder hostText = new StringBuilder();
					appendRiskDeltaText(hostText, hd.getRiskDelta(), host);
					appendCipherDeltaText(hostText, hd.getCipherDelta(), host);
					appendMapDeltaText(hostText, hd.getSecurityHeadersDelta(), host);
					appendMapDeltaText(hostText, hd.getConnectionDelta(), host);
					appendMapDeltaText(hostText, hd.getHttpHeadersDelta(), host);
					appendFingerprintDeltaText(hostText, hd.getFingerprintDelta(), host);

					for (String line : hostText.toString().split("\n")) {
						Color lineColor = Color.DARK_GRAY;
						String trimmed = line.trim();
						if (trimmed.startsWith("+")) lineColor = green;
						else if (trimmed.startsWith("-")) lineColor = red;
						else if (trimmed.startsWith("~")) lineColor = yellow;
						else if (trimmed.startsWith("[")) lineColor = Color.BLACK;
						addPdfLine(pdfDoc, line, fontSize, leading,
								lineColor, trimmed.startsWith("["));
					}
				}
			}
		} catch (com.lowagie.text.DocumentException e) {
			throw new IOException("Failed to write delta PDF: " + e.getMessage(), e);
		} finally {
			pdfDoc.close();
		}
	}

	private static void writePdfSharedRisks(com.lowagie.text.Document pdfDoc,
			DeltaScanResult result, float fontSize, float leading)
			throws com.lowagie.text.DocumentException {
		SharedRiskAnalysis analysis = SharedRiskAnalysis.analyze(result);
		if (analysis.getTotalHostCount() == 0) {
			addPdfLine(pdfDoc, "[Shared Risks]", 10f, 12f, Color.BLACK, true);
			addPdfLine(pdfDoc, "   No shared risks found.", fontSize, leading,
					Color.DARK_GRAY, false);
			addPdfLine(pdfDoc, " ", fontSize, leading, Color.DARK_GRAY, false);
			return;
		}

		addPdfLine(pdfDoc, "[Shared Risks]", 10f, 12f, Color.BLACK, true);
		String basePath = result.getBaseFile() != null
				? result.getBaseFile().getAbsolutePath() : "(unknown)";
		String targetPath = result.getTargetFile() != null
				? result.getTargetFile().getAbsolutePath() : "(unknown)";
		addPdfLine(pdfDoc, "   Base scan: " + basePath, fontSize, leading,
				Color.DARK_GRAY, false);
		addPdfLine(pdfDoc, "   Target scan: " + targetPath, fontSize, leading,
				Color.DARK_GRAY, false);

		List<RiskDelta.DeductionInfo> universal = analysis.getUniversalDeductions();
		if (!universal.isEmpty()) {
			for (RiskDelta.DeductionInfo di : universal) {
				addPdfLine(pdfDoc, "   " + di.getRuleId() + " [" + di.getSeverity()
						+ "] " + di.getDescription()
						+ " (score: " + formatDeductionScore(di.getScore()) + ")",
						fontSize, leading, Color.BLACK, true);
			}
		} else {
			addPdfLine(pdfDoc, "   No risks shared across all hosts.",
					fontSize, leading, Color.DARK_GRAY, false);
		}
		addPdfLine(pdfDoc, " ", fontSize, leading, Color.DARK_GRAY, false);

		for (SharedRiskAnalysis.SharedRiskGroup group : analysis.getHostGroups()) {
			addPdfLine(pdfDoc, "[Shared Risks]", 10f, 12f, Color.BLACK, true);
			addPdfLine(pdfDoc, "   Hosts: " + String.join(", ", group.getHostUrls()),
					fontSize, leading, Color.DARK_GRAY, false);
			for (RiskDelta.DeductionInfo di : group.getDeductions()) {
				addPdfLine(pdfDoc, "   " + di.getRuleId() + " [" + di.getSeverity()
						+ "] " + di.getDescription()
						+ " (score: " + formatDeductionScore(di.getScore()) + ")",
						fontSize, leading, Color.BLACK, true);
			}
			addPdfLine(pdfDoc, " ", fontSize, leading, Color.DARK_GRAY, false);
		}
	}

}
