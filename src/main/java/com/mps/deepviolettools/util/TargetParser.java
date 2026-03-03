package com.mps.deepviolettools.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for parsing scan targets into normalized HTTPS URLs.
 *
 * <p>Supported input formats:
 * <ul>
 *   <li>Bare hostname: {@code example.com} &rarr; {@code https://example.com:443/}</li>
 *   <li>Hostname with port: {@code example.com:8443} &rarr; {@code https://example.com:8443/}</li>
 *   <li>IPv4 address: {@code 10.0.1.5} &rarr; {@code https://10.0.1.5:443/}</li>
 *   <li>IPv4 with port: {@code 10.0.1.5:8443} &rarr; {@code https://10.0.1.5:8443/}</li>
 *   <li>IPv6 bracketed: {@code [2001:db8::1]} &rarr; {@code https://[2001:db8::1]:443/}</li>
 *   <li>IPv6 with port: {@code [::1]:8443} &rarr; {@code https://[::1]:8443/}</li>
 *   <li>IPv6 bare: {@code 2001:db8::1} &rarr; {@code https://[2001:db8::1]:443/}</li>
 *   <li>IPv4 CIDR block: {@code 10.0.1.0/24} &rarr; 254 individual IPs</li>
 *   <li>IPv6 CIDR block: {@code 2001:db8::/120} &rarr; individual IPs (capped at max expansion)</li>
 *   <li>Dash range (IPv4 only): {@code 10.0.2.1-50} &rarr; {@code 10.0.2.1} through {@code 10.0.2.50}</li>
 *   <li>Full URL: {@code https://example.com/} &rarr; used as-is</li>
 * </ul>
 */
public final class TargetParser {

    private static final Logger logger = LoggerFactory.getLogger(TargetParser.class);

    /** Default maximum number of addresses expanded from a single CIDR block. */
    public static final int DEFAULT_MAX_CIDR_EXPANSION = 512;

    private static int maxCidrExpansion = DEFAULT_MAX_CIDR_EXPANSION;

    private TargetParser() {
        // Prevent instantiation
    }

    /**
     * Sets the maximum number of addresses that a single CIDR block may expand to.
     * Blocks that would exceed this limit are rejected with a warning.
     *
     * @param max maximum expansion count (must be &ge; 1)
     */
    public static void setMaxCidrExpansion(int max) {
        maxCidrExpansion = Math.max(1, max);
    }

    /**
     * Returns the current maximum CIDR expansion limit.
     */
    public static int getMaxCidrExpansion() {
        return maxCidrExpansion;
    }

    /**
     * Splits the input on commas or newlines, parses each target, and returns a list
     * of normalized HTTPS URLs. Blank entries, comment lines (starting with {@code #}),
     * and unparseable targets are skipped. Each entry is trimmed of leading/trailing
     * whitespace before parsing.
     *
     * @param commaOrNewlineSeparated comma- or newline-separated list of targets
     * @return list of normalized URL strings
     */
    public static List<String> parse(String commaOrNewlineSeparated) {
        if (commaOrNewlineSeparated == null || commaOrNewlineSeparated.isBlank()) {
            return Collections.emptyList();
        }

        List<String> results = new ArrayList<>();
        // Split on commas or newlines (or a mix)
        String[] tokens = commaOrNewlineSeparated.split("[,\\r?\\n]+");
        for (String token : tokens) {
            String trimmed = token.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            try {
                String normalized = normalizeTarget(trimmed);
                if (normalized != null) {
                    results.add(normalized);
                }
            } catch (Exception e) {
                // normalizeTarget handles expansion internally; if a single target
                // is actually a range/CIDR it returns just the first — but we need
                // to handle expansion here too
                logger.warn("Skipping unparseable target: {}", trimmed, e);
            }
        }
        return results;
    }

    /**
     * Reads targets from a file, skipping comment lines (starting with {@code #})
     * and blank lines. Each remaining line is parsed as a target.
     *
     * @param file the file to read
     * @return list of normalized URL strings
     * @throws IOException if the file cannot be read
     */
    public static List<String> parseFile(File file) throws IOException {
        List<String> results = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                List<String> parsed = parseTarget(trimmed);
                results.addAll(parsed);
            }
        }
        return results;
    }

    /**
     * Normalizes a single target string into an HTTPS URL. If the target is already
     * a full URL (starts with {@code https://}), it is returned as-is. Otherwise the
     * format is detected and the appropriate URL is constructed.
     *
     * <p>For targets that expand to multiple URLs (CIDR, dash range), only the first
     * result is returned. Use {@link #parse(String)} for full expansion.
     *
     * @param target the raw target string
     * @return normalized URL string, or {@code null} if the target cannot be parsed
     */
    public static String normalizeTarget(String target) {
        if (target == null) {
            return null;
        }
        target = target.trim();
        if (target.isEmpty()) {
            return null;
        }

        // Already a full URL
        if (target.toLowerCase().startsWith("https://")) {
            return target;
        }

        // CIDR notation — detect by '/' but not in URLs
        // For bracketed IPv6 CIDR like [2001:db8::]/120, strip brackets first
        if (target.contains("/") && !target.contains("://")) {
            try {
                String cidrTarget = target;
                // Strip brackets if present: [2001:db8::]/120 -> 2001:db8::/120
                if (cidrTarget.startsWith("[")) {
                    int closeBracket = cidrTarget.indexOf(']');
                    if (closeBracket > 0) {
                        cidrTarget = cidrTarget.substring(1, closeBracket)
                                + cidrTarget.substring(closeBracket + 1);
                    }
                }
                List<String> ips = expandCidr(cidrTarget);
                if (!ips.isEmpty()) {
                    return buildUrl(ips.get(0), 443);
                }
            } catch (Exception e) {
                logger.warn("Failed to parse CIDR target: {}", target, e);
            }
            return null;
        }

        // Dash range (IPv4 only) — return first expanded IP as URL
        if (target.matches(".*\\d+-\\d+$") && !target.contains("://") && !isBareIpv6(target)) {
            try {
                List<String> ips = expandDashRange(target);
                if (!ips.isEmpty()) {
                    return buildUrl(ips.get(0), 443);
                }
            } catch (Exception e) {
                logger.warn("Failed to parse dash-range target: {}", target, e);
            }
            return null;
        }

        // Hostname or IP (IPv4/IPv6) with optional port
        return parseHostPort(target);
    }

    /**
     * Internal method that parses a single target and returns all expanded URLs.
     * This is used by {@link #parse(String)} and {@link #parseFile(File)} to
     * support CIDR and dash-range expansion.
     */
    private static List<String> parseTarget(String target) {
        if (target == null || target.isBlank()) {
            return Collections.emptyList();
        }
        target = target.trim();

        // Already a full URL
        if (target.toLowerCase().startsWith("https://")) {
            return List.of(target);
        }

        // CIDR notation
        if (target.contains("/") && !target.contains("://")) {
            try {
                String cidrTarget = target;
                if (cidrTarget.startsWith("[")) {
                    int closeBracket = cidrTarget.indexOf(']');
                    if (closeBracket > 0) {
                        cidrTarget = cidrTarget.substring(1, closeBracket)
                                + cidrTarget.substring(closeBracket + 1);
                    }
                }
                List<String> ips = expandCidr(cidrTarget);
                List<String> urls = new ArrayList<>(ips.size());
                for (String ip : ips) {
                    urls.add(buildUrl(ip, 443));
                }
                return urls;
            } catch (Exception e) {
                logger.warn("Skipping unparseable CIDR target: {}", target, e);
                return Collections.emptyList();
            }
        }

        // Dash range (IPv4 only)
        if (target.matches(".*\\d+-\\d+$") && !target.contains("://") && !isBareIpv6(target)) {
            try {
                List<String> ips = expandDashRange(target);
                List<String> urls = new ArrayList<>(ips.size());
                for (String ip : ips) {
                    urls.add(buildUrl(ip, 443));
                }
                return urls;
            } catch (Exception e) {
                logger.warn("Skipping unparseable dash-range target: {}", target, e);
                return Collections.emptyList();
            }
        }

        // Hostname or IP with optional port
        String url = parseHostPort(target);
        if (url != null) {
            return List.of(url);
        }
        return Collections.emptyList();
    }

    /**
     * Expands a CIDR block into a list of individual IP address strings.
     * Supports both IPv4 and IPv6 CIDR notation.
     *
     * <p>For IPv4 prefix lengths of /31 and /32, all addresses are included.
     * For larger IPv4 networks (/30 and below), network and broadcast addresses
     * are excluded. IPv6 CIDR always includes all addresses in the range.
     *
     * <p>Expansion is capped at {@link #getMaxCidrExpansion()} addresses.
     *
     * @param cidr CIDR notation string, e.g. {@code 10.0.1.0/24} or {@code 2001:db8::/120}
     * @return list of IP address strings
     */
    private static List<String> expandCidr(String cidr) {
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            logger.warn("Invalid CIDR notation: {}", cidr);
            return Collections.emptyList();
        }

        String baseIp = parts[0].trim();
        int prefixLength;
        try {
            prefixLength = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            logger.warn("Invalid CIDR prefix length: {}", cidr);
            return Collections.emptyList();
        }

        // Resolve to determine IPv4 vs IPv6
        InetAddress addr;
        try {
            addr = InetAddress.getByName(baseIp);
        } catch (UnknownHostException e) {
            logger.warn("Cannot resolve base IP for CIDR: {}", baseIp, e);
            return Collections.emptyList();
        }

        byte[] bytes = addr.getAddress();
        boolean isIpv6 = (bytes.length == 16);
        int maxPrefix = isIpv6 ? 128 : 32;

        if (prefixLength < 0 || prefixLength > maxPrefix) {
            logger.warn("CIDR prefix length out of range (0-{}): {}", maxPrefix, prefixLength);
            return Collections.emptyList();
        }

        int totalBits = isIpv6 ? 128 : 32;
        int hostBits = totalBits - prefixLength;

        // Check expansion size before allocating
        if (hostBits > 20) {
            // More than ~1M addresses — always reject regardless of cap
            logger.warn("CIDR block /{} would expand to 2^{} addresses, too large: {}",
                    prefixLength, hostBits, cidr);
            return Collections.emptyList();
        }

        long totalAddresses = 1L << hostBits;

        // For IPv4 /30 and below, network and broadcast are excluded
        boolean excludeNetworkBroadcast = !isIpv6 && prefixLength < 31;
        long usableCount = excludeNetworkBroadcast ? totalAddresses - 2 : totalAddresses;
        if (usableCount <= 0) {
            return Collections.emptyList();
        }

        if (usableCount > maxCidrExpansion) {
            logger.warn("CIDR block {} would expand to {} addresses, exceeding limit of {}: {}",
                    cidr, usableCount, maxCidrExpansion, cidr);
            return Collections.emptyList();
        }

        // Use BigInteger for protocol-agnostic address arithmetic
        BigInteger baseAddr = new BigInteger(1, bytes);
        BigInteger mask = BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE).not()
                .and(BigInteger.ONE.shiftLeft(totalBits).subtract(BigInteger.ONE));
        BigInteger networkAddr = baseAddr.and(mask);

        BigInteger startAddr;
        BigInteger endAddr;
        if (excludeNetworkBroadcast) {
            // Exclude network (first) and broadcast (last) for IPv4
            startAddr = networkAddr.add(BigInteger.ONE);
            endAddr = networkAddr.add(BigInteger.valueOf(totalAddresses - 2));
        } else {
            startAddr = networkAddr;
            endAddr = networkAddr.add(BigInteger.valueOf(totalAddresses - 1));
        }

        List<String> ips = new ArrayList<>((int) usableCount);
        for (BigInteger ip = startAddr; ip.compareTo(endAddr) <= 0; ip = ip.add(BigInteger.ONE)) {
            ips.add(bigIntegerToIp(ip, totalBits));
        }

        return ips;
    }

    /**
     * Expands a dash range into a list of individual IP address strings.
     * IPv4 only — IPv6 dash ranges are not supported.
     *
     * <p>The expected format is {@code A.B.C.start-end} where start and end are
     * the last octet values (inclusive).
     *
     * @param range dash range string, e.g. {@code 10.0.2.1-50}
     * @return list of IP address strings
     */
    private static List<String> expandDashRange(String range) {
        // Find the last dot to split the prefix from the range part
        int lastDot = range.lastIndexOf('.');
        if (lastDot < 0) {
            logger.warn("Invalid dash range format (no dot found): {}", range);
            return Collections.emptyList();
        }

        String prefix = range.substring(0, lastDot); // e.g. "10.0.2"
        String rangePart = range.substring(lastDot + 1); // e.g. "1-50"

        int dashIndex = rangePart.indexOf('-');
        if (dashIndex < 0) {
            logger.warn("Invalid dash range format (no dash in last octet): {}", range);
            return Collections.emptyList();
        }

        int start;
        int end;
        try {
            start = Integer.parseInt(rangePart.substring(0, dashIndex));
            end = Integer.parseInt(rangePart.substring(dashIndex + 1));
        } catch (NumberFormatException e) {
            logger.warn("Invalid dash range values: {}", range);
            return Collections.emptyList();
        }

        if (start < 0 || start > 255 || end < 0 || end > 255) {
            logger.warn("Dash range octet values out of range (0-255): {}", range);
            return Collections.emptyList();
        }

        if (start > end) {
            logger.warn("Dash range start ({}) is greater than end ({}): {}", start, end, range);
            return Collections.emptyList();
        }

        List<String> ips = new ArrayList<>();
        for (int i = start; i <= end; i++) {
            ips.add(prefix + "." + i);
        }
        return ips;
    }

    /**
     * Parses a host (hostname or IP) with an optional port and builds an HTTPS URL.
     * Supports IPv4, IPv6 (bracketed and bare), and hostnames.
     *
     * @param hostPort host string, optionally followed by {@code :port}
     * @return normalized HTTPS URL, or {@code null} if parsing fails
     */
    private static String parseHostPort(String hostPort) {
        String host;
        int port = 443;

        if (hostPort.startsWith("[")) {
            // Bracketed IPv6: [addr] or [addr]:port
            int closeBracket = hostPort.indexOf(']');
            if (closeBracket < 0) {
                logger.warn("Missing closing bracket in IPv6 address: {}", hostPort);
                return null;
            }
            host = hostPort.substring(1, closeBracket); // strip brackets
            String remainder = hostPort.substring(closeBracket + 1);
            if (remainder.startsWith(":")) {
                try {
                    port = Integer.parseInt(remainder.substring(1));
                } catch (NumberFormatException e) {
                    logger.warn("Invalid port in bracketed IPv6 target: {}", hostPort);
                    return null;
                }
            } else if (!remainder.isEmpty()) {
                logger.warn("Unexpected characters after closing bracket: {}", hostPort);
                return null;
            }
            // host is the bare IPv6 address; buildUrl will add brackets
            return buildUrl(host, port);
        }

        if (isBareIpv6(hostPort)) {
            // Bare IPv6 address without brackets or port
            host = hostPort;
            return buildUrl(host, port);
        }

        // IPv4 or hostname with optional :port
        int lastColon = hostPort.lastIndexOf(':');
        if (lastColon > 0) {
            String possiblePort = hostPort.substring(lastColon + 1);
            try {
                port = Integer.parseInt(possiblePort);
                host = hostPort.substring(0, lastColon);
            } catch (NumberFormatException e) {
                // Not a port number; treat the whole string as a hostname
                host = hostPort;
                port = 443;
            }
        } else {
            host = hostPort;
        }

        if (host.isEmpty()) {
            logger.warn("Empty host in target: {}", hostPort);
            return null;
        }

        return buildUrl(host, port);
    }

    /**
     * Builds an HTTPS URL from a host and port.
     * IPv6 addresses are wrapped in brackets per RFC 3986.
     */
    private static String buildUrl(String host, int port) {
        if (isBareIpv6(host)) {
            // IPv6 address — wrap in brackets for URL
            return "https://[" + host + "]:" + port + "/";
        }
        return "https://" + host + ":" + port + "/";
    }

    /**
     * Detects whether a string is a bare (un-bracketed) IPv6 address.
     * A bare IPv6 address contains more than one colon and no "://" scheme prefix.
     */
    static boolean isBareIpv6(String s) {
        if (s == null || s.contains("://")) {
            return false;
        }
        // Count colons — IPv6 has at least 2 colons (e.g. ::1)
        int colonCount = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == ':') {
                colonCount++;
                if (colonCount > 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Converts a BigInteger IP address to its string representation.
     * Uses {@link InetAddress#getByAddress(byte[])} for protocol-agnostic formatting.
     */
    private static String bigIntegerToIp(BigInteger ip, int totalBits) {
        int byteLen = totalBits / 8;
        byte[] raw = ip.toByteArray();

        // BigInteger may produce extra leading zero byte or fewer bytes than needed
        byte[] padded = new byte[byteLen];
        if (raw.length == byteLen) {
            padded = raw;
        } else if (raw.length > byteLen) {
            // Strip leading sign byte(s)
            System.arraycopy(raw, raw.length - byteLen, padded, 0, byteLen);
        } else {
            // Pad with leading zeros
            System.arraycopy(raw, 0, padded, byteLen - raw.length, raw.length);
        }

        try {
            return InetAddress.getByAddress(padded).getHostAddress();
        } catch (UnknownHostException e) {
            // Should not happen for valid byte arrays
            throw new IllegalStateException("Failed to format IP address", e);
        }
    }

    /**
     * Strips IPv6 brackets from a host string if present.
     * For example, {@code [::1]} becomes {@code ::1}.
     * IPv4 addresses and hostnames are returned unchanged.
     *
     * @param host the host string, possibly with IPv6 brackets
     * @return the host string without brackets
     */
    public static String stripBrackets(String host) {
        if (host != null && host.startsWith("[") && host.endsWith("]")) {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }
}
