package com.mps.deepviolettools.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link TargetParser}.
 */
class TargetParserTest {

    // -------------------------------------------------------------------------
    // parse(String) — comma- and newline-separated input
    // -------------------------------------------------------------------------

    @Test
    void parse_nullInput_returnsEmptyList() {
        List<String> result = TargetParser.parse(null);
        assertNotNull(result);
        assertTrue(result.isEmpty(), "null input should yield an empty list");
    }

    @Test
    void parse_emptyString_returnsEmptyList() {
        List<String> result = TargetParser.parse("");
        assertNotNull(result);
        assertTrue(result.isEmpty(), "empty string should yield an empty list");
    }

    @Test
    void parse_blankString_returnsEmptyList() {
        List<String> result = TargetParser.parse("   \t  ");
        assertNotNull(result);
        assertTrue(result.isEmpty(), "blank string should yield an empty list");
    }

    @Test
    void parse_singleBareHostname_returnsOneUrl() {
        List<String> result = TargetParser.parse("example.com");
        assertEquals(1, result.size());
        assertEquals("https://example.com:443/", result.get(0));
    }

    @Test
    void parse_commaSeparatedHostnames_returnsAllUrls() {
        List<String> result = TargetParser.parse("example.com,foo.org,bar.net");
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
        assertEquals("https://bar.net:443/", result.get(2));
    }

    @Test
    void parse_newlineSeparatedHostnames_returnsAllUrls() {
        List<String> result = TargetParser.parse("example.com\nfoo.org\nbar.net");
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
        assertEquals("https://bar.net:443/", result.get(2));
    }

    @Test
    void parse_crlfNewlineSeparated_returnsAllUrls() {
        List<String> result = TargetParser.parse("example.com\r\nfoo.org\r\nbar.net");
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
        assertEquals("https://bar.net:443/", result.get(2));
    }

    @Test
    void parse_mixedCommaAndNewline_returnsAllUrls() {
        List<String> result = TargetParser.parse("example.com,foo.org\nbar.net");
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
        assertEquals("https://bar.net:443/", result.get(2));
    }

    @Test
    void parse_leadingAndTrailingWhitespaceAroundTokens_handledCorrectly() {
        List<String> result = TargetParser.parse("  example.com  ,  foo.org  ");
        assertEquals(2, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
    }

    @Test
    void parse_cidrNotation_returnsFirstExpandedHost() {
        // parse() calls normalizeTarget() per token, which returns only the first
        // expanded IP for CIDR notation. Full expansion requires parseFile().
        List<String> result = TargetParser.parse("192.168.1.0/24");
        assertEquals(1, result.size());
        assertEquals("https://192.168.1.1:443/", result.get(0));
    }

    @Test
    void parse_dashRange_returnsFirstExpandedHost() {
        // parse() calls normalizeTarget() per token, which returns only the first
        // expanded IP for dash ranges. Full expansion requires parseFile().
        List<String> result = TargetParser.parse("10.0.2.1-50");
        assertEquals(1, result.size());
        assertEquals("https://10.0.2.1:443/", result.get(0));
    }

    @Test
    void parse_mixedTargetTypes_eachTokenProducesOneUrl() {
        List<String> result = TargetParser.parse("example.com,10.0.0.1-3,https://secure.example.org/");
        // parse() uses normalizeTarget() per token, so CIDR/dash-range tokens each
        // yield only the first expanded host rather than the full expansion.
        // example.com -> 1 URL
        // 10.0.0.1-3  -> 1 URL (first expanded host: 10.0.0.1)
        // https://... -> 1 URL as-is
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://10.0.0.1:443/", result.get(1));
        assertEquals("https://secure.example.org/", result.get(2));
    }

    // -------------------------------------------------------------------------
    // normalizeTarget(String) — individual target formats
    // -------------------------------------------------------------------------

    @Test
    void normalizeTarget_null_returnsNull() {
        assertNull(TargetParser.normalizeTarget(null));
    }

    @Test
    void normalizeTarget_emptyString_returnsNull() {
        assertNull(TargetParser.normalizeTarget(""));
    }

    @Test
    void normalizeTarget_blankString_returnsNull() {
        assertNull(TargetParser.normalizeTarget("   "));
    }

    @Test
    void normalizeTarget_bareHostname_addsDefaultPort() {
        assertEquals("https://example.com:443/", TargetParser.normalizeTarget("example.com"));
    }

    @Test
    void normalizeTarget_hostnameWithPort_usesSuppliedPort() {
        assertEquals("https://example.com:8443/", TargetParser.normalizeTarget("example.com:8443"));
    }

    @Test
    void normalizeTarget_hostnameWithPort80_usesPort80() {
        assertEquals("https://example.com:80/", TargetParser.normalizeTarget("example.com:80"));
    }

    @Test
    void normalizeTarget_ipAddress_addsDefaultPort() {
        assertEquals("https://10.0.1.5:443/", TargetParser.normalizeTarget("10.0.1.5"));
    }

    @Test
    void normalizeTarget_ipAddressWithPort_usesSuppliedPort() {
        assertEquals("https://10.0.1.5:8443/", TargetParser.normalizeTarget("10.0.1.5:8443"));
    }

    @Test
    void normalizeTarget_cidrSlash32_returnsSingleHost() {
        // /32 is a single host — normalizeTarget returns only the first (and only) result
        assertEquals("https://10.0.0.1:443/", TargetParser.normalizeTarget("10.0.0.1/32"));
    }

    @Test
    void normalizeTarget_cidrSlash31_returnsFirstOfTwoHosts() {
        // /31: two addresses included (RFC 3021); normalizeTarget returns the first
        assertEquals("https://10.0.0.0:443/", TargetParser.normalizeTarget("10.0.0.0/31"));
    }

    @Test
    void normalizeTarget_cidrSlash24_returnsFirstExpandedHost() {
        // /24 expands to 254 hosts; normalizeTarget returns only the first
        assertEquals("https://10.0.1.1:443/", TargetParser.normalizeTarget("10.0.1.0/24"));
    }

    @Test
    void normalizeTarget_dashRange_returnsFirstExpandedHost() {
        assertEquals("https://10.0.2.1:443/", TargetParser.normalizeTarget("10.0.2.1-50"));
    }

    @Test
    void normalizeTarget_fullHttpsUrl_returnedAsIs() {
        String url = "https://example.com/";
        assertEquals(url, TargetParser.normalizeTarget(url));
    }

    @Test
    void normalizeTarget_fullHttpsUrlWithPath_returnedAsIs() {
        String url = "https://example.com:8443/some/path";
        assertEquals(url, TargetParser.normalizeTarget(url));
    }

    @Test
    void normalizeTarget_fullHttpsUrlUpperCase_returnedAsIs() {
        // URL detection is case-insensitive
        String url = "HTTPS://example.com/";
        assertEquals(url, TargetParser.normalizeTarget(url));
    }

    @Test
    void normalizeTarget_invalidCidr_returnsNull() {
        // prefix length out of range
        assertNull(TargetParser.normalizeTarget("10.0.0.0/33"));
    }

    @Test
    void normalizeTarget_cidrWithNonNumericPrefix_returnsNull() {
        assertNull(TargetParser.normalizeTarget("10.0.0.0/abc"));
    }

    // -------------------------------------------------------------------------
    // CIDR expansion — /24, /32, /31 (via parseFile for full expansion)
    // -------------------------------------------------------------------------

    @Test
    void parseFile_cidrSlash24_produces254Hosts(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("cidr24.txt");
        Files.writeString(file, "10.0.1.0/24\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(254, result.size(),
                "/24 should expand to 254 usable host addresses");
        assertEquals("https://10.0.1.1:443/", result.get(0));
        assertEquals("https://10.0.1.254:443/", result.get(253));
    }

    @Test
    void parseFile_cidrSlash24_excludesNetworkAndBroadcast(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("cidr24.txt");
        Files.writeString(file, "10.0.1.0/24\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertFalse(result.contains("https://10.0.1.0:443/"),
                "Network address should be excluded from /24 expansion");
        assertFalse(result.contains("https://10.0.1.255:443/"),
                "Broadcast address should be excluded from /24 expansion");
    }

    @Test
    void parseFile_cidrSlash32_produces1Host(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("cidr32.txt");
        Files.writeString(file, "192.168.0.5/32\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(1, result.size(),
                "/32 should expand to exactly 1 host");
        assertEquals("https://192.168.0.5:443/", result.get(0));
    }

    @Test
    void parseFile_cidrSlash31_produces2Hosts(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("cidr31.txt");
        Files.writeString(file, "10.0.0.0/31\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(2, result.size(),
                "/31 should expand to 2 addresses (RFC 3021 point-to-point)");
        assertEquals("https://10.0.0.0:443/", result.get(0));
        assertEquals("https://10.0.0.1:443/", result.get(1));
    }

    @Test
    void parseFile_cidrSlash30_produces2UsableHosts(@TempDir Path tempDir) throws IOException {
        // /30: 4 addresses total, minus network and broadcast = 2 usable
        Path file = tempDir.resolve("cidr30.txt");
        Files.writeString(file, "10.0.0.0/30\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(2, result.size(),
                "/30 should expand to 2 usable host addresses");
        assertEquals("https://10.0.0.1:443/", result.get(0));
        assertEquals("https://10.0.0.2:443/", result.get(1));
    }

    @Test
    void parse_invalidCidr_prefixTooLarge_returnsEmpty() {
        // normalizeTarget returns null for /33; parse() skips null results
        List<String> result = TargetParser.parse("10.0.0.0/33");
        assertTrue(result.isEmpty(), "CIDR /33 should be skipped as invalid");
    }

    @Test
    void parse_invalidCidr_prefixNegative_returnsEmpty() {
        List<String> result = TargetParser.parse("10.0.0.0/-1");
        assertTrue(result.isEmpty(), "CIDR /-1 should be skipped as invalid");
    }

    @Test
    void parse_invalidCidr_nonNumericPrefix_returnsEmpty() {
        List<String> result = TargetParser.parse("10.0.0.0/xyz");
        assertTrue(result.isEmpty(), "CIDR with non-numeric prefix should be skipped");
    }

    // -------------------------------------------------------------------------
    // Dash range expansion (via parseFile for full expansion)
    // -------------------------------------------------------------------------

    @Test
    void parseFile_dashRange1To50_produces50Hosts(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("dash50.txt");
        Files.writeString(file, "10.0.2.1-50\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(50, result.size(),
                "10.0.2.1-50 should expand to 50 host addresses");
        assertEquals("https://10.0.2.1:443/", result.get(0));
        assertEquals("https://10.0.2.50:443/", result.get(49));
    }

    @Test
    void parseFile_dashRangeSingleAddress_produces1Host(@TempDir Path tempDir) throws IOException {
        // start == end: a range of exactly one address
        Path file = tempDir.resolve("dash1.txt");
        Files.writeString(file, "10.0.0.5-5\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(1, result.size(),
                "Dash range where start equals end should expand to 1 host");
        assertEquals("https://10.0.0.5:443/", result.get(0));
    }

    @Test
    void parseFile_dashRangeFullOctet_produces256Hosts(@TempDir Path tempDir) throws IOException {
        // 0-255: full last octet
        Path file = tempDir.resolve("dash256.txt");
        Files.writeString(file, "10.0.0.0-255\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(256, result.size(),
                "0-255 should expand to 256 addresses");
        assertEquals("https://10.0.0.0:443/", result.get(0));
        assertEquals("https://10.0.0.255:443/", result.get(255));
    }

    @Test
    void parse_dashRangeStartGreaterThanEnd_returnsEmpty() {
        // normalizeTarget returns null for invalid range; parse() skips null results
        List<String> result = TargetParser.parse("10.0.0.50-10");
        assertTrue(result.isEmpty(),
                "Dash range where start > end should be skipped as invalid");
    }

    @Test
    void parse_dashRangeOctetAbove255_returnsEmpty() {
        // 300 is out of valid octet range
        List<String> result = TargetParser.parse("10.0.0.1-300");
        assertTrue(result.isEmpty(),
                "Dash range with end > 255 should be skipped as invalid");
    }

    // -------------------------------------------------------------------------
    // parseFile(File) — file with targets, comments, blank lines
    // -------------------------------------------------------------------------

    @Test
    void parseFile_fileWithTargets_returnsAllUrls(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file,
                "example.com\n" +
                "foo.org\n" +
                "bar.net\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
        assertEquals("https://bar.net:443/", result.get(2));
    }

    @Test
    void parseFile_commentsAreSkipped(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file,
                "# This is a comment\n" +
                "example.com\n" +
                "# Another comment\n" +
                "foo.org\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(2, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
    }

    @Test
    void parseFile_blankLinesAreSkipped(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file,
                "\n" +
                "example.com\n" +
                "\n" +
                "foo.org\n" +
                "\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(2, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
    }

    @Test
    void parseFile_mixedCommentsAndBlankLines(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file,
                "# Scan targets for 2026-Q1\n" +
                "\n" +
                "example.com\n" +
                "  \n" +           // whitespace-only line
                "# Servers in DMZ\n" +
                "10.0.0.1\n" +
                "10.0.0.2:8443\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(3, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://10.0.0.1:443/", result.get(1));
        assertEquals("https://10.0.0.2:8443/", result.get(2));
    }

    @Test
    void parseFile_withCidrLine_expandsHosts(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file,
                "# CIDR expansion\n" +
                "10.1.1.0/30\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        // /30 -> 2 usable hosts
        assertEquals(2, result.size());
        assertEquals("https://10.1.1.1:443/", result.get(0));
        assertEquals("https://10.1.1.2:443/", result.get(1));
    }

    @Test
    void parseFile_withDashRangeLine_expandsHosts(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file, "10.0.5.1-5\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(5, result.size());
        assertEquals("https://10.0.5.1:443/", result.get(0));
        assertEquals("https://10.0.5.5:443/", result.get(4));
    }

    @Test
    void parseFile_emptyFile_returnsEmptyList(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("empty.txt");
        Files.writeString(file, "");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertNotNull(result);
        assertTrue(result.isEmpty(), "Empty file should yield an empty list");
    }

    @Test
    void parseFile_onlyComments_returnsEmptyList(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("comments.txt");
        Files.writeString(file,
                "# comment 1\n" +
                "# comment 2\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertTrue(result.isEmpty(), "File with only comments should yield an empty list");
    }

    @Test
    void parseFile_nonExistentFile_throwsIOException() {
        File missing = new File("/tmp/this-file-does-not-exist-deepviolet.txt");
        assertThrows(IOException.class, () -> TargetParser.parseFile(missing),
                "parseFile should throw IOException for a non-existent file");
    }

    @Test
    void parseFile_withFullHttpsUrl_returnedAsIs(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("targets.txt");
        Files.writeString(file, "https://secure.example.com/\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(1, result.size());
        assertEquals("https://secure.example.com/", result.get(0));
    }

    // -------------------------------------------------------------------------
    // Edge cases — empty strings, whitespace, mixed valid/invalid
    // -------------------------------------------------------------------------

    @Test
    void parse_onlyCommas_returnsEmptyList() {
        List<String> result = TargetParser.parse(",,,");
        assertTrue(result.isEmpty(), "Input of only commas should yield an empty list");
    }

    @Test
    void parse_onlyNewlines_returnsEmptyList() {
        List<String> result = TargetParser.parse("\n\n\n");
        assertTrue(result.isEmpty(), "Input of only newlines should yield an empty list");
    }

    @Test
    void parse_validAndInvalidTargetsMixed_validOnesReturned() {
        // Invalid CIDR is skipped; valid hostname is included
        List<String> result = TargetParser.parse("example.com,10.0.0.0/33");
        assertEquals(1, result.size());
        assertEquals("https://example.com:443/", result.get(0));
    }

    @Test
    void parse_hostnameWithNonNumericAfterColon_treatsWholeStringAsHostname() {
        // "example.com:notaport" — the part after ":" is not a number, so the
        // entire string is used as a hostname with default port 443
        List<String> result = TargetParser.parse("example.com:notaport");
        assertEquals(1, result.size());
        assertEquals("https://example.com:notaport:443/", result.get(0));
    }

    @Test
    void normalizeTarget_ipWithPort1_usesPort1() {
        assertEquals("https://10.0.0.1:1/", TargetParser.normalizeTarget("10.0.0.1:1"));
    }

    @Test
    void normalizeTarget_ipWithPort65535_usesPort65535() {
        assertEquals("https://10.0.0.1:65535/", TargetParser.normalizeTarget("10.0.0.1:65535"));
    }

    @Test
    void parse_commentLinesAreSkipped() {
        List<String> result = TargetParser.parse(
                "# This is a comment\nexample.com\n# Another comment\nfoo.org");
        assertEquals(2, result.size());
        assertEquals("https://example.com:443/", result.get(0));
        assertEquals("https://foo.org:443/", result.get(1));
    }

    @Test
    void parse_onlyComments_returnsEmptyList() {
        List<String> result = TargetParser.parse("# comment 1\n# comment 2");
        assertTrue(result.isEmpty(), "Input of only comments should yield an empty list");
    }

    // -------------------------------------------------------------------------
    // IPv6 address literal support
    // -------------------------------------------------------------------------

    @Test
    void normalizeTarget_bracketedIpv6_addsDefaultPort() {
        assertEquals("https://[::1]:443/", TargetParser.normalizeTarget("[::1]"));
    }

    @Test
    void normalizeTarget_bracketedIpv6WithPort_usesSuppliedPort() {
        assertEquals("https://[::1]:8443/", TargetParser.normalizeTarget("[::1]:8443"));
    }

    @Test
    void normalizeTarget_bracketedFullIpv6_addsDefaultPort() {
        assertEquals("https://[2001:db8::1]:443/",
                TargetParser.normalizeTarget("[2001:db8::1]"));
    }

    @Test
    void normalizeTarget_bracketedFullIpv6WithPort_usesSuppliedPort() {
        assertEquals("https://[2001:db8::1]:8443/",
                TargetParser.normalizeTarget("[2001:db8::1]:8443"));
    }

    @Test
    void normalizeTarget_bareIpv6Loopback_wrapsBrackets() {
        assertEquals("https://[::1]:443/", TargetParser.normalizeTarget("::1"));
    }

    @Test
    void normalizeTarget_bareIpv6Full_wrapsBrackets() {
        assertEquals("https://[2001:db8::1]:443/",
                TargetParser.normalizeTarget("2001:db8::1"));
    }

    @Test
    void normalizeTarget_bareIpv6AllZeros_wrapsBrackets() {
        // :: is the all-zeros address
        assertEquals("https://[::]:443/", TargetParser.normalizeTarget("::"));
    }

    @Test
    void normalizeTarget_ipv6HttpsUrl_returnedAsIs() {
        String url = "https://[::1]:443/";
        assertEquals(url, TargetParser.normalizeTarget(url));
    }

    @Test
    void parse_bracketedIpv6InList_returnsCorrectUrl() {
        List<String> result = TargetParser.parse("[::1],[2001:db8::1]:8443");
        assertEquals(2, result.size());
        assertEquals("https://[::1]:443/", result.get(0));
        assertEquals("https://[2001:db8::1]:8443/", result.get(1));
    }

    @Test
    void parse_bareIpv6InList_returnsCorrectUrl() {
        List<String> result = TargetParser.parse("::1\n2001:db8::1");
        assertEquals(2, result.size());
        assertEquals("https://[::1]:443/", result.get(0));
        assertEquals("https://[2001:db8::1]:443/", result.get(1));
    }

    @Test
    void parse_mixedIpv4AndIpv6_returnsAllUrls() {
        List<String> result = TargetParser.parse(
                "10.0.0.1\n[::1]:8443\nexample.com\n2001:db8::1");
        assertEquals(4, result.size());
        assertEquals("https://10.0.0.1:443/", result.get(0));
        assertEquals("https://[::1]:8443/", result.get(1));
        assertEquals("https://example.com:443/", result.get(2));
        assertEquals("https://[2001:db8::1]:443/", result.get(3));
    }

    // -------------------------------------------------------------------------
    // IPv6 CIDR expansion
    // -------------------------------------------------------------------------

    @Test
    void normalizeTarget_ipv6CidrSlash128_returnsSingleHost() {
        // /128 is a single IPv6 host
        String result = TargetParser.normalizeTarget("::1/128");
        assertEquals("https://[0:0:0:0:0:0:0:1]:443/", result);
    }

    @Test
    void parseFile_ipv6CidrSlash126_produces4Hosts(@TempDir Path tempDir) throws IOException {
        // /126: 4 addresses, IPv6 does not exclude network/broadcast
        Path file = tempDir.resolve("ipv6cidr.txt");
        Files.writeString(file, "2001:db8::0/126\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(4, result.size(), "/126 should expand to 4 IPv6 addresses");
    }

    @Test
    void parseFile_ipv6CidrSlash120_produces256Hosts(@TempDir Path tempDir) throws IOException {
        // /120: 256 addresses
        Path file = tempDir.resolve("ipv6cidr120.txt");
        Files.writeString(file, "2001:db8::0/120\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(256, result.size(), "/120 should expand to 256 IPv6 addresses");
    }

    @Test
    void parse_ipv6CidrPrefixTooLarge_returnsEmpty() {
        List<String> result = TargetParser.parse("::1/129");
        assertTrue(result.isEmpty(), "IPv6 CIDR /129 should be rejected");
    }

    // -------------------------------------------------------------------------
    // CIDR expansion limit
    // -------------------------------------------------------------------------

    private int savedMaxExpansion;

    @BeforeEach
    void saveMaxExpansion() {
        savedMaxExpansion = TargetParser.getMaxCidrExpansion();
    }

    @AfterEach
    void restoreMaxExpansion() {
        TargetParser.setMaxCidrExpansion(savedMaxExpansion);
    }

    @Test
    void expandCidr_exceedsMaxExpansion_returnsEmpty() {
        TargetParser.setMaxCidrExpansion(10);
        // /24 would expand to 254 hosts, exceeding limit of 10
        assertNull(TargetParser.normalizeTarget("10.0.0.0/24"));
    }

    @Test
    void expandCidr_withinMaxExpansion_succeeds(@TempDir Path tempDir) throws IOException {
        TargetParser.setMaxCidrExpansion(10);
        // /30 expands to 2 hosts, within limit
        Path file = tempDir.resolve("small.txt");
        Files.writeString(file, "10.0.0.0/30\n");
        List<String> result = TargetParser.parseFile(file.toFile());
        assertEquals(2, result.size());
    }

    @Test
    void expandCidr_ipv6ExceedsMaxExpansion_returnsEmpty() {
        TargetParser.setMaxCidrExpansion(100);
        // /120 would expand to 256 hosts, exceeding limit of 100
        assertNull(TargetParser.normalizeTarget("2001:db8::/120"));
    }

    // -------------------------------------------------------------------------
    // isBareIpv6 helper
    // -------------------------------------------------------------------------

    @Test
    void isBareIpv6_loopback_true() {
        assertTrue(TargetParser.isBareIpv6("::1"));
    }

    @Test
    void isBareIpv6_fullAddress_true() {
        assertTrue(TargetParser.isBareIpv6("2001:db8::1"));
    }

    @Test
    void isBareIpv6_allZeros_true() {
        assertTrue(TargetParser.isBareIpv6("::"));
    }

    @Test
    void isBareIpv6_ipv4_false() {
        assertFalse(TargetParser.isBareIpv6("10.0.0.1"));
    }

    @Test
    void isBareIpv6_hostname_false() {
        assertFalse(TargetParser.isBareIpv6("example.com"));
    }

    @Test
    void isBareIpv6_hostnameWithPort_false() {
        assertFalse(TargetParser.isBareIpv6("example.com:8443"));
    }

    @Test
    void isBareIpv6_urlScheme_false() {
        assertFalse(TargetParser.isBareIpv6("https://[::1]:443/"));
    }

    @Test
    void isBareIpv6_null_false() {
        assertFalse(TargetParser.isBareIpv6(null));
    }

    // -------------------------------------------------------------------------
    // stripBrackets helper
    // -------------------------------------------------------------------------

    @Test
    void stripBrackets_bracketedIpv6_stripsBrackets() {
        assertEquals("::1", TargetParser.stripBrackets("[::1]"));
    }

    @Test
    void stripBrackets_ipv4_unchanged() {
        assertEquals("10.0.0.1", TargetParser.stripBrackets("10.0.0.1"));
    }

    @Test
    void stripBrackets_hostname_unchanged() {
        assertEquals("example.com", TargetParser.stripBrackets("example.com"));
    }

    @Test
    void stripBrackets_null_returnsNull() {
        assertNull(TargetParser.stripBrackets(null));
    }

    // -------------------------------------------------------------------------
    // Mixed IPv4/IPv6 file parsing
    // -------------------------------------------------------------------------

    @Test
    void parseFile_mixedIpv4Ipv6Targets(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("mixed.txt");
        Files.writeString(file,
                "# Mixed IPv4 and IPv6 targets\n" +
                "10.0.0.1\n" +
                "[::1]\n" +
                "example.com\n" +
                "[2001:db8::1]:8443\n" +
                "10.0.0.0/30\n");

        List<String> result = TargetParser.parseFile(file.toFile());
        // 1 IPv4 + 1 IPv6 + 1 hostname + 1 IPv6 with port + 2 from /30
        assertEquals(6, result.size());
        assertEquals("https://10.0.0.1:443/", result.get(0));
        assertEquals("https://[::1]:443/", result.get(1));
        assertEquals("https://example.com:443/", result.get(2));
        assertEquals("https://[2001:db8::1]:8443/", result.get(3));
        assertEquals("https://10.0.0.1:443/", result.get(4));
        assertEquals("https://10.0.0.2:443/", result.get(5));
    }
}
