package com.mps.deepviolettools.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.model.ScanResult.SourceProvenance;

/**
 * Unit tests for {@link ReportExporter}, including host index methods
 * and encrypted .dvscan file format.
 */
class ReportExporterTest {

    @TempDir
    File tempDir;

    @BeforeAll
    static void initEncryption() {
        FontPreferences.ensureEncryptionSeed();
    }

    // ---- displayName tests ----

    @Test
    void displayName_stripsHttpsSchemeTrailingSlashAndDefaultPort() {
        assertEquals("example.com",
                ReportExporter.displayName("https://example.com:443/"));
    }

    @Test
    void displayName_keepsNonDefaultPort() {
        assertEquals("example.com:8443",
                ReportExporter.displayName("https://example.com:8443/"));
    }

    @Test
    void displayName_stripsSchemeOnly() {
        assertEquals("expired.badssl.com",
                ReportExporter.displayName("https://expired.badssl.com"));
    }

    @Test
    void displayName_handlesIpAddress() {
        assertEquals("192.168.1.5",
                ReportExporter.displayName("https://192.168.1.5:443/"));
    }

    @Test
    void displayName_handlesNullGracefully() {
        assertEquals("", ReportExporter.displayName(null));
    }

    @Test
    void displayName_handlesHttpScheme() {
        assertEquals("example.com",
                ReportExporter.displayName("http://example.com/"));
    }

    // ---- buildHostIndexBody tests ----

    @Test
    void buildHostIndexBody_emptyResults() {
        ScanResult result = new ScanResult();
        result.setTotalTargets(0);
        String body = ReportExporter.buildHostIndexBody(result, 20);
        assertEquals("", body);
    }

    @Test
    void buildHostIndexBody_singleHost() {
        ScanResult result = makeScanResult("https://example.com:443/");
        String body = ReportExporter.buildHostIndexBody(result, 20);
        assertNotNull(body);
        assertFalse(body.isEmpty());
        // Single host spans all 20 columns
        assertTrue(body.contains("Col"), "Should contain column reference");
        assertTrue(body.contains("example.com"), "Should contain display name");
    }

    @Test
    void buildHostIndexBody_caseA_fourHosts() {
        ScanResult result = makeScanResult(
                "https://expired.badssl.com:443/",
                "https://wrong.host.badssl.com:443/",
                "https://self-signed.badssl.com:443/",
                "https://untrusted-root.badssl.com:443/");
        String body = ReportExporter.buildHostIndexBody(result, 20);
        assertNotNull(body);
        // All four hosts should appear
        assertTrue(body.contains("expired.badssl.com"));
        assertTrue(body.contains("wrong.host.badssl.com"));
        assertTrue(body.contains("self-signed.badssl.com"));
        assertTrue(body.contains("untrusted-root.badssl.com"));
        // Should use range format (Case A)
        assertTrue(body.contains("Col"));
    }

    @Test
    void buildHostIndexBody_caseA_exactly20Hosts() {
        String[] urls = new String[20];
        for (int i = 0; i < 20; i++) {
            urls[i] = "https://host" + (i + 1) + ".example.com:443/";
        }
        ScanResult result = makeScanResult(urls);
        String body = ReportExporter.buildHostIndexBody(result, 20);
        assertNotNull(body);
        // 20 hosts = 20 blocks, so each host gets exactly 1 column (no range)
        assertTrue(body.contains("host1.example.com"));
        assertTrue(body.contains("host20.example.com"));
        // Should NOT contain "Column Mapping" (Case B marker)
        assertFalse(body.contains("Column Mapping"));
    }

    @Test
    void buildHostIndexBody_caseB_manyHosts() {
        String[] urls = new String[50];
        for (int i = 0; i < 50; i++) {
            urls[i] = "https://192.168.1." + (i + 1) + ":443/";
        }
        ScanResult result = makeScanResult(urls);
        String body = ReportExporter.buildHostIndexBody(result, 20);
        assertNotNull(body);
        // Case B markers
        assertTrue(body.contains("Column Mapping"),
                "Many hosts should trigger Case B with Column Mapping");
        assertTrue(body.contains("Host Directory"),
                "Many hosts should trigger Case B with Host Directory");
        assertTrue(body.contains("50 hosts across 20 columns"));
        // First and last host should appear in directory
        assertTrue(body.contains("192.168.1.1"));
        assertTrue(body.contains("192.168.1.50"));
    }

    @Test
    void buildHostIndex_includesHeader() {
        ScanResult result = makeScanResult("https://example.com:443/");
        String full = ReportExporter.buildHostIndex(result, 20);
        assertTrue(full.startsWith("[Host Index]\n"),
                "Should start with [Host Index] header");
    }

    @Test
    void buildHostIndex_emptyForNoResults() {
        ScanResult result = new ScanResult();
        result.setTotalTargets(0);
        assertEquals("", ReportExporter.buildHostIndex(result, 20));
    }

    // ---- encrypted .dvscan tests ----

    @Test
    void saveScanFile_roundTrip() throws IOException {
        ScanResult original = makeScanResult(
                "https://example.com:443/",
                "https://expired.badssl.com:443/");
        // Set an error on the second host
        original.getResults().get(1).setErrorMessage("certificate expired");
        original.setErrorCount(1);
        original.setSuccessCount(1);

        File file = new File(tempDir, "test.dvscan");
        ReportExporter.saveScanFile(file, original);

        ScanResult loaded = ReportExporter.loadScanFile(file);
        assertEquals(original.getTotalTargets(), loaded.getTotalTargets());
        assertEquals(original.getSuccessCount(), loaded.getSuccessCount());
        assertEquals(original.getErrorCount(), loaded.getErrorCount());
        assertEquals(original.getResults().size(), loaded.getResults().size());
        assertEquals(original.getResults().get(0).getTargetUrl(),
                loaded.getResults().get(0).getTargetUrl());
        assertEquals(original.getResults().get(1).getErrorMessage(),
                loaded.getResults().get(1).getErrorMessage());
    }

    @Test
    void saveScanFile_fileFormat() throws IOException {
        ScanResult result = makeScanResult("https://example.com:443/");
        File file = new File(tempDir, "format.dvscan");
        ReportExporter.saveScanFile(file, result);

        byte[] data = Files.readAllBytes(file.toPath());
        // Minimum: header (5) + IV (12) + auth tag (16) = 33 bytes
        assertTrue(data.length >= 33, "File must be at least 33 bytes");
        // Magic = "DVSC"
        assertEquals(0x44, data[0] & 0xFF);
        assertEquals(0x56, data[1] & 0xFF);
        assertEquals(0x53, data[2] & 0xFF);
        assertEquals(0x43, data[3] & 0xFF);
        // Version = 0x01
        assertEquals(0x01, data[4] & 0xFF);
    }

    @Test
    void loadScanFile_tamperedFile() throws IOException {
        ScanResult result = makeScanResult("https://example.com:443/");
        File file = new File(tempDir, "tampered.dvscan");
        ReportExporter.saveScanFile(file, result);

        // Flip a byte in the encrypted payload
        byte[] data = Files.readAllBytes(file.toPath());
        data[data.length - 1] ^= 0xFF;
        Files.write(file.toPath(), data);

        IOException ex = assertThrows(IOException.class,
                () -> ReportExporter.loadScanFile(file));
        assertTrue(ex.getMessage().contains("tampered"),
                "Should mention tampering: " + ex.getMessage());
    }

    @Test
    void loadScanFile_truncatedFile() {
        File file = new File(tempDir, "truncated.dvscan");
        try {
            Files.write(file.toPath(), new byte[] { 0x44, 0x56 });
        } catch (IOException e) {
            fail("Setup failed: " + e.getMessage());
        }

        IOException ex = assertThrows(IOException.class,
                () -> ReportExporter.loadScanFile(file));
        assertTrue(ex.getMessage().contains("too small"),
                "Should mention file too small: " + ex.getMessage());
    }

    @Test
    void loadScanFile_badMagic() {
        File file = new File(tempDir, "badmagic.dvscan");
        try {
            Files.write(file.toPath(), new byte[] {
                    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00 });
        } catch (IOException e) {
            fail("Setup failed: " + e.getMessage());
        }

        IOException ex = assertThrows(IOException.class,
                () -> ReportExporter.loadScanFile(file));
        assertTrue(ex.getMessage().contains("bad magic"),
                "Should mention bad magic: " + ex.getMessage());
    }

    @Test
    void loadScanFile_unsupportedVersion() {
        File file = new File(tempDir, "badversion.dvscan");
        try {
            Files.write(file.toPath(), new byte[] {
                    0x44, 0x56, 0x53, 0x43, 0x02, // DVSC + version 2
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00 });
        } catch (IOException e) {
            fail("Setup failed: " + e.getMessage());
        }

        IOException ex = assertThrows(IOException.class,
                () -> ReportExporter.loadScanFile(file));
        assertTrue(ex.getMessage().contains("Unsupported"),
                "Should mention unsupported version: " + ex.getMessage());
    }

    // ---- provenance tests ----

    @Test
    void saveScanFile_returnsProvenance() throws IOException {
        ScanResult result = makeScanResult("https://example.com:443/");
        File file = new File(tempDir, "prov.dvscan");
        SourceProvenance prov = ReportExporter.saveScanFile(file, result);
        assertNotNull(prov);
        assertEquals("prov.dvscan", prov.getFileName());
        assertEquals(file.getAbsolutePath(), prov.getFilePath());
        assertNotNull(prov.getSha256());
        assertEquals(64, prov.getSha256().length());
    }

    @Test
    void loadScanFile_setsScanProvenance() throws IOException {
        ScanResult result = makeScanResult("https://example.com:443/");
        File file = new File(tempDir, "scan-prov.dvscan");
        ReportExporter.saveScanFile(file, result);

        ScanResult loaded = ReportExporter.loadScanFile(file);
        assertNotNull(loaded.getScanSource());
        assertEquals("scan-prov.dvscan", loaded.getScanSource().getFileName());
        assertNotNull(loaded.getScanSource().getSha256());
        assertEquals(64, loaded.getScanSource().getSha256().length());
    }

    @Test
    void saveScanFile_roundTrip_preservesTargetProvenance() throws IOException {
        ScanResult result = makeScanResult("https://example.com:443/");
        result.setTargetSource(new SourceProvenance(
                "targets.txt", "/tmp/targets.txt",
                "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"));
        File file = new File(tempDir, "target-prov.dvscan");
        ReportExporter.saveScanFile(file, result);

        ScanResult loaded = ReportExporter.loadScanFile(file);
        assertNotNull(loaded.getTargetSource());
        assertEquals("targets.txt", loaded.getTargetSource().getFileName());
        assertEquals("/tmp/targets.txt", loaded.getTargetSource().getFilePath());
        assertEquals("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                loaded.getTargetSource().getSha256());
    }

    @Test
    void buildProvenanceText_formatsCorrectly() {
        ScanResult result = makeScanResult("https://example.com:443/");
        result.setTargetSource(new SourceProvenance(
                "targets.txt", "/data/targets.txt",
                "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"));
        result.setScanSource(new SourceProvenance(
                "scan.dvscan", "/data/scan.dvscan",
                "1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff1111aaaa2222bbbb"));
        String text = ReportExporter.buildProvenanceText(result);
        assertTrue(text.contains("Target Source:"), "Should contain 'Target Source:'");
        assertTrue(text.contains("Scan File:"), "Should contain 'Scan File:'");
        assertTrue(text.contains("Target SHA-256:"), "Should contain 'Target SHA-256:'");
        assertTrue(text.contains("Scan SHA-256:"), "Should contain 'Scan SHA-256:'");
        assertTrue(text.contains("targets.txt"));
        assertTrue(text.contains("scan.dvscan"));
    }

    // ---- helpers ----

    private static ScanResult makeScanResult(String... urls) {
        ScanResult result = new ScanResult();
        result.setTotalTargets(urls.length);
        int success = 0;
        for (String url : urls) {
            HostResult hr = new HostResult(url);
            // Mark as successful (no error message set)
            result.addResult(hr);
            success++;
        }
        result.setSuccessCount(success);
        result.setErrorCount(0);
        return result;
    }
}
