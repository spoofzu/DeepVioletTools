package com.mps.deepviolettools.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mps.deepviolettools.model.HeatMapData.HeatMapCell;
import com.mps.deepviolettools.model.HeatMapData.HeatMapRow;

/**
 * Unit tests for {@link ScanResult} heat map builders, including the
 * split security headers / connection / HTTP response builders, the
 * revocation builder, synthetic certificate risk rows, error column tracking,
 * cipher logic, and connection expansion.
 */
class ScanResultTest {

    private static final int N_BLOCKS = 20;

    // ---- Helper factories ----

    private static ScanResult resultWithSecurityHeaders(Map<String, String> headers) {
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");
        hr.setSecurityHeaders(headers);
        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);
        return bsr;
    }

    private static ScanResult resultWithConnProperties(Map<String, String> props) {
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");
        hr.setConnProperties(props);
        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);
        return bsr;
    }

    private static ScanResult resultWithHttpHeaders(Map<String, String> headers) {
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");
        hr.setHttpHeaders(headers);
        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);
        return bsr;
    }

    private static ScanResult resultWithScanTree(ScanNode tree) {
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");
        hr.setScanTree(tree);
        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);
        return bsr;
    }

    // ---- toSecurityHeadersHeatMap ----

    @Test
    void securityHeaders_has7Rows() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Strict-Transport-Security", "max-age=31536000");
        headers.put("Content-Security-Policy", "default-src 'self'");
        headers.put("X-Content-Type-Options", "nosniff");
        headers.put("X-Frame-Options", "DENY");
        headers.put("X-XSS-Protection", "1; mode=block");
        headers.put("Referrer-Policy", "no-referrer");
        headers.put("Permissions-Policy", "camera=()");

        ScanResult bsr = resultWithSecurityHeaders(headers);
        HeatMapData data = bsr.toSecurityHeadersHeatMap(N_BLOCKS);

        assertEquals(7, data.getRows().size());
        assertEquals(HeatMapData.MapType.SECURITY_HEADERS, data.getMapType());
    }

    @Test
    void securityHeaders_presentIsPass_missingIsFail() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Strict-Transport-Security", "max-age=31536000");
        headers.put("Content-Security-Policy", "MISSING");
        // Others not present at all

        ScanResult bsr = resultWithSecurityHeaders(headers);
        HeatMapData data = bsr.toSecurityHeadersHeatMap(N_BLOCKS);

        // First row: HSTS -- present -> should be all pass
        HeatMapRow hstsRow = data.getRows().get(0);
        assertEquals("Strict-Transport-Security", hstsRow.getDescription());
        assertTrue(hstsRow.getCells()[0].getPassCount() > 0);
        assertEquals(0, hstsRow.getCells()[0].getFailCount());

        // Second row: CSP -- MISSING -> should be fail
        HeatMapRow cspRow = data.getRows().get(1);
        assertEquals("Content-Security-Policy", cspRow.getDescription());
        assertTrue(cspRow.getCells()[0].getFailCount() > 0);
        assertEquals(0, cspRow.getCells()[0].getPassCount());
    }

    @Test
    void securityHeaders_empty_returnsNoRows() {
        ScanResult bsr = new ScanResult();
        HeatMapData data = bsr.toSecurityHeadersHeatMap(N_BLOCKS);
        assertTrue(data.getRows().isEmpty());
    }

    // ---- toConnectionHeatMap ----

    @Test
    void connection_excludesSecurityAndHttpGroups() {
        Map<String, String> props = new HashMap<>();
        props.put("DEFLATE_COMPRESSION", "false");

        ScanResult bsr = resultWithConnProperties(props);
        // Also set security headers and http headers -- these should NOT appear
        bsr.getResults().get(0).setSecurityHeaders(Map.of("Strict-Transport-Security", "max-age=31536000"));
        bsr.getResults().get(0).setHttpHeaders(Map.of("Content-Type", "text/html"));

        HeatMapData data = bsr.toConnectionHeatMap(N_BLOCKS);
        assertEquals(HeatMapData.MapType.CONNECTION, data.getMapType());

        // Should only have connection property rows, not security header or HTTP header rows
        for (HeatMapRow row : data.getRows()) {
            assertEquals("CONNECTION PROPERTIES", row.getCategory());
        }
        assertEquals(1, data.getRows().size());
    }

    // ---- toConnectionHeatMap — per-protocol expansion ----

    @Test
    void connection_expandsNegotiatedProtocol() {
        ScanResult bsr = new ScanResult();

        ScanResult.HostResult hr1 = new ScanResult.HostResult("https://host1.com");
        hr1.setConnProperties(Map.of("NEGOTIATED_PROTOCOL", "TLSv1.3"));
        bsr.addResult(hr1);

        ScanResult.HostResult hr2 = new ScanResult.HostResult("https://host2.com");
        hr2.setConnProperties(Map.of("NEGOTIATED_PROTOCOL", "TLSv1.2"));
        bsr.addResult(hr2);

        bsr.setTotalTargets(2);
        bsr.setSuccessCount(2);

        HeatMapData data = bsr.toConnectionHeatMap(N_BLOCKS);

        // Should have 2 rows: NEGOTIATED_PROTOCOL_TLSv1.3 and NEGOTIATED_PROTOCOL_TLSv1.2
        assertEquals(2, data.getRows().size());
        assertTrue(data.getRows().get(0).getId().startsWith("NEGOTIATED_PROTOCOL_"));
        assertTrue(data.getRows().get(1).getId().startsWith("NEGOTIATED_PROTOCOL_"));
    }

    @Test
    void connection_expandsNegotiatedCipherSuite() {
        ScanResult bsr = new ScanResult();

        ScanResult.HostResult hr1 = new ScanResult.HostResult("https://host1.com");
        hr1.setConnProperties(Map.of("NEGOTIATED_CIPHER_SUITE", "TLS_AES_256_GCM_SHA384"));
        bsr.addResult(hr1);

        ScanResult.HostResult hr2 = new ScanResult.HostResult("https://host2.com");
        hr2.setConnProperties(Map.of("NEGOTIATED_CIPHER_SUITE", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
        bsr.addResult(hr2);

        bsr.setTotalTargets(2);
        bsr.setSuccessCount(2);

        HeatMapData data = bsr.toConnectionHeatMap(N_BLOCKS);

        // Should have 2 rows, one per unique cipher
        assertEquals(2, data.getRows().size());
        assertTrue(data.getRows().get(0).getId().startsWith("NEGOTIATED_CIPHER_SUITE-->"));
        assertTrue(data.getRows().get(1).getId().startsWith("NEGOTIATED_CIPHER_SUITE-->"));
    }

    // ---- toHttpResponseHeatMap ----

    @Test
    void httpResponse_presenceChecks() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "text/html");
        headers.put("Server", "nginx");

        ScanResult bsr = resultWithHttpHeaders(headers);
        HeatMapData data = bsr.toHttpResponseHeatMap(N_BLOCKS);

        assertEquals(HeatMapData.MapType.HTTP_RESPONSE, data.getMapType());
        assertEquals(2, data.getRows().size());
        // Both present -> pass
        for (HeatMapRow row : data.getRows()) {
            assertTrue(row.getCells()[0].getPassCount() > 0);
        }
    }

    // ---- toRiskHeatMap — synthetic certificate rows ----

    @Test
    void risk_includesCertificateCategoryWithThreeRows() {
        // Create a minimal risk score mock and scan tree with cert data
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");

        // Need a risk score for the host to be included
        hr.setRiskScore(new com.mps.deepviolet.api.IRiskScore() {
            @Override public int getTotalScore() { return 100; }
            @Override public LetterGrade getLetterGrade() { return LetterGrade.A; }
            @Override public RiskLevel getRiskLevel() { return RiskLevel.LOW; }
            @Override public ICategoryScore[] getCategoryScores() { return new ICategoryScore[0]; }
            @Override public ICategoryScore getCategoryScore(ScoreCategory c) { return null; }
            @Override public ICategoryScore getCategoryScore(String key) { return null; }
            @Override public String getHostUrl() { return "https://example.com"; }
            @Override public IScoringDiagnostic[] getDiagnostics() { return new IScoringDiagnostic[0]; }
        });

        // Add cert chain data in scan tree
        ScanNode root = ScanNode.createRoot();
        ScanNode certSection = ScanNode.createSection("Server certificate chain");
        root.addChild(certSection);
        ScanNode endEntity = ScanNode.createSubsection("CN=example.com");
        certSection.addChild(endEntity);
        endEntity.addChild(ScanNode.createKeyValue("TrustState", "TRUSTED"));
        endEntity.addChild(ScanNode.createKeyValue("ValidState", "VALID"));
        endEntity.addChild(ScanNode.createKeyValue("DaysUntilExpiration", "365"));
        hr.setScanTree(root);

        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);

        HeatMapData data = bsr.toRiskHeatMap(N_BLOCKS);

        // Should have CERTIFICATE category with 3 rows
        long certRows = data.getRows().stream()
                .filter(r -> "CERTIFICATE".equals(r.getCategory()))
                .count();
        assertEquals(3, certRows, "Expected 3 CERTIFICATE rows");

        // All should pass with the given values
        for (HeatMapRow row : data.getRows()) {
            if ("CERTIFICATE".equals(row.getCategory())) {
                assertTrue(row.getCells()[0].getPassCount() > 0,
                        "Expected pass for: " + row.getDescription());
            }
        }
    }

    @Test
    void risk_certNotTrusted_fails() {
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");
        hr.setRiskScore(new com.mps.deepviolet.api.IRiskScore() {
            @Override public int getTotalScore() { return 100; }
            @Override public LetterGrade getLetterGrade() { return LetterGrade.A; }
            @Override public RiskLevel getRiskLevel() { return RiskLevel.LOW; }
            @Override public ICategoryScore[] getCategoryScores() { return new ICategoryScore[0]; }
            @Override public ICategoryScore getCategoryScore(ScoreCategory c) { return null; }
            @Override public ICategoryScore getCategoryScore(String key) { return null; }
            @Override public String getHostUrl() { return "https://example.com"; }
            @Override public IScoringDiagnostic[] getDiagnostics() { return new IScoringDiagnostic[0]; }
        });

        ScanNode root = ScanNode.createRoot();
        ScanNode certSection = ScanNode.createSection("Server certificate chain");
        root.addChild(certSection);
        ScanNode endEntity = ScanNode.createSubsection("CN=expired.example.com");
        certSection.addChild(endEntity);
        endEntity.addChild(ScanNode.createKeyValue("TrustState", "UNTRUSTED"));
        endEntity.addChild(ScanNode.createKeyValue("ValidState", "EXPIRED"));
        endEntity.addChild(ScanNode.createKeyValue("DaysUntilExpiration", "10"));
        hr.setScanTree(root);

        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);

        HeatMapData data = bsr.toRiskHeatMap(N_BLOCKS);

        // All CERTIFICATE rows should fail
        for (HeatMapRow row : data.getRows()) {
            if ("CERTIFICATE".equals(row.getCategory())) {
                assertTrue(row.getCells()[0].getFailCount() > 0,
                        "Expected fail for: " + row.getDescription());
            }
        }
    }

    // ---- toRevocationHeatMap ----

    @Test
    void revocation_has5Rows() {
        ScanNode root = ScanNode.createRoot();
        ScanNode revSection = ScanNode.createSection("Revocation status");
        root.addChild(revSection);
        ScanNode ocsp = ScanNode.createSubsection("OCSP Check");
        revSection.addChild(ocsp);
        ocsp.addChild(ScanNode.createKeyValue("Status", "GOOD"));
        ocsp.addChild(ScanNode.createKeyValue("Stapling", "PRESENT"));

        ScanNode crl = ScanNode.createSubsection("CRL Check");
        revSection.addChild(crl);
        crl.addChild(ScanNode.createKeyValue("Status", "GOOD"));

        ScanNode onecrl = ScanNode.createSubsection("OneCRL Check");
        revSection.addChild(onecrl);
        onecrl.addChild(ScanNode.createKeyValue("Status", "NOT FOUND"));

        ScanNode sct = ScanNode.createSubsection("SCT Verification");
        revSection.addChild(sct);
        sct.addChild(ScanNode.createKeyValue("Status", "3 SCTs found"));

        ScanResult bsr = resultWithScanTree(root);
        HeatMapData data = bsr.toRevocationHeatMap(N_BLOCKS);

        assertEquals(HeatMapData.MapType.REVOCATION, data.getMapType());
        assertEquals(5, data.getRows().size());

        // First row should be "OCSP Responder" (renamed from "OCSP Status")
        assertEquals("OCSP Responder", data.getRows().get(0).getDescription());

        // All should pass with the given values
        for (HeatMapRow row : data.getRows()) {
            assertTrue(row.getCells()[0].getPassCount() > 0,
                    "Expected pass for: " + row.getDescription());
        }
    }

    @Test
    void revocation_noSection_allInconclusive() {
        ScanNode root = ScanNode.createRoot();
        // No "Revocation status" section

        ScanResult bsr = resultWithScanTree(root);
        HeatMapData data = bsr.toRevocationHeatMap(N_BLOCKS);

        assertEquals(5, data.getRows().size());
        for (HeatMapRow row : data.getRows()) {
            assertTrue(row.getCells()[0].getInconclusiveCount() > 0,
                    "Expected inconclusive for: " + row.getDescription());
        }
    }

    // ---- toCipherHeatMap — uniform available logic ----

    @Test
    void cipher_weakOffered_isPass() {
        // With uniform logic, a WEAK cipher offered should be pass (available)
        ScanResult bsr = new ScanResult();
        ScanResult.HostResult hr = new ScanResult.HostResult("https://example.com");
        hr.setCiphers(new com.mps.deepviolet.api.ICipherSuite[] {
            new TestCipherSuite("TLS_RSA_WITH_RC4_128_SHA", "WEAK")
        });
        bsr.addResult(hr);
        bsr.setTotalTargets(1);
        bsr.setSuccessCount(1);

        HeatMapData data = bsr.toCipherHeatMap(N_BLOCKS);

        assertEquals(1, data.getRows().size());
        // Offered = pass (uniform available logic)
        assertTrue(data.getRows().get(0).getCells()[0].getPassCount() > 0,
                "WEAK cipher offered should be pass (available)");
    }

    // ---- Error column tracking ----

    @Test
    void errorColumns_trackedWhenHostsFail() {
        ScanResult bsr = new ScanResult();

        ScanResult.HostResult hr1 = new ScanResult.HostResult("https://good.com");
        hr1.setSecurityHeaders(Map.of("Strict-Transport-Security", "max-age=31536000"));
        bsr.addResult(hr1);

        ScanResult.HostResult hr2 = new ScanResult.HostResult("https://bad.com");
        hr2.setErrorMessage("Connection failed");
        bsr.addResult(hr2);

        bsr.setTotalTargets(2);
        bsr.setSuccessCount(1);
        bsr.setErrorCount(1);

        HeatMapData data = bsr.toSecurityHeadersHeatMap(N_BLOCKS);

        // Error host should have error columns set
        boolean anyError = false;
        for (int col = 0; col < N_BLOCKS; col++) {
            if (data.hasErrorColumn(col)) {
                anyError = true;
                break;
            }
        }
        assertTrue(anyError, "Expected at least one error column");
    }

    // ---- Helper method tests ----

    @Test
    void findSection_findsMatchingSection() {
        ScanNode root = ScanNode.createRoot();
        ScanNode s1 = ScanNode.createSection("Host information");
        ScanNode s2 = ScanNode.createSection("Connection characteristics");
        root.addChild(s1);
        root.addChild(s2);

        assertSame(s1, ScanResult.findSection(root, "Host information"));
        assertSame(s2, ScanResult.findSection(root, "Connection characteristics"));
        assertNull(ScanResult.findSection(root, "Nonexistent"));
    }

    @Test
    void findKeyValue_recursiveSearch() {
        ScanNode parent = ScanNode.createSection("Test");
        ScanNode sub = ScanNode.createSubsection("Sub");
        parent.addChild(sub);
        sub.addChild(ScanNode.createKeyValue("Nested", "value1"));
        parent.addChild(ScanNode.createKeyValue("Top", "value2"));

        assertEquals("value1", ScanResult.findKeyValue(parent, "Nested"));
        assertEquals("value2", ScanResult.findKeyValue(parent, "Top"));
        assertNull(ScanResult.findKeyValue(parent, "Missing"));
    }

    // ---- Test helper class ----

    private static class TestCipherSuite implements com.mps.deepviolet.api.ICipherSuite {
        private final String name;
        private final String strength;

        TestCipherSuite(String name, String strength) {
            this.name = name;
            this.strength = strength;
        }

        @Override public String getSuiteName() { return name; }
        @Override public String getStrengthEvaluation() { return strength; }
        @Override public String getHandshakeProtocol() { return "TLSv1.2"; }
    }
}
