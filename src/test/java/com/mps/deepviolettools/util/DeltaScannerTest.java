package com.mps.deepviolettools.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.model.CipherDelta;
import com.mps.deepviolettools.model.DeltaDirection;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.model.FingerprintDelta;
import com.mps.deepviolettools.model.HostDelta;
import com.mps.deepviolettools.model.HostDelta.HostStatus;
import com.mps.deepviolettools.model.MapDelta;
import com.mps.deepviolettools.util.FontPreferences;

/**
 * Unit tests for {@link DeltaScanner} — host matching, section comparison,
 * and edge cases.
 */
class DeltaScannerTest {

    // ---- Stub implementations ----

    private static class StubCipher implements ICipherSuite {
        private final String name;
        private final String strength;
        private final String protocol;

        StubCipher(String name, String strength, String protocol) {
            this.name = name;
            this.strength = strength;
            this.protocol = protocol;
        }

        @Override public String getSuiteName() { return name; }
        @Override public String getStrengthEvaluation() { return strength; }
        @Override public String getHandshakeProtocol() { return protocol; }
    }

    // ---- Helper factories ----

    private static ScanResult singleHostResult(String url) {
        ScanResult sr = new ScanResult();
        HostResult hr = new HostResult(url);
        sr.addResult(hr);
        sr.setTotalTargets(1);
        sr.setSuccessCount(1);
        return sr;
    }

    private static ScanResult twoHostResult(String url1, String url2) {
        ScanResult sr = new ScanResult();
        sr.addResult(new HostResult(url1));
        sr.addResult(new HostResult(url2));
        sr.setTotalTargets(2);
        sr.setSuccessCount(2);
        return sr;
    }

    private static ScanResult emptyResult() {
        ScanResult sr = new ScanResult();
        sr.setTotalTargets(0);
        sr.setSuccessCount(0);
        return sr;
    }

    // ---- Host matching tests ----

    @Test
    void normalizeForMatch_stripsSchemePortSlashAndLowercases() {
        assertEquals("example.com",
                DeltaScanner.normalizeForMatch("https://Example.COM:443/"));
    }

    @Test
    void normalizeForMatch_preservesNonDefaultPort() {
        assertEquals("example.com:8443",
                DeltaScanner.normalizeForMatch("https://example.com:8443/"));
    }

    @Test
    void compare_identicalScans_allUnchanged() {
        ScanResult base = twoHostResult(
                "https://a.example.com/", "https://b.example.com/");
        ScanResult target = twoHostResult(
                "https://a.example.com/", "https://b.example.com/");

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);

        assertEquals(0, result.getChangedCount());
        assertEquals(0, result.getAddedCount());
        assertEquals(0, result.getRemovedCount());
        assertEquals(2, result.getUnchangedCount());
    }

    @Test
    void compare_hostAdded_countsCorrectly() {
        ScanResult base = singleHostResult("https://existing.com/");
        ScanResult target = twoHostResult(
                "https://existing.com/", "https://newhost.com/");

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);

        assertEquals(1, result.getAddedCount());
        assertEquals(0, result.getRemovedCount());
        assertEquals(1, result.getUnchangedCount());

        java.util.List<HostDelta> added = result.getHostDeltas(HostStatus.ADDED);
        assertEquals(1, added.size());
        assertEquals("newhost.com", added.get(0).getNormalizedUrl());
    }

    @Test
    void compare_hostRemoved_countsCorrectly() {
        ScanResult base = twoHostResult(
                "https://existing.com/", "https://removed.com/");
        ScanResult target = singleHostResult("https://existing.com/");

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);

        assertEquals(0, result.getAddedCount());
        assertEquals(1, result.getRemovedCount());
        assertEquals(1, result.getUnchangedCount());

        java.util.List<HostDelta> removed = result.getHostDeltas(HostStatus.REMOVED);
        assertEquals(1, removed.size());
        assertEquals("removed.com", removed.get(0).getNormalizedUrl());
    }

    @Test
    void compare_completelyDisjointHosts_allAddedAndRemoved() {
        ScanResult base = singleHostResult("https://old.com/");
        ScanResult target = singleHostResult("https://new.com/");

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);

        assertEquals(0, result.getChangedCount());
        assertEquals(1, result.getAddedCount());
        assertEquals(1, result.getRemovedCount());
        assertEquals(0, result.getUnchangedCount());
    }

    @Test
    void compare_emptyScans_noDelta() {
        DeltaScanResult result = DeltaScanner.compare(
                emptyResult(), emptyResult(), null, null);

        assertEquals(0, result.getChangedCount());
        assertEquals(0, result.getAddedCount());
        assertEquals(0, result.getRemovedCount());
        assertEquals(0, result.getUnchangedCount());
    }

    @Test
    void compare_hostMatchingIsCaseInsensitive() {
        ScanResult base = singleHostResult("https://Example.COM/");
        ScanResult target = singleHostResult("https://example.com/");

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);

        assertEquals(0, result.getAddedCount());
        assertEquals(0, result.getRemovedCount());
        // Same host, just different case
        assertEquals(1, result.getUnchangedCount());
    }

    // ---- Map diff tests ----

    @Test
    void compareMaps_detectsAddedAndRemovedEntries() {
        Map<String, String> base = new HashMap<>();
        base.put("A", "1");
        base.put("B", "2");

        Map<String, String> target = new HashMap<>();
        target.put("B", "2");
        target.put("C", "3");

        MapDelta delta = DeltaScanner.compareMaps("test", base, target);

        assertTrue(delta.hasChanges());
        assertEquals(1, delta.getAddedEntries().size());
        assertTrue(delta.getAddedEntries().containsKey("C"));
        assertEquals(1, delta.getRemovedEntries().size());
        assertTrue(delta.getRemovedEntries().containsKey("A"));
        assertEquals(0, delta.getChangedEntries().size());
        assertEquals(1, delta.getUnchangedCount());
    }

    @Test
    void compareMaps_detectsChangedValues() {
        Map<String, String> base = Map.of("K", "old");
        Map<String, String> target = Map.of("K", "new");

        MapDelta delta = DeltaScanner.compareMaps("test", base, target);

        assertTrue(delta.hasChanges());
        assertEquals(1, delta.getChangedEntries().size());
        String[] vals = delta.getChangedEntries().get("K");
        assertEquals("old", vals[0]);
        assertEquals("new", vals[1]);
    }

    @Test
    void compareMaps_identicalMaps_noChanges() {
        Map<String, String> m = Map.of("A", "1", "B", "2");
        MapDelta delta = DeltaScanner.compareMaps("test", m, m);

        assertFalse(delta.hasChanges());
        assertEquals(2, delta.getUnchangedCount());
    }

    @Test
    void compareMaps_nullMaps_noChanges() {
        MapDelta delta = DeltaScanner.compareMaps("test", null, null);
        assertFalse(delta.hasChanges());
    }

    // ---- Cipher diff tests ----

    @Test
    void compareCiphers_detectsAddedAndRemoved() {
        ICipherSuite[] base = {
            new StubCipher("TLS_AES_128_GCM_SHA256", "STRONG", "TLSv1.3"),
            new StubCipher("TLS_RSA_WITH_AES_128_CBC_SHA", "WEAK", "TLSv1.2")
        };
        ICipherSuite[] target = {
            new StubCipher("TLS_AES_128_GCM_SHA256", "STRONG", "TLSv1.3"),
            new StubCipher("TLS_AES_256_GCM_SHA384", "STRONG", "TLSv1.3")
        };

        CipherDelta delta = DeltaScanner.compareCiphers(base, target);

        assertTrue(delta.hasChanges());
        assertEquals(1, delta.getAddedCiphers().size());
        assertEquals("TLS_AES_256_GCM_SHA384", delta.getAddedCiphers().get(0).getName());
        assertEquals(1, delta.getRemovedCiphers().size());
        assertEquals("TLS_RSA_WITH_AES_128_CBC_SHA", delta.getRemovedCiphers().get(0).getName());
        assertEquals(1, delta.getUnchangedCount());
    }

    @Test
    void compareCiphers_identicalSuites_noChanges() {
        ICipherSuite[] suites = {
            new StubCipher("TLS_AES_128_GCM_SHA256", "STRONG", "TLSv1.3")
        };
        CipherDelta delta = DeltaScanner.compareCiphers(suites, suites);
        assertFalse(delta.hasChanges());
    }

    @Test
    void compareCiphers_nullArrays_noChanges() {
        CipherDelta delta = DeltaScanner.compareCiphers(null, null);
        assertFalse(delta.hasChanges());
    }

    // ---- Fingerprint diff tests ----

    @Test
    void compareFingerprints_identical_noChanges() {
        // 30-char probe fingerprint: 10 x 3-char probe codes
        String fp = "abcabcabcabcabcabcabcabcabcabc";
        FingerprintDelta delta = DeltaScanner.compareFingerprints(fp, fp);
        assertFalse(delta.hasChanges());
    }

    @Test
    void compareFingerprints_differentProbe_hasChanges() {
        String fp1 = "abcabcabcabcabcabcabcabcabcabc";
        String fp2 = "xyzabcabcabcabcabcabcabcabcabc";
        FingerprintDelta delta = DeltaScanner.compareFingerprints(fp1, fp2);
        assertTrue(delta.hasChanges());
        assertEquals(1, delta.getProbeDiffs().size());
        assertEquals(1, delta.getProbeDiffs().get(0).getProbeNumber());
    }

    @Test
    void compareFingerprints_nullBoth_noChanges() {
        FingerprintDelta delta = DeltaScanner.compareFingerprints(null, null);
        assertFalse(delta.hasChanges());
    }

    // ---- Section change detection ----

    @Test
    void compare_securityHeadersChanged_marksHostAsChanged() {
        ScanResult base = new ScanResult();
        HostResult baseHr = new HostResult("https://example.com/");
        baseHr.setSecurityHeaders(Map.of("HSTS", "max-age=31536000"));
        base.addResult(baseHr);
        base.setTotalTargets(1);
        base.setSuccessCount(1);

        ScanResult target = new ScanResult();
        HostResult targetHr = new HostResult("https://example.com/");
        targetHr.setSecurityHeaders(Map.of("HSTS", "max-age=63072000"));
        target.addResult(targetHr);
        target.setTotalTargets(1);
        target.setSuccessCount(1);

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);

        assertEquals(1, result.getChangedCount());
        assertEquals(0, result.getUnchangedCount());
        HostDelta hd = result.getHostDeltas(HostStatus.CHANGED).get(0);
        assertTrue(hd.getSecurityHeadersDelta().hasChanges());
    }

    // ---- DeltaScanResult model tests ----

    @Test
    void deltaScanResult_sortsHostsByStatusThenName() {
        DeltaScanResult result = new DeltaScanResult(null, null, null, null, 3, 3);
        result.addHostDelta(new HostDelta("z.com", HostStatus.UNCHANGED, null, null));
        result.addHostDelta(new HostDelta("b.com", HostStatus.ADDED, null, null));
        result.addHostDelta(new HostDelta("a.com", HostStatus.CHANGED, null, null));
        result.finalize_();

        java.util.List<HostDelta> deltas = result.getHostDeltas();
        assertEquals(HostStatus.CHANGED, deltas.get(0).getStatus());
        assertEquals(HostStatus.ADDED, deltas.get(1).getStatus());
        assertEquals(HostStatus.UNCHANGED, deltas.get(2).getStatus());
    }

    // ---- Text rendering test ----

    @Test
    void deltaToPlainText_containsExpectedSections() {
        ScanResult base = singleHostResult("https://example.com/");
        ScanResult target = twoHostResult(
                "https://example.com/", "https://new.example.com/");

        DeltaScanResult result = DeltaScanner.compare(base, target, null, null);
        String text = ReportExporter.deltaToPlainText(result);

        // Shared risks section is always present
        assertTrue(text.contains("[Shared Risks]"));
        // Workbench-only sections require workbench mode;
        // test environment defaults to normal mode
        FontPreferences prefs = FontPreferences.load();
        if (prefs.isWorkbenchMode()) {
            assertTrue(text.contains("[Delta Summary]"));
            assertTrue(text.contains("Hosts Added:"));
            assertTrue(text.contains("new.example.com"));
        }
    }
}
