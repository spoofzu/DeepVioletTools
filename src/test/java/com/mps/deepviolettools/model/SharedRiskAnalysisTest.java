package com.mps.deepviolettools.model;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolettools.model.HostDelta.HostStatus;
import com.mps.deepviolettools.model.ScanResult.HostResult;

/**
 * Unit tests for {@link SharedRiskAnalysis} — shared risk grouping logic.
 */
class SharedRiskAnalysisTest {

    // ---- Stub implementations of IRiskScore API ----

    private static class StubDeduction implements IRiskScore.IDeduction {
        private final String ruleId;
        private final String description;
        private final double score;
        private final String severity;

        StubDeduction(String ruleId, String description,
                      double score, String severity) {
            this.ruleId = ruleId;
            this.description = description;
            this.score = score;
            this.severity = severity;
        }

        @Override public String getRuleId() { return ruleId; }
        @Override public String getDescription() { return description; }
        @Override public double getScore() { return score; }
        @Override public String getSeverity() { return severity; }
        @Override public boolean isInconclusive() { return false; }
        @Override public IRiskScore.IDeduction.IScope getScope() { return null; }
    }

    private static class StubCategoryScore implements IRiskScore.ICategoryScore {
        private final IRiskScore.IDeduction[] deductions;

        StubCategoryScore(IRiskScore.IDeduction... deductions) {
            this.deductions = deductions;
        }

        @Override public IRiskScore.ScoreCategory getCategory() {
            return IRiskScore.ScoreCategory.OTHER;
        }
        @Override public String getCategoryKey() { return "other"; }
        @Override public int getScore() { return 100; }
        @Override public IRiskScore.RiskLevel getRiskLevel() {
            return IRiskScore.RiskLevel.LOW;
        }
        @Override public String getDisplayName() { return "Other"; }
        @Override public String getSummary() { return ""; }
        @Override public IRiskScore.IDeduction[] getDeductions() {
            return deductions;
        }
        @Override public IRiskScore.IScoringDiagnostic[] getDiagnostics() {
            return null;
        }
    }

    private static class StubRiskScore implements IRiskScore {
        private final ICategoryScore[] categories;

        StubRiskScore(ICategoryScore... categories) {
            this.categories = categories;
        }

        @Override public int getTotalScore() { return 80; }
        @Override public LetterGrade getLetterGrade() { return LetterGrade.B; }
        @Override public RiskLevel getRiskLevel() { return RiskLevel.LOW; }
        @Override public ICategoryScore[] getCategoryScores() { return categories; }
        @Override public ICategoryScore getCategoryScore(ScoreCategory cat) { return null; }
        @Override public ICategoryScore getCategoryScore(String key) { return null; }
        @Override public String getHostUrl() { return ""; }
        @Override public IScoringDiagnostic[] getDiagnostics() { return null; }
    }

    // ---- Helpers ----

    private static IRiskScore riskWith(String... ruleIds) {
        IRiskScore.IDeduction[] deds = new IRiskScore.IDeduction[ruleIds.length];
        for (int i = 0; i < ruleIds.length; i++) {
            deds[i] = new StubDeduction(ruleIds[i], "Desc for " + ruleIds[i],
                    0.10 * (i + 1), severityFor(i));
        }
        return new StubRiskScore(new StubCategoryScore(deds));
    }

    private static String severityFor(int index) {
        return switch (index % 4) {
            case 0 -> "LOW";
            case 1 -> "MEDIUM";
            case 2 -> "HIGH";
            case 3 -> "CRITICAL";
            default -> "INFO";
        };
    }

    private static HostDelta matchedHost(String url, IRiskScore baseRisk,
                                          IRiskScore targetRisk) {
        HostResult base = new HostResult("https://" + url);
        base.setRiskScore(baseRisk);
        HostResult target = new HostResult("https://" + url);
        target.setRiskScore(targetRisk);
        return new HostDelta(url, HostStatus.CHANGED, base, target);
    }

    private static HostDelta unchangedHost(String url, IRiskScore risk) {
        HostResult base = new HostResult("https://" + url);
        base.setRiskScore(risk);
        HostResult target = new HostResult("https://" + url);
        target.setRiskScore(risk);
        return new HostDelta(url, HostStatus.UNCHANGED, base, target);
    }

    private static HostDelta addedHost(String url, IRiskScore risk) {
        HostResult target = new HostResult("https://" + url);
        target.setRiskScore(risk);
        return new HostDelta(url, HostStatus.ADDED, null, target);
    }

    private static HostDelta removedHost(String url, IRiskScore risk) {
        HostResult base = new HostResult("https://" + url);
        base.setRiskScore(risk);
        return new HostDelta(url, HostStatus.REMOVED, base, null);
    }

    private static HostDelta errorHost(String url) {
        return new HostDelta(url, HostStatus.ERROR, null, null);
    }

    private static DeltaScanResult deltaWith(HostDelta... deltas) {
        DeltaScanResult result = new DeltaScanResult(
                new File("base.dvscan"), new File("target.dvscan"),
                null, null, deltas.length, deltas.length);
        for (HostDelta d : deltas) {
            result.addHostDelta(d);
        }
        result.finalize_();
        return result;
    }

    // ---- Tests ----

    @Test
    void analyze_nullResult_returnsEmpty() {
        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(null);
        assertTrue(result.getUniversalDeductions().isEmpty());
        assertTrue(result.getHostGroups().isEmpty());
        assertEquals(0, result.getTotalHostCount());
    }

    @Test
    void analyze_twoHostsSameDeductions_allUniversal() {
        IRiskScore risk = riskWith("R1", "R2");
        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", risk),
                unchangedHost("host2.com", risk));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(2, result.getTotalHostCount());
        assertEquals(2, result.getUniversalDeductions().size());
        assertTrue(result.getHostGroups().isEmpty());
        // Sorted by severity desc: R2 (MEDIUM, index 1) before R1 (LOW, index 0)
        assertEquals("R2", result.getUniversalDeductions().get(0).getRuleId());
        assertEquals("R1", result.getUniversalDeductions().get(1).getRuleId());
    }

    @Test
    void analyze_twoHostsPartialOverlap_universalAndGrouped() {
        // 3 hosts: all have R1, only host1+host2 have R2, only host3 has R3
        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", riskWith("R1", "R2")),
                unchangedHost("host2.com", riskWith("R1", "R2")),
                unchangedHost("host3.com", riskWith("R1", "R3")));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(3, result.getTotalHostCount());
        // R1 is universal (all 3 hosts)
        assertEquals(1, result.getUniversalDeductions().size());
        assertEquals("R1", result.getUniversalDeductions().get(0).getRuleId());
        // R2 is grouped (2 hosts), R3 is unique (1 host, not shared)
        assertEquals(1, result.getHostGroups().size());
        SharedRiskAnalysis.SharedRiskGroup group = result.getHostGroups().get(0);
        assertEquals(Set.of("host1.com", "host2.com"), group.getHostUrls());
        assertEquals(1, group.getDeductions().size());
        assertEquals("R2", group.getDeductions().get(0).getRuleId());
    }

    @Test
    void analyze_matchedHost_usesUnionOfBaseAndTarget() {
        // Base has R1, target has R2 — union should include both
        IRiskScore baseRisk = riskWith("R1");
        IRiskScore targetRisk = riskWith("R2");

        DeltaScanResult delta = deltaWith(
                matchedHost("host1.com", baseRisk, targetRisk),
                matchedHost("host2.com", baseRisk, targetRisk));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(2, result.getTotalHostCount());
        // Both R1 and R2 should be universal (both hosts have the union)
        assertEquals(2, result.getUniversalDeductions().size());
        Set<String> ruleIds = Set.of(
                result.getUniversalDeductions().get(0).getRuleId(),
                result.getUniversalDeductions().get(1).getRuleId());
        assertTrue(ruleIds.contains("R1"));
        assertTrue(ruleIds.contains("R2"));
    }

    @Test
    void analyze_hostWithNullRiskScore_excludedFromCount() {
        // host1 has risk data, host2 has null risk score
        HostResult base2 = new HostResult("https://host2.com");
        // Don't set risk score — it stays null
        HostResult target2 = new HostResult("https://host2.com");
        HostDelta hd2 = new HostDelta("host2.com", HostStatus.UNCHANGED, base2, target2);

        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", riskWith("R1")),
                hd2);

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        // Only host1 counted (host2 had no deductions)
        assertEquals(1, result.getTotalHostCount());
        // R1 is in all counted hosts (1/1), so it's universal
        assertEquals(1, result.getUniversalDeductions().size());
        assertEquals("R1", result.getUniversalDeductions().get(0).getRuleId());
        assertTrue(result.getHostGroups().isEmpty());
    }

    @Test
    void analyze_universalSortedBySeverityThenScore() {
        // Create deductions with different severities
        IRiskScore.IDeduction low = new StubDeduction("R-LOW", "Low", 0.10, "LOW");
        IRiskScore.IDeduction high = new StubDeduction("R-HIGH", "High", 0.60, "HIGH");
        IRiskScore.IDeduction med = new StubDeduction("R-MED", "Medium", 0.25, "MEDIUM");
        IRiskScore.IDeduction crit = new StubDeduction("R-CRIT", "Critical", 0.90, "CRITICAL");
        IRiskScore risk = new StubRiskScore(new StubCategoryScore(low, high, med, crit));

        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", risk),
                unchangedHost("host2.com", risk));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(4, result.getUniversalDeductions().size());
        // Sorted by severity desc: CRITICAL, HIGH, MEDIUM, LOW
        assertEquals("R-CRIT", result.getUniversalDeductions().get(0).getRuleId());
        assertEquals("R-HIGH", result.getUniversalDeductions().get(1).getRuleId());
        assertEquals("R-MED", result.getUniversalDeductions().get(2).getRuleId());
        assertEquals("R-LOW", result.getUniversalDeductions().get(3).getRuleId());
    }

    @Test
    void analyze_hostGroupsSortedByGroupSizeDesc() {
        // 4 hosts: R1 in all 4 (universal), R2 in 3 hosts, R3 in 2 hosts
        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", riskWith("R1", "R2", "R3")),
                unchangedHost("host2.com", riskWith("R1", "R2", "R3")),
                unchangedHost("host3.com", riskWith("R1", "R2")),
                unchangedHost("host4.com", riskWith("R1")));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(4, result.getTotalHostCount());
        assertEquals(1, result.getUniversalDeductions().size());
        assertEquals("R1", result.getUniversalDeductions().get(0).getRuleId());

        assertEquals(2, result.getHostGroups().size());
        // Group with 3 hosts (R2) should come before group with 2 hosts (R3)
        assertEquals(3, result.getHostGroups().get(0).getHostUrls().size());
        assertEquals(2, result.getHostGroups().get(1).getHostUrls().size());
    }

    @Test
    void analyze_errorHostsExcluded() {
        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", riskWith("R1")),
                unchangedHost("host2.com", riskWith("R1")),
                errorHost("host3.com"));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(2, result.getTotalHostCount());
        assertEquals(1, result.getUniversalDeductions().size());
    }

    @Test
    void analyze_addedHostUsesTargetOnly() {
        IRiskScore risk = riskWith("R1");
        DeltaScanResult delta = deltaWith(
                addedHost("host1.com", risk),
                addedHost("host2.com", risk));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(2, result.getTotalHostCount());
        assertEquals(1, result.getUniversalDeductions().size());
        assertEquals("R1", result.getUniversalDeductions().get(0).getRuleId());
    }

    @Test
    void analyze_removedHostUsesBaseOnly() {
        IRiskScore risk = riskWith("R1");
        DeltaScanResult delta = deltaWith(
                removedHost("host1.com", risk),
                removedHost("host2.com", risk));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertEquals(2, result.getTotalHostCount());
        assertEquals(1, result.getUniversalDeductions().size());
        assertEquals("R1", result.getUniversalDeductions().get(0).getRuleId());
    }

    @Test
    void collectionsAreUnmodifiable() {
        IRiskScore risk = riskWith("R1", "R2");
        DeltaScanResult delta = deltaWith(
                unchangedHost("host1.com", risk),
                unchangedHost("host2.com", riskWith("R1")),
                unchangedHost("host3.com", riskWith("R1")));

        SharedRiskAnalysis result = SharedRiskAnalysis.analyze(delta);

        assertThrows(UnsupportedOperationException.class,
                () -> result.getUniversalDeductions().add(null));
        assertThrows(UnsupportedOperationException.class,
                () -> result.getHostGroups().add(null));
        if (!result.getHostGroups().isEmpty()) {
            SharedRiskAnalysis.SharedRiskGroup group = result.getHostGroups().get(0);
            assertThrows(UnsupportedOperationException.class,
                    () -> group.getDeductions().add(null));
            assertThrows(UnsupportedOperationException.class,
                    () -> group.getHostUrls().add("extra"));
        }
    }
}
