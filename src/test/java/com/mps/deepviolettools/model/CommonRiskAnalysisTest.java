package com.mps.deepviolettools.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CommonRiskAnalysis} — deduction grouping logic.
 */
class CommonRiskAnalysisTest {

    // ---- Helpers ----

    private static RiskDelta.DeductionInfo deduction(String ruleId, String desc,
                                                      double score, String severity) {
        return new RiskDelta.DeductionInfo(ruleId, desc, score, severity);
    }

    private static HostDelta hostWithRisk(String url,
                                           List<RiskDelta.DeductionInfo> added,
                                           List<RiskDelta.DeductionInfo> removed) {
        HostDelta hd = new HostDelta(url, HostDelta.HostStatus.CHANGED, null, null);
        RiskDelta rd = new RiskDelta(80, 70, "B", "C", added, removed);
        hd.setRiskDelta(rd);
        return hd;
    }

    // ---- Tests ----

    @Test
    void analyze_nullInput_returnsEmpty() {
        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(null);
        assertTrue(result.getCommonDeductions().isEmpty());
        assertTrue(result.getUniqueDeductions().isEmpty());
    }

    @Test
    void analyze_emptyList_returnsEmpty() {
        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(Collections.emptyList());
        assertTrue(result.getCommonDeductions().isEmpty());
        assertTrue(result.getUniqueDeductions().isEmpty());
    }

    @Test
    void analyze_singleHost_allUnique() {
        RiskDelta.DeductionInfo d1 = deduction("R1", "Weak cipher", -5, "HIGH");
        HostDelta hd = hostWithRisk("host1.com", List.of(d1), Collections.emptyList());

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd));

        assertTrue(result.getCommonDeductions().isEmpty());
        assertEquals(1, result.getUniqueDeductions().size());
        assertTrue(result.getUniqueDeductions().containsKey("host1.com"));
        assertEquals(1, result.getUniqueDeductions().get("host1.com").size());
        assertTrue(result.getUniqueDeductions().get("host1.com").get(0).isAdded());
    }

    @Test
    void analyze_twoHostsSameAddedRule_isCommon() {
        RiskDelta.DeductionInfo d1 = deduction("R1", "Weak cipher", -5, "HIGH");
        HostDelta hd1 = hostWithRisk("host1.com", List.of(d1), Collections.emptyList());
        HostDelta hd2 = hostWithRisk("host2.com", List.of(d1), Collections.emptyList());

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd1, hd2));

        assertEquals(1, result.getCommonDeductions().size());
        assertTrue(result.getUniqueDeductions().isEmpty());

        CommonRiskAnalysis.DeductionOccurrence occ = result.getCommonDeductions().get(0);
        assertTrue(occ.isAdded());
        assertEquals("R1", occ.getDeduction().getRuleId());
        assertEquals(2, occ.getHostUrls().size());
    }

    @Test
    void analyze_twoHostsSameRemovedRule_isCommon() {
        RiskDelta.DeductionInfo d1 = deduction("R2", "Missing HSTS", -3, "MEDIUM");
        HostDelta hd1 = hostWithRisk("host1.com", Collections.emptyList(), List.of(d1));
        HostDelta hd2 = hostWithRisk("host2.com", Collections.emptyList(), List.of(d1));

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd1, hd2));

        assertEquals(1, result.getCommonDeductions().size());
        assertFalse(result.getCommonDeductions().get(0).isAdded());
    }

    @Test
    void analyze_mixedDirection_treatedAsUnique() {
        RiskDelta.DeductionInfo d1 = deduction("R1", "Weak cipher", -5, "HIGH");
        // host1 has R1 added, host2 has R1 removed
        HostDelta hd1 = hostWithRisk("host1.com", List.of(d1), Collections.emptyList());
        HostDelta hd2 = hostWithRisk("host2.com", Collections.emptyList(), List.of(d1));

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd1, hd2));

        assertTrue(result.getCommonDeductions().isEmpty());
        assertEquals(2, result.getUniqueDeductions().size());
        assertTrue(result.getUniqueDeductions().containsKey("host1.com"));
        assertTrue(result.getUniqueDeductions().containsKey("host2.com"));
    }

    @Test
    void analyze_commonSortedByCountDescThenScoreDesc() {
        RiskDelta.DeductionInfo d1 = deduction("R1", "Rule 1", -5, "HIGH");
        RiskDelta.DeductionInfo d2 = deduction("R2", "Rule 2", -10, "CRITICAL");
        // R1 in 3 hosts, R2 in 2 hosts
        HostDelta hd1 = hostWithRisk("h1", List.of(d1, d2), Collections.emptyList());
        HostDelta hd2 = hostWithRisk("h2", List.of(d1, d2), Collections.emptyList());
        HostDelta hd3 = hostWithRisk("h3", List.of(d1), Collections.emptyList());

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd1, hd2, hd3));

        assertEquals(2, result.getCommonDeductions().size());
        // R1 has 3 hosts, R2 has 2 hosts — R1 should come first
        assertEquals("R1", result.getCommonDeductions().get(0).getDeduction().getRuleId());
        assertEquals("R2", result.getCommonDeductions().get(1).getDeduction().getRuleId());
    }

    @Test
    void analyze_hostWithNoRiskDelta_skipped() {
        HostDelta hd1 = new HostDelta("host1.com",
                HostDelta.HostStatus.ADDED, null, null);
        // No risk delta set
        RiskDelta.DeductionInfo d1 = deduction("R1", "Rule", -5, "HIGH");
        HostDelta hd2 = hostWithRisk("host2.com", List.of(d1), Collections.emptyList());

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd1, hd2));

        assertTrue(result.getCommonDeductions().isEmpty());
        assertEquals(1, result.getUniqueDeductions().size());
    }

    @Test
    void analyze_multipleRulesMixedCommonAndUnique() {
        RiskDelta.DeductionInfo d1 = deduction("R1", "Common rule", -5, "HIGH");
        RiskDelta.DeductionInfo d2 = deduction("R2", "Unique rule", -3, "MEDIUM");

        HostDelta hd1 = hostWithRisk("host1.com",
                List.of(d1, d2), Collections.emptyList());
        HostDelta hd2 = hostWithRisk("host2.com",
                List.of(d1), Collections.emptyList());

        CommonRiskAnalysis result = CommonRiskAnalysis.analyze(List.of(hd1, hd2));

        assertEquals(1, result.getCommonDeductions().size());
        assertEquals("R1", result.getCommonDeductions().get(0).getDeduction().getRuleId());

        assertEquals(1, result.getUniqueDeductions().size());
        assertTrue(result.getUniqueDeductions().containsKey("host1.com"));
        assertEquals("R2", result.getUniqueDeductions().get("host1.com")
                .get(0).getDeduction().getRuleId());
    }

    @Test
    void deductionOccurrence_hostUrlsAreUnmodifiable() {
        RiskDelta.DeductionInfo d = deduction("R1", "Rule", -5, "HIGH");
        List<String> hosts = new ArrayList<>();
        hosts.add("host1.com");
        CommonRiskAnalysis.DeductionOccurrence occ =
                new CommonRiskAnalysis.DeductionOccurrence(d, true, hosts);

        assertThrows(UnsupportedOperationException.class,
                () -> occ.getHostUrls().add("host2.com"));
    }
}
