package com.mps.deepviolettools.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Analyzes risk deductions across multiple {@link HostDelta} objects to
 * partition them into common (shared by 2+ hosts) and unique (per-host)
 * groups. Used by {@code DeltaResultsPanel} to render structured delta
 * reports.
 */
public class CommonRiskAnalysis {

    /**
     * A single deduction occurrence with its direction and affected hosts.
     */
    public static class DeductionOccurrence {
        private final RiskDelta.DeductionInfo deduction;
        private final boolean added;
        private final List<String> hostUrls;

        public DeductionOccurrence(RiskDelta.DeductionInfo deduction,
                                   boolean added, List<String> hostUrls) {
            this.deduction = deduction;
            this.added = added;
            this.hostUrls = Collections.unmodifiableList(new ArrayList<>(hostUrls));
        }

        public RiskDelta.DeductionInfo getDeduction() { return deduction; }
        public boolean isAdded() { return added; }
        public List<String> getHostUrls() { return hostUrls; }
    }

    private final List<DeductionOccurrence> commonDeductions;
    private final Map<String, List<DeductionOccurrence>> uniqueDeductions;

    private CommonRiskAnalysis(List<DeductionOccurrence> commonDeductions,
                               Map<String, List<DeductionOccurrence>> uniqueDeductions) {
        this.commonDeductions = Collections.unmodifiableList(commonDeductions);
        this.uniqueDeductions = Collections.unmodifiableMap(uniqueDeductions);
    }

    public List<DeductionOccurrence> getCommonDeductions() {
        return commonDeductions;
    }

    public Map<String, List<DeductionOccurrence>> getUniqueDeductions() {
        return uniqueDeductions;
    }

    /**
     * Analyze host deltas and partition risk deductions into common vs unique.
     *
     * <p>A deduction is <b>common</b> if its ruleId appears in 2+ hosts with the
     * same direction (all added or all removed). A deduction is <b>unique</b> if
     * it appears in only 1 host, or has mixed direction across hosts.</p>
     *
     * @param hostDeltas the list of host deltas to analyze
     * @return a new {@code CommonRiskAnalysis} with partitioned deductions
     */
    public static CommonRiskAnalysis analyze(List<HostDelta> hostDeltas) {
        if (hostDeltas == null || hostDeltas.isEmpty()) {
            return new CommonRiskAnalysis(Collections.emptyList(),
                    Collections.emptyMap());
        }

        // Track: ruleId -> (deduction, isAdded, list of host URLs)
        // We need to handle the case where the same ruleId appears as both
        // added and removed across different hosts (mixed direction).
        Map<String, RiskDelta.DeductionInfo> deductionsByRule = new LinkedHashMap<>();
        Map<String, List<String>> addedHosts = new LinkedHashMap<>();
        Map<String, List<String>> removedHosts = new LinkedHashMap<>();

        for (HostDelta hd : hostDeltas) {
            RiskDelta rd = hd.getRiskDelta();
            if (rd == null) continue;
            String hostUrl = hd.getNormalizedUrl();

            for (RiskDelta.DeductionInfo di : rd.getAddedDeductions()) {
                String ruleId = di.getRuleId();
                deductionsByRule.putIfAbsent(ruleId, di);
                addedHosts.computeIfAbsent(ruleId, k -> new ArrayList<>()).add(hostUrl);
            }

            for (RiskDelta.DeductionInfo di : rd.getRemovedDeductions()) {
                String ruleId = di.getRuleId();
                deductionsByRule.putIfAbsent(ruleId, di);
                removedHosts.computeIfAbsent(ruleId, k -> new ArrayList<>()).add(hostUrl);
            }
        }

        List<DeductionOccurrence> common = new ArrayList<>();
        Map<String, List<DeductionOccurrence>> unique = new LinkedHashMap<>();

        for (Map.Entry<String, RiskDelta.DeductionInfo> entry : deductionsByRule.entrySet()) {
            String ruleId = entry.getKey();
            RiskDelta.DeductionInfo di = entry.getValue();
            List<String> added = addedHosts.getOrDefault(ruleId, Collections.emptyList());
            List<String> removed = removedHosts.getOrDefault(ruleId, Collections.emptyList());

            boolean isMixed = !added.isEmpty() && !removed.isEmpty();

            if (isMixed) {
                // Mixed direction: treat each direction group as unique per host
                for (String host : added) {
                    unique.computeIfAbsent(host, k -> new ArrayList<>())
                            .add(new DeductionOccurrence(di, true, List.of(host)));
                }
                for (String host : removed) {
                    unique.computeIfAbsent(host, k -> new ArrayList<>())
                            .add(new DeductionOccurrence(di, false, List.of(host)));
                }
            } else if (!added.isEmpty()) {
                if (added.size() >= 2) {
                    common.add(new DeductionOccurrence(di, true, added));
                } else {
                    String host = added.get(0);
                    unique.computeIfAbsent(host, k -> new ArrayList<>())
                            .add(new DeductionOccurrence(di, true, List.of(host)));
                }
            } else if (!removed.isEmpty()) {
                if (removed.size() >= 2) {
                    common.add(new DeductionOccurrence(di, false, removed));
                } else {
                    String host = removed.get(0);
                    unique.computeIfAbsent(host, k -> new ArrayList<>())
                            .add(new DeductionOccurrence(di, false, List.of(host)));
                }
            }
        }

        // Sort common: by occurrence count desc, then score desc (more negative = worse)
        common.sort(Comparator
                .comparingInt((DeductionOccurrence o) -> -o.getHostUrls().size())
                .thenComparingDouble(o -> o.getDeduction().getScore()));

        return new CommonRiskAnalysis(common, unique);
    }
}
