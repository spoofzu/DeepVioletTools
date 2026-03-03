package com.mps.deepviolettools.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolettools.model.HostDelta.HostStatus;
import com.mps.deepviolettools.model.ScanResult.HostResult;

/**
 * Analyzes deduction <b>presence</b> across all hosts in both scans of a
 * {@link DeltaScanResult} to find shared risks — deductions that appear
 * in two or more hosts regardless of whether the host changed between
 * scans.
 *
 * <p>Replaces {@link CommonRiskAnalysis} for delta detail rendering.
 * Where {@code CommonRiskAnalysis} looks at delta <em>changes</em>
 * (added/removed deductions), this class looks at the <em>union</em> of
 * deductions present in each host across both scans and partitions them
 * into universal (all hosts) and grouped (2+ hosts but not all).</p>
 */
public class SharedRiskAnalysis {

    /**
     * A group of hosts that share the same set of deductions.
     */
    public static class SharedRiskGroup {
        private final Set<String> hostUrls;
        private final List<RiskDelta.DeductionInfo> deductions;

        public SharedRiskGroup(Set<String> hostUrls,
                               List<RiskDelta.DeductionInfo> deductions) {
            this.hostUrls = Collections.unmodifiableSet(new LinkedHashSet<>(hostUrls));
            this.deductions = Collections.unmodifiableList(new ArrayList<>(deductions));
        }

        public Set<String> getHostUrls() { return hostUrls; }
        public List<RiskDelta.DeductionInfo> getDeductions() { return deductions; }
    }

    private final List<RiskDelta.DeductionInfo> universalDeductions;
    private final List<SharedRiskGroup> hostGroups;
    private final int totalHostCount;

    private SharedRiskAnalysis(List<RiskDelta.DeductionInfo> universalDeductions,
                               List<SharedRiskGroup> hostGroups,
                               int totalHostCount) {
        this.universalDeductions = Collections.unmodifiableList(universalDeductions);
        this.hostGroups = Collections.unmodifiableList(hostGroups);
        this.totalHostCount = totalHostCount;
    }

    public List<RiskDelta.DeductionInfo> getUniversalDeductions() {
        return universalDeductions;
    }

    public List<SharedRiskGroup> getHostGroups() {
        return hostGroups;
    }

    public int getTotalHostCount() {
        return totalHostCount;
    }

    /**
     * Analyze a delta scan result to find shared risks across hosts.
     *
     * <p>Algorithm:
     * <ol>
     *   <li>For each {@link HostDelta}, collect the union of deductions from
     *       base and/or target {@link HostResult} depending on status:
     *       CHANGED/UNCHANGED use both, ADDED uses target only, REMOVED uses
     *       base only, ERROR is skipped.</li>
     *   <li>Build reverse index: ruleId → set of host URLs that have it.</li>
     *   <li>Partition into universal (all hosts) and host groups (2+ but not all).</li>
     *   <li>Sort universal by severity desc then score. Sort groups by size desc.</li>
     * </ol>
     *
     * @param result the delta scan result to analyze
     * @return a new {@code SharedRiskAnalysis}
     */
    public static SharedRiskAnalysis analyze(DeltaScanResult result) {
        if (result == null) {
            return new SharedRiskAnalysis(Collections.emptyList(),
                    Collections.emptyList(), 0);
        }

        // ruleId -> DeductionInfo (first seen wins)
        Map<String, RiskDelta.DeductionInfo> deductionsByRule = new LinkedHashMap<>();
        // ruleId -> set of host URLs that have it
        Map<String, Set<String>> ruleToHosts = new LinkedHashMap<>();
        int totalHosts = 0;

        for (HostDelta hd : result.getHostDeltas()) {
            HostStatus status = hd.getStatus();
            if (status == HostStatus.ERROR) continue;

            HostResult baseResult = hd.getBaseResult();
            HostResult targetResult = hd.getTargetResult();

            // Collect deductions based on status
            Map<String, RiskDelta.DeductionInfo> hostDeductions;
            switch (status) {
                case CHANGED:
                case UNCHANGED:
                    // Union of base and target deductions
                    hostDeductions = collectDeductions(
                            baseResult != null ? baseResult.getRiskScore() : null);
                    Map<String, RiskDelta.DeductionInfo> targetDeds = collectDeductions(
                            targetResult != null ? targetResult.getRiskScore() : null);
                    hostDeductions.putAll(targetDeds);
                    break;
                case ADDED:
                    hostDeductions = collectDeductions(
                            targetResult != null ? targetResult.getRiskScore() : null);
                    break;
                case REMOVED:
                    hostDeductions = collectDeductions(
                            baseResult != null ? baseResult.getRiskScore() : null);
                    break;
                default:
                    continue;
            }

            // Skip hosts with no risk data
            if (hostDeductions.isEmpty()) continue;

            totalHosts++;
            String hostUrl = hd.getNormalizedUrl();

            for (Map.Entry<String, RiskDelta.DeductionInfo> e : hostDeductions.entrySet()) {
                deductionsByRule.putIfAbsent(e.getKey(), e.getValue());
                ruleToHosts.computeIfAbsent(e.getKey(),
                        k -> new LinkedHashSet<>()).add(hostUrl);
            }
        }

        if (totalHosts == 0) {
            return new SharedRiskAnalysis(Collections.emptyList(),
                    Collections.emptyList(), 0);
        }

        // Partition into universal vs grouped
        List<RiskDelta.DeductionInfo> universal = new ArrayList<>();
        // hostUrlSet (as sorted key) -> list of deductions
        Map<Set<String>, List<RiskDelta.DeductionInfo>> groupMap = new LinkedHashMap<>();

        for (Map.Entry<String, Set<String>> entry : ruleToHosts.entrySet()) {
            String ruleId = entry.getKey();
            Set<String> hosts = entry.getValue();
            RiskDelta.DeductionInfo di = deductionsByRule.get(ruleId);

            if (hosts.size() >= totalHosts) {
                universal.add(di);
            } else if (hosts.size() >= 2) {
                // Use a TreeSet as key for consistent grouping
                Set<String> groupKey = new TreeSet<>(hosts);
                groupMap.computeIfAbsent(groupKey, k -> new ArrayList<>()).add(di);
            }
            // hosts.size() == 1: not shared, skip
        }

        // Sort universal by severity desc then score desc
        universal.sort(SEVERITY_THEN_SCORE);

        // Build host groups sorted by group size desc
        List<SharedRiskGroup> groups = new ArrayList<>();
        for (Map.Entry<Set<String>, List<RiskDelta.DeductionInfo>> e : groupMap.entrySet()) {
            List<RiskDelta.DeductionInfo> deds = new ArrayList<>(e.getValue());
            deds.sort(SEVERITY_THEN_SCORE);
            groups.add(new SharedRiskGroup(e.getKey(), deds));
        }
        groups.sort(Comparator.comparingInt(
                (SharedRiskGroup g) -> -g.getHostUrls().size()));

        return new SharedRiskAnalysis(universal, groups, totalHosts);
    }

    /**
     * Collect all deductions from a risk score into a ruleId → DeductionInfo map.
     * Replicates the pattern from {@code DeltaScanner.collectDeductions()}.
     */
    static Map<String, RiskDelta.DeductionInfo> collectDeductions(IRiskScore score) {
        Map<String, RiskDelta.DeductionInfo> map = new LinkedHashMap<>();
        if (score == null) return map;

        IRiskScore.ICategoryScore[] cats = score.getCategoryScores();
        if (cats == null) return map;

        for (IRiskScore.ICategoryScore cat : cats) {
            IRiskScore.IDeduction[] deds = cat.getDeductions();
            if (deds == null) continue;
            for (IRiskScore.IDeduction d : deds) {
                map.put(d.getRuleId(), new RiskDelta.DeductionInfo(
                        d.getRuleId(), d.getDescription(),
                        d.getScore(), d.getSeverity()));
            }
        }
        return map;
    }

    private static final Comparator<RiskDelta.DeductionInfo> SEVERITY_THEN_SCORE =
            Comparator.comparingInt((RiskDelta.DeductionInfo d) -> severityOrdinal(d.getSeverity()))
                    .reversed()
                    .thenComparing(Comparator.comparingDouble(
                            (RiskDelta.DeductionInfo d) -> d.getScore()).reversed());

    private static int severityOrdinal(String severity) {
        if (severity == null) return 0;
        return switch (severity) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            case "INFO" -> 0;
            default -> 0;
        };
    }
}
