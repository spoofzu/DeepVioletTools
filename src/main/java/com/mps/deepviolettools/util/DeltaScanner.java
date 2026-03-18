package com.mps.deepviolettools.util;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint.FingerprintComponents;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.HostResult;
import com.mps.deepviolettools.model.CipherDelta;
import com.mps.deepviolettools.model.DeltaDirection;
import com.mps.deepviolettools.model.DeltaScanResult;
import com.mps.deepviolettools.model.FingerprintDelta;
import com.mps.deepviolettools.model.HostDelta;
import com.mps.deepviolettools.model.HostDelta.HostStatus;
import com.mps.deepviolettools.model.MapDelta;
import com.mps.deepviolettools.model.RiskDelta;

/**
 * Stateless comparison engine that produces a {@link DeltaScanResult}
 * from two {@link ScanResult} objects. Follows the same static-method
 * pattern as {@link TargetParser}.
 */
public class DeltaScanner {

    private DeltaScanner() {
    }

    /**
     * Compare two scan results and produce a delta report.
     *
     * @param base       the baseline (older) scan
     * @param target     the target (newer) scan
     * @param baseFile   the file the base scan was loaded from (may be null)
     * @param targetFile the file the target scan was loaded from (may be null)
     * @return the delta comparison result
     */
    public static DeltaScanResult compare(ScanResult base,
                                           ScanResult target,
                                           File baseFile, File targetFile) {
        DeltaScanResult result = new DeltaScanResult(
                baseFile, targetFile,
                base.getScanId(), target.getScanId(),
                base.getResults().size(), target.getResults().size());

        // Build lookup maps keyed by normalized URL
        Map<String, HostResult> baseMap = buildHostMap(base);
        Map<String, HostResult> targetMap = buildHostMap(target);

        // All unique keys
        Set<String> allKeys = new LinkedHashSet<>();
        allKeys.addAll(baseMap.keySet());
        allKeys.addAll(targetMap.keySet());

        for (String key : allKeys) {
            HostResult baseHr = baseMap.get(key);
            HostResult targetHr = targetMap.get(key);

            if (baseHr != null && targetHr != null) {
                // Host in both scans — compare
                HostDelta delta = new HostDelta(key, HostStatus.CHANGED,
                        baseHr, targetHr);
                compareSections(delta, baseHr, targetHr);
                if (!delta.hasChanges()) {
                    // Reclassify as UNCHANGED
                    delta = new HostDelta(key, HostStatus.UNCHANGED,
                            baseHr, targetHr);
                }
                result.addHostDelta(delta);
            } else if (baseHr == null) {
                // Host only in target — added
                result.addHostDelta(new HostDelta(key, HostStatus.ADDED,
                        null, targetHr));
            } else {
                // Host only in base — removed
                result.addHostDelta(new HostDelta(key, HostStatus.REMOVED,
                        baseHr, null));
            }
        }

        result.finalize_();
        return result;
    }

    /**
     * Build a map of normalized URL → HostResult for lookup.
     */
    static Map<String, HostResult> buildHostMap(ScanResult scan) {
        Map<String, HostResult> map = new LinkedHashMap<>();
        for (HostResult hr : scan.getResults()) {
            String key = normalizeForMatch(hr.getTargetUrl());
            map.put(key, hr);
        }
        return map;
    }

    /**
     * Normalize a URL for host matching: strip scheme, default port, trailing
     * slash, then lowercase.
     */
    static String normalizeForMatch(String url) {
        return ReportExporter.displayName(url).toLowerCase();
    }

    /**
     * Compare all sections between base and target host results and populate
     * the host delta with section-level deltas.
     */
    private static void compareSections(HostDelta delta,
                                         HostResult base, HostResult target) {
        delta.setRiskDelta(compareRisk(base.getRiskScore(), target.getRiskScore()));
        delta.setCipherDelta(compareCiphers(base.getCiphers(), target.getCiphers()));
        delta.setSecurityHeadersDelta(compareMaps("Security headers analysis",
                base.getSecurityHeaders(), target.getSecurityHeaders()));
        delta.setConnectionDelta(compareMaps("Connection characteristics",
                base.getConnProperties(), target.getConnProperties()));
        delta.setHttpHeadersDelta(compareMaps("HTTP response headers",
                base.getHttpHeaders(), target.getHttpHeaders()));
        delta.setFingerprintDelta(compareFingerprints(
                base.getTlsFingerprint(), target.getTlsFingerprint()));

        // Compute overall direction
        delta.setOverallDirection(computeOverallDirection(delta));
    }

    /**
     * Compare risk scores between two scans.
     */
    static RiskDelta compareRisk(IRiskScore base, IRiskScore target) {
        if (base == null && target == null) {
            return new RiskDelta(0, 0, "", "", null, null);
        }

        int baseScore = base != null ? base.getTotalScore() : 0;
        int targetScore = target != null ? target.getTotalScore() : 0;
        String baseGrade = base != null ? base.getLetterGrade().name() : "N/A";
        String targetGrade = target != null ? target.getLetterGrade().name() : "N/A";

        // Collect deduction rule IDs from each scan
        Map<String, RiskDelta.DeductionInfo> baseDeds = collectDeductions(base);
        Map<String, RiskDelta.DeductionInfo> targetDeds = collectDeductions(target);

        List<RiskDelta.DeductionInfo> added = new ArrayList<>();
        List<RiskDelta.DeductionInfo> removed = new ArrayList<>();

        for (Map.Entry<String, RiskDelta.DeductionInfo> e : targetDeds.entrySet()) {
            if (!baseDeds.containsKey(e.getKey())) {
                added.add(e.getValue());
            }
        }
        for (Map.Entry<String, RiskDelta.DeductionInfo> e : baseDeds.entrySet()) {
            if (!targetDeds.containsKey(e.getKey())) {
                removed.add(e.getValue());
            }
        }

        return new RiskDelta(baseScore, targetScore, baseGrade, targetGrade,
                added, removed);
    }

    private static Map<String, RiskDelta.DeductionInfo> collectDeductions(
            IRiskScore score) {
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

    /**
     * Compare cipher suites between two scans.
     */
    static CipherDelta compareCiphers(ICipherSuite[] base,
                                       ICipherSuite[] target) {
        Set<String> baseNames = new LinkedHashSet<>();
        Map<String, ICipherSuite> baseMap = new LinkedHashMap<>();
        if (base != null) {
            for (ICipherSuite cs : base) {
                baseNames.add(cs.getSuiteName());
                baseMap.put(cs.getSuiteName(), cs);
            }
        }

        Set<String> targetNames = new LinkedHashSet<>();
        Map<String, ICipherSuite> targetMap = new LinkedHashMap<>();
        if (target != null) {
            for (ICipherSuite cs : target) {
                targetNames.add(cs.getSuiteName());
                targetMap.put(cs.getSuiteName(), cs);
            }
        }

        List<CipherDelta.CipherInfo> added = new ArrayList<>();
        List<CipherDelta.CipherInfo> removed = new ArrayList<>();
        int unchanged = 0;

        for (String name : targetNames) {
            if (!baseNames.contains(name)) {
                ICipherSuite cs = targetMap.get(name);
                added.add(new CipherDelta.CipherInfo(
                        cs.getSuiteName(), cs.getStrengthEvaluation(),
                        cs.getHandshakeProtocol()));
            } else {
                unchanged++;
            }
        }
        for (String name : baseNames) {
            if (!targetNames.contains(name)) {
                ICipherSuite cs = baseMap.get(name);
                removed.add(new CipherDelta.CipherInfo(
                        cs.getSuiteName(), cs.getStrengthEvaluation(),
                        cs.getHandshakeProtocol()));
            }
        }

        return new CipherDelta(added, removed, unchanged);
    }

    /**
     * Compare two key-value maps (security headers, connection properties, etc.).
     */
    static MapDelta compareMaps(String sectionName,
                                 Map<String, String> base,
                                 Map<String, String> target) {
        if (base == null) base = Map.of();
        if (target == null) target = Map.of();

        Map<String, String> added = new LinkedHashMap<>();
        Map<String, String> removed = new LinkedHashMap<>();
        Map<String, String[]> changed = new LinkedHashMap<>();
        int unchanged = 0;

        for (Map.Entry<String, String> e : target.entrySet()) {
            String baseVal = base.get(e.getKey());
            if (baseVal == null) {
                added.put(e.getKey(), e.getValue());
            } else if (!baseVal.equals(e.getValue())) {
                changed.put(e.getKey(), new String[]{baseVal, e.getValue()});
            } else {
                unchanged++;
            }
        }
        for (Map.Entry<String, String> e : base.entrySet()) {
            if (!target.containsKey(e.getKey())) {
                removed.put(e.getKey(), e.getValue());
            }
        }

        return new MapDelta(sectionName, added, removed, changed, unchanged);
    }

    /**
     * Compare TLS fingerprints between two scans.
     */
    static FingerprintDelta compareFingerprints(String base, String target) {
        if (base == null && target == null) {
            return new FingerprintDelta(null, null, null);
        }
        if (base == null || target == null) {
            return new FingerprintDelta(base, target, null);
        }

        FingerprintComponents baseFp = TlsServerFingerprint.parse(base);
        FingerprintComponents targetFp = TlsServerFingerprint.parse(target);

        List<FingerprintDelta.ProbeDiff> probeDiffs = new ArrayList<>();
        if (baseFp != null && targetFp != null) {
            for (int i = 1; i <= 10; i++) {
                String baseCode = baseFp.getProbeCode(i);
                String targetCode = targetFp.getProbeCode(i);
                if (!baseCode.equals(targetCode)) {
                    probeDiffs.add(new FingerprintDelta.ProbeDiff(
                            i, baseCode, targetCode));
                }
            }
        }

        return new FingerprintDelta(base, target, probeDiffs);
    }

    /**
     * Compute the overall direction for a host delta based on its section deltas.
     */
    private static DeltaDirection computeOverallDirection(HostDelta delta) {
        boolean hasImproved = false;
        boolean hasDegraded = false;

        RiskDelta risk = delta.getRiskDelta();
        if (risk != null && risk.hasChanges()) {
            if (risk.getDirection() == DeltaDirection.IMPROVED) hasImproved = true;
            if (risk.getDirection() == DeltaDirection.DEGRADED) hasDegraded = true;
        }

        CipherDelta cipher = delta.getCipherDelta();
        if (cipher != null && cipher.hasChanges()) {
            // Added weak ciphers or removed strong ciphers = degraded
            boolean addedWeak = cipher.getAddedCiphers().stream()
                    .anyMatch(c -> "WEAK".equalsIgnoreCase(c.getStrength())
                            || "INSECURE".equalsIgnoreCase(c.getStrength()));
            boolean removedStrong = cipher.getRemovedCiphers().stream()
                    .anyMatch(c -> "STRONG".equalsIgnoreCase(c.getStrength()));
            boolean removedWeak = cipher.getRemovedCiphers().stream()
                    .anyMatch(c -> "WEAK".equalsIgnoreCase(c.getStrength())
                            || "INSECURE".equalsIgnoreCase(c.getStrength()));

            if (addedWeak || removedStrong) hasDegraded = true;
            if (removedWeak) hasImproved = true;
        }

        if (hasImproved && hasDegraded) return DeltaDirection.MIXED;
        if (hasImproved) return DeltaDirection.IMPROVED;
        if (hasDegraded) return DeltaDirection.DEGRADED;
        if (delta.hasChanges()) return DeltaDirection.NEUTRAL;
        return DeltaDirection.UNCHANGED;
    }
}
