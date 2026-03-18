package com.mps.deepviolettools.model;

import java.util.Collections;
import java.util.List;

/**
 * TLS fingerprint comparison between two scans of the same host.
 */
public class FingerprintDelta {

    /**
     * Describes a per-probe difference in the fingerprint.
     */
    public static class ProbeDiff {
        private final int probeNumber;
        private final String baseCode;
        private final String targetCode;

        public ProbeDiff(int probeNumber, String baseCode, String targetCode) {
            this.probeNumber = probeNumber;
            this.baseCode = baseCode;
            this.targetCode = targetCode;
        }

        public int getProbeNumber() { return probeNumber; }
        public String getBaseCode() { return baseCode; }
        public String getTargetCode() { return targetCode; }
    }

    private final String baseFingerprint;
    private final String targetFingerprint;
    private final boolean changed;
    private final List<ProbeDiff> probeDiffs;

    public FingerprintDelta(String baseFingerprint, String targetFingerprint,
                            List<ProbeDiff> probeDiffs) {
        this.baseFingerprint = baseFingerprint;
        this.targetFingerprint = targetFingerprint;
        this.probeDiffs = probeDiffs != null
                ? Collections.unmodifiableList(probeDiffs)
                : Collections.emptyList();
        this.changed = baseFingerprint != null && targetFingerprint != null
                && !baseFingerprint.equals(targetFingerprint);
    }

    public String getBaseFingerprint() { return baseFingerprint; }
    public String getTargetFingerprint() { return targetFingerprint; }
    public boolean isChanged() { return changed; }
    public List<ProbeDiff> getProbeDiffs() { return probeDiffs; }

    public boolean hasChanges() { return changed; }
}
