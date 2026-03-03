package com.mps.deepviolettools.model;

import com.mps.deepviolettools.model.ScanResult.HostResult;

/**
 * Per-host comparison result in a delta scan.
 */
public class HostDelta {

    public enum HostStatus {
        CHANGED, ADDED, REMOVED, UNCHANGED, ERROR
    }

    private final String normalizedUrl;
    private final HostStatus status;
    private final HostResult baseResult;
    private final HostResult targetResult;
    private RiskDelta riskDelta;
    private CipherDelta cipherDelta;
    private MapDelta securityHeadersDelta;
    private MapDelta connectionDelta;
    private MapDelta httpHeadersDelta;
    private FingerprintDelta fingerprintDelta;
    private DeltaDirection overallDirection;

    public HostDelta(String normalizedUrl, HostStatus status,
                     HostResult baseResult, HostResult targetResult) {
        this.normalizedUrl = normalizedUrl;
        this.status = status;
        this.baseResult = baseResult;
        this.targetResult = targetResult;
        this.overallDirection = DeltaDirection.UNCHANGED;
    }

    public String getNormalizedUrl() { return normalizedUrl; }
    public HostStatus getStatus() { return status; }
    public HostResult getBaseResult() { return baseResult; }
    public HostResult getTargetResult() { return targetResult; }

    public RiskDelta getRiskDelta() { return riskDelta; }
    public void setRiskDelta(RiskDelta riskDelta) { this.riskDelta = riskDelta; }

    public CipherDelta getCipherDelta() { return cipherDelta; }
    public void setCipherDelta(CipherDelta cipherDelta) { this.cipherDelta = cipherDelta; }

    public MapDelta getSecurityHeadersDelta() { return securityHeadersDelta; }
    public void setSecurityHeadersDelta(MapDelta delta) { this.securityHeadersDelta = delta; }

    public MapDelta getConnectionDelta() { return connectionDelta; }
    public void setConnectionDelta(MapDelta delta) { this.connectionDelta = delta; }

    public MapDelta getHttpHeadersDelta() { return httpHeadersDelta; }
    public void setHttpHeadersDelta(MapDelta delta) { this.httpHeadersDelta = delta; }

    public FingerprintDelta getFingerprintDelta() { return fingerprintDelta; }
    public void setFingerprintDelta(FingerprintDelta delta) { this.fingerprintDelta = delta; }

    public DeltaDirection getOverallDirection() { return overallDirection; }
    public void setOverallDirection(DeltaDirection dir) { this.overallDirection = dir; }

    /**
     * Returns true if any section has changes.
     */
    public boolean hasChanges() {
        return (riskDelta != null && riskDelta.hasChanges())
                || (cipherDelta != null && cipherDelta.hasChanges())
                || (securityHeadersDelta != null && securityHeadersDelta.hasChanges())
                || (connectionDelta != null && connectionDelta.hasChanges())
                || (httpHeadersDelta != null && httpHeadersDelta.hasChanges())
                || (fingerprintDelta != null && fingerprintDelta.hasChanges());
    }
}
