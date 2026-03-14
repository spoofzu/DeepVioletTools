package com.mps.deepviolettools.model;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

/**
 * Top-level container for a delta scan comparison between two scans.
 */
public class DeltaScanResult {

    private final File baseFile;
    private final File targetFile;
    private final String baseScanId;
    private final String targetScanId;
    private final Date comparisonDate;
    private final int baseHostCount;
    private final int targetHostCount;
    private int changedCount;
    private int addedCount;
    private int removedCount;
    private int unchangedCount;
    private final List<HostDelta> hostDeltas;

    public DeltaScanResult(File baseFile, File targetFile,
                           String baseScanId, String targetScanId,
                           int baseHostCount, int targetHostCount) {
        this.baseFile = baseFile;
        this.targetFile = targetFile;
        this.baseScanId = baseScanId;
        this.targetScanId = targetScanId;
        this.comparisonDate = new Date();
        this.baseHostCount = baseHostCount;
        this.targetHostCount = targetHostCount;
        this.hostDeltas = new ArrayList<>();
    }

    public void addHostDelta(HostDelta delta) {
        hostDeltas.add(delta);
    }

    /**
     * Sort host deltas by status (CHANGED, ADDED, REMOVED, UNCHANGED, ERROR)
     * then by normalized URL, and recompute summary counts.
     */
    public void finalize_() {
        hostDeltas.sort(Comparator
                .comparingInt((HostDelta d) -> d.getStatus().ordinal())
                .thenComparing(HostDelta::getNormalizedUrl));
        changedCount = 0;
        addedCount = 0;
        removedCount = 0;
        unchangedCount = 0;
        for (HostDelta d : hostDeltas) {
            switch (d.getStatus()) {
                case CHANGED: changedCount++; break;
                case ADDED: addedCount++; break;
                case REMOVED: removedCount++; break;
                case UNCHANGED: unchangedCount++; break;
                case ERROR: break;
            }
        }
    }

    public File getBaseFile() { return baseFile; }
    public File getTargetFile() { return targetFile; }
    public String getBaseScanId() { return baseScanId; }
    public String getTargetScanId() { return targetScanId; }
    public Date getComparisonDate() { return comparisonDate; }
    public int getBaseHostCount() { return baseHostCount; }
    public int getTargetHostCount() { return targetHostCount; }
    public int getChangedCount() { return changedCount; }
    public int getAddedCount() { return addedCount; }
    public int getRemovedCount() { return removedCount; }
    public int getUnchangedCount() { return unchangedCount; }

    public List<HostDelta> getHostDeltas() {
        return Collections.unmodifiableList(hostDeltas);
    }

    /**
     * Returns only the host deltas with the given status.
     */
    public List<HostDelta> getHostDeltas(HostDelta.HostStatus status) {
        List<HostDelta> filtered = new ArrayList<>();
        for (HostDelta d : hostDeltas) {
            if (d.getStatus() == status) filtered.add(d);
        }
        return filtered;
    }
}
