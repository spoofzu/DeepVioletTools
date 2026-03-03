package com.mps.deepviolettools.model;

import java.util.Collections;
import java.util.List;

/**
 * Risk score comparison between two scans of the same host.
 */
public class RiskDelta {

    /**
     * Describes a single risk deduction that was added or removed.
     */
    public static class DeductionInfo {
        private final String ruleId;
        private final String description;
        private final double score;
        private final String severity;

        public DeductionInfo(String ruleId, String description,
                             double score, String severity) {
            this.ruleId = ruleId;
            this.description = description;
            this.score = score;
            this.severity = severity;
        }

        public String getRuleId() { return ruleId; }
        public String getDescription() { return description; }
        public double getScore() { return score; }
        public String getSeverity() { return severity; }
    }

    private final int baseScore;
    private final int targetScore;
    private final int scoreDiff;
    private final String baseGrade;
    private final String targetGrade;
    private final List<DeductionInfo> addedDeductions;
    private final List<DeductionInfo> removedDeductions;
    private final DeltaDirection direction;

    public RiskDelta(int baseScore, int targetScore,
                     String baseGrade, String targetGrade,
                     List<DeductionInfo> addedDeductions,
                     List<DeductionInfo> removedDeductions) {
        this.baseScore = baseScore;
        this.targetScore = targetScore;
        this.scoreDiff = targetScore - baseScore;
        this.baseGrade = baseGrade;
        this.targetGrade = targetGrade;
        this.addedDeductions = addedDeductions != null
                ? Collections.unmodifiableList(addedDeductions)
                : Collections.emptyList();
        this.removedDeductions = removedDeductions != null
                ? Collections.unmodifiableList(removedDeductions)
                : Collections.emptyList();

        if (scoreDiff > 0) {
            this.direction = DeltaDirection.IMPROVED;
        } else if (scoreDiff < 0) {
            this.direction = DeltaDirection.DEGRADED;
        } else if (!this.addedDeductions.isEmpty() || !this.removedDeductions.isEmpty()) {
            this.direction = DeltaDirection.NEUTRAL;
        } else {
            this.direction = DeltaDirection.UNCHANGED;
        }
    }

    public int getBaseScore() { return baseScore; }
    public int getTargetScore() { return targetScore; }
    public int getScoreDiff() { return scoreDiff; }
    public String getBaseGrade() { return baseGrade; }
    public String getTargetGrade() { return targetGrade; }
    public List<DeductionInfo> getAddedDeductions() { return addedDeductions; }
    public List<DeductionInfo> getRemovedDeductions() { return removedDeductions; }
    public DeltaDirection getDirection() { return direction; }

    public boolean hasChanges() {
        return scoreDiff != 0 || !addedDeductions.isEmpty()
                || !removedDeductions.isEmpty();
    }
}
