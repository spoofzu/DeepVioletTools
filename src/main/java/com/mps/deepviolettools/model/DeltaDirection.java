package com.mps.deepviolettools.model;

/**
 * Indicates the overall direction of change for a host or section
 * in a delta scan comparison.
 */
public enum DeltaDirection {
    /** Security posture improved (e.g. score went up, weak ciphers removed). */
    IMPROVED,
    /** Security posture degraded (e.g. score went down, weak ciphers added). */
    DEGRADED,
    /** Changes occurred but neither clearly better nor worse. */
    NEUTRAL,
    /** Some aspects improved while others degraded. */
    MIXED,
    /** No changes detected. */
    UNCHANGED
}
