package com.mps.deepviolettools.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Generic key-value map diff, reused for security headers, connection
 * properties, and HTTP response headers.
 */
public class MapDelta {

    private final String sectionName;
    private final Map<String, String> addedEntries;
    private final Map<String, String> removedEntries;
    /** Key → {oldValue, newValue}. */
    private final Map<String, String[]> changedEntries;
    private final int unchangedCount;

    public MapDelta(String sectionName,
                    Map<String, String> addedEntries,
                    Map<String, String> removedEntries,
                    Map<String, String[]> changedEntries,
                    int unchangedCount) {
        this.sectionName = sectionName;
        this.addedEntries = addedEntries != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(addedEntries))
                : Collections.emptyMap();
        this.removedEntries = removedEntries != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(removedEntries))
                : Collections.emptyMap();
        this.changedEntries = changedEntries != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(changedEntries))
                : Collections.emptyMap();
        this.unchangedCount = unchangedCount;
    }

    public String getSectionName() {
        return sectionName;
    }

    public Map<String, String> getAddedEntries() {
        return addedEntries;
    }

    public Map<String, String> getRemovedEntries() {
        return removedEntries;
    }

    public Map<String, String[]> getChangedEntries() {
        return changedEntries;
    }

    public int getUnchangedCount() {
        return unchangedCount;
    }

    public boolean hasChanges() {
        return !addedEntries.isEmpty() || !removedEntries.isEmpty()
                || !changedEntries.isEmpty();
    }
}
