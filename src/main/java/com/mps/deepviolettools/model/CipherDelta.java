package com.mps.deepviolettools.model;

import java.util.Collections;
import java.util.List;

/**
 * Cipher suite diff between two scans of the same host.
 */
public class CipherDelta {

    /**
     * Describes a cipher suite that was added or removed.
     */
    public static class CipherInfo {
        private final String name;
        private final String strength;
        private final String protocol;

        public CipherInfo(String name, String strength, String protocol) {
            this.name = name;
            this.strength = strength;
            this.protocol = protocol;
        }

        public String getName() { return name; }
        public String getStrength() { return strength; }
        public String getProtocol() { return protocol; }
    }

    private final List<CipherInfo> addedCiphers;
    private final List<CipherInfo> removedCiphers;
    private final int unchangedCount;

    public CipherDelta(List<CipherInfo> addedCiphers,
                       List<CipherInfo> removedCiphers,
                       int unchangedCount) {
        this.addedCiphers = addedCiphers != null
                ? Collections.unmodifiableList(addedCiphers)
                : Collections.emptyList();
        this.removedCiphers = removedCiphers != null
                ? Collections.unmodifiableList(removedCiphers)
                : Collections.emptyList();
        this.unchangedCount = unchangedCount;
    }

    public List<CipherInfo> getAddedCiphers() { return addedCiphers; }
    public List<CipherInfo> getRemovedCiphers() { return removedCiphers; }
    public int getUnchangedCount() { return unchangedCount; }

    public boolean hasChanges() {
        return !addedCiphers.isEmpty() || !removedCiphers.isEmpty();
    }
}
