package com.mps.deepviolettools.model;

import java.util.ArrayList;
import java.util.List;

import com.mps.deepviolettools.model.HeatMapData.HeatMapCell;
import com.mps.deepviolettools.model.HeatMapData.HeatMapRow;
import com.mps.deepviolettools.model.HeatMapData.MapType;
import com.mps.deepviolettools.model.HostDelta.HostStatus;

/**
 * Builds {@link HeatMapData} objects from a {@link DeltaScanResult} for
 * delta visualization. Uses the existing HeatMapData structure with
 * semantic mapping: pass=improved, fail=degraded, inconclusive=neutral change.
 * Cells with totalCount=0 represent unchanged (rendered gray).
 */
public class DeltaHeatMapBuilder {

    private DeltaHeatMapBuilder() {
    }

    /**
     * Build an overview heat map with one row per section (Risk, Ciphers,
     * Headers, Connection, HTTP, Fingerprint) and one column per changed host.
     */
    public static HeatMapData buildOverviewHeatMap(DeltaScanResult result,
                                                    int nBlocks) {
        List<HostDelta> changed = result.getHostDeltas(HostStatus.CHANGED);
        if (changed.isEmpty()) {
            return new HeatMapData(MapType.RISK, new ArrayList<>(), nBlocks, 1, 0);
        }

        int totalHosts = changed.size();
        String[] sectionNames = {
            "Risk Assessment", "Cipher Suites", "Security Headers",
            "Connection", "HTTP Headers", "Fingerprint"
        };

        List<HeatMapRow> rows = new ArrayList<>();
        for (String section : sectionNames) {
            HeatMapCell[] cells = new HeatMapCell[nBlocks];
            for (int b = 0; b < nBlocks; b++) {
                cells[b] = new HeatMapCell(0, 0, 0, null, new ArrayList<>());
            }

            for (int i = 0; i < totalHosts; i++) {
                HostDelta hd = changed.get(i);
                int[] range = HeatMapData.assignBlockRange(i, totalHosts, nBlocks);
                DeltaDirection dir = getSectionDirection(hd, section);

                for (int b = range[0]; b <= range[1]; b++) {
                    switch (dir) {
                        case IMPROVED:
                            cells[b].addPass();
                            break;
                        case DEGRADED:
                            cells[b].addFail();
                            break;
                        case NEUTRAL:
                        case MIXED:
                            cells[b].addInconclusive();
                            break;
                        case UNCHANGED:
                            // Leave totalCount=0 → gray
                            break;
                    }
                    cells[b].addHostName(hd.getNormalizedUrl());
                }
            }

            rows.add(new HeatMapRow("Delta Overview", section, section,
                    null, cells));
        }

        return new HeatMapData(MapType.RISK, rows, nBlocks, 1, totalHosts);
    }

    /**
     * Build a risk delta heat map with per-deduction rows showing which
     * hosts gained or lost specific risk deductions.
     */
    public static HeatMapData buildRiskDeltaHeatMap(DeltaScanResult result,
                                                     int nBlocks) {
        List<HostDelta> changed = result.getHostDeltas(HostStatus.CHANGED);
        List<HostDelta> withRisk = new ArrayList<>();
        for (HostDelta hd : changed) {
            if (hd.getRiskDelta() != null && hd.getRiskDelta().hasChanges()) {
                withRisk.add(hd);
            }
        }
        if (withRisk.isEmpty()) {
            return new HeatMapData(MapType.RISK, new ArrayList<>(), nBlocks, 1, 0);
        }

        int totalHosts = withRisk.size();
        // Score row
        HeatMapCell[] scoreCells = new HeatMapCell[nBlocks];
        for (int b = 0; b < nBlocks; b++) {
            scoreCells[b] = new HeatMapCell(0, 0, 0, null, new ArrayList<>());
        }
        for (int i = 0; i < totalHosts; i++) {
            HostDelta hd = withRisk.get(i);
            int[] range = HeatMapData.assignBlockRange(i, totalHosts, nBlocks);
            RiskDelta rd = hd.getRiskDelta();
            for (int b = range[0]; b <= range[1]; b++) {
                if (rd.getScoreDiff() > 0) scoreCells[b].addPass();
                else if (rd.getScoreDiff() < 0) scoreCells[b].addFail();
                else scoreCells[b].addInconclusive();
                scoreCells[b].addHostName(hd.getNormalizedUrl());
            }
        }

        List<HeatMapRow> rows = new ArrayList<>();
        rows.add(new HeatMapRow("Risk Score", "score", "Overall Score Change",
                null, scoreCells));

        return new HeatMapData(MapType.RISK, rows, nBlocks, 1, totalHosts);
    }

    /**
     * Build a cipher delta heat map showing cipher additions/removals per host.
     */
    public static HeatMapData buildCipherDeltaHeatMap(DeltaScanResult result,
                                                       int nBlocks) {
        List<HostDelta> changed = result.getHostDeltas(HostStatus.CHANGED);
        List<HostDelta> withCipher = new ArrayList<>();
        for (HostDelta hd : changed) {
            if (hd.getCipherDelta() != null && hd.getCipherDelta().hasChanges()) {
                withCipher.add(hd);
            }
        }
        if (withCipher.isEmpty()) {
            return new HeatMapData(MapType.CIPHER, new ArrayList<>(), nBlocks, 1, 0);
        }

        int totalHosts = withCipher.size();
        HeatMapCell[] cells = new HeatMapCell[nBlocks];
        for (int b = 0; b < nBlocks; b++) {
            cells[b] = new HeatMapCell(0, 0, 0, null, new ArrayList<>());
        }
        for (int i = 0; i < totalHosts; i++) {
            HostDelta hd = withCipher.get(i);
            int[] range = HeatMapData.assignBlockRange(i, totalHosts, nBlocks);
            CipherDelta cd = hd.getCipherDelta();
            for (int b = range[0]; b <= range[1]; b++) {
                // Removed weak = improved (pass), added weak = degraded (fail)
                boolean addedWeak = cd.getAddedCiphers().stream()
                        .anyMatch(c -> "WEAK".equalsIgnoreCase(c.getStrength())
                                || "INSECURE".equalsIgnoreCase(c.getStrength()));
                boolean removedWeak = cd.getRemovedCiphers().stream()
                        .anyMatch(c -> "WEAK".equalsIgnoreCase(c.getStrength())
                                || "INSECURE".equalsIgnoreCase(c.getStrength()));
                if (addedWeak) cells[b].addFail();
                else if (removedWeak) cells[b].addPass();
                else cells[b].addInconclusive();
                cells[b].addHostName(hd.getNormalizedUrl());
            }
        }

        List<HeatMapRow> rows = new ArrayList<>();
        rows.add(new HeatMapRow("Cipher Changes", "ciphers",
                "Cipher Suite Changes", null, cells));

        return new HeatMapData(MapType.CIPHER, rows, nBlocks, 1, totalHosts);
    }

    /**
     * Returns the delta legend text for a delta heat map.
     */
    public static String deltaLegendText(int changedHosts, int nBlocks) {
        return "  Green=improved  Red=degraded  Yellow=neutral change  "
                + "Gray=unchanged  (" + changedHosts + " changed hosts, "
                + nBlocks + " columns)";
    }

    private static DeltaDirection getSectionDirection(HostDelta hd,
                                                       String section) {
        switch (section) {
            case "Risk Assessment":
                return hd.getRiskDelta() != null && hd.getRiskDelta().hasChanges()
                        ? hd.getRiskDelta().getDirection()
                        : DeltaDirection.UNCHANGED;
            case "Cipher Suites":
                if (hd.getCipherDelta() == null || !hd.getCipherDelta().hasChanges())
                    return DeltaDirection.UNCHANGED;
                boolean addedWeak = hd.getCipherDelta().getAddedCiphers().stream()
                        .anyMatch(c -> "WEAK".equalsIgnoreCase(c.getStrength()));
                boolean removedWeak = hd.getCipherDelta().getRemovedCiphers().stream()
                        .anyMatch(c -> "WEAK".equalsIgnoreCase(c.getStrength()));
                if (addedWeak && removedWeak) return DeltaDirection.MIXED;
                if (addedWeak) return DeltaDirection.DEGRADED;
                if (removedWeak) return DeltaDirection.IMPROVED;
                return DeltaDirection.NEUTRAL;
            case "Security Headers":
                return mapDirection(hd.getSecurityHeadersDelta());
            case "Connection":
                return mapDirection(hd.getConnectionDelta());
            case "HTTP Headers":
                return mapDirection(hd.getHttpHeadersDelta());
            case "Fingerprint":
                return hd.getFingerprintDelta() != null
                        && hd.getFingerprintDelta().hasChanges()
                        ? DeltaDirection.NEUTRAL : DeltaDirection.UNCHANGED;
            default:
                return DeltaDirection.UNCHANGED;
        }
    }

    private static DeltaDirection mapDirection(MapDelta md) {
        if (md == null || !md.hasChanges()) return DeltaDirection.UNCHANGED;
        return DeltaDirection.NEUTRAL;
    }
}
