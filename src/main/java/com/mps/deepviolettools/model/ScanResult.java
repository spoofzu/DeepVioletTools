package com.mps.deepviolettools.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint.FingerprintComponents;
import com.mps.deepviolettools.model.HeatMapData.HeatMapCell;
import com.mps.deepviolettools.model.HeatMapData.HeatMapRow;
import com.mps.deepviolettools.model.HeatMapData.MapType;

/**
 * Holds all per-host scan results from a scan and builds
 * {@link HeatMapData} objects for visualization across seven dimensions:
 * risk assessment (including certificate risks), cipher suites, security
 * headers, connection properties, HTTP response headers, revocation status,
 * and TLS fingerprint.
 *
 * @author Milton Smith
 */
public class ScanResult {

    /**
     * Encapsulates the scan result data for a single target host.
     */
    public static class HostResult {
        private final String targetUrl;
        private IRiskScore riskScore;
        private ICipherSuite[] ciphers;
        private Map<String, String> securityHeaders;
        private Map<String, String> connProperties;
        private Map<String, String> httpHeaders;
        private String tlsFingerprint;
        private ScanNode scanTree;
        private String errorMessage;
        private Map<String, Object> ruleContextMap;

        public HostResult(String targetUrl) {
            this.targetUrl = targetUrl;
        }

        public String getTargetUrl() {
            return targetUrl;
        }

        public IRiskScore getRiskScore() {
            return riskScore;
        }

        public void setRiskScore(IRiskScore riskScore) {
            this.riskScore = riskScore;
        }

        public ICipherSuite[] getCiphers() {
            return ciphers;
        }

        public void setCiphers(ICipherSuite[] ciphers) {
            this.ciphers = ciphers;
        }

        public Map<String, String> getSecurityHeaders() {
            return securityHeaders;
        }

        public void setSecurityHeaders(Map<String, String> securityHeaders) {
            this.securityHeaders = securityHeaders;
        }

        public Map<String, String> getConnProperties() {
            return connProperties;
        }

        public void setConnProperties(Map<String, String> connProperties) {
            this.connProperties = connProperties;
        }

        public Map<String, String> getHttpHeaders() {
            return httpHeaders;
        }

        public void setHttpHeaders(Map<String, String> httpHeaders) {
            this.httpHeaders = httpHeaders;
        }

        public String getTlsFingerprint() {
            return tlsFingerprint;
        }

        public void setTlsFingerprint(String tlsFingerprint) {
            this.tlsFingerprint = tlsFingerprint;
        }

        public ScanNode getScanTree() {
            return scanTree;
        }

        public void setScanTree(ScanNode scanTree) {
            this.scanTree = scanTree;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }

        public Map<String, Object> getRuleContextMap() {
            return ruleContextMap;
        }

        public void setRuleContextMap(Map<String, Object> ruleContextMap) {
            this.ruleContextMap = ruleContextMap;
        }

        /**
         * Returns true if the scan completed without error.
         */
        public boolean isSuccess() {
            return errorMessage == null;
        }
    }

    /**
     * Tracks the origin of a file in the provenance chain:
     * Target File &rarr; Scan File &rarr; Report.
     */
    public static class SourceProvenance {
        private final String fileName;
        private final String filePath;
        private final String sha256;

        public SourceProvenance(String fileName, String filePath, String sha256) {
            this.fileName = fileName;
            this.filePath = filePath;
            this.sha256 = sha256;
        }

        public String getFileName() { return fileName; }
        public String getFilePath() { return filePath; }
        public String getSha256() { return sha256; }
    }

    private final List<HostResult> results = new ArrayList<>();
    private int totalTargets;
    private int successCount;
    private int errorCount;
    private SourceProvenance targetSource;
    private transient SourceProvenance scanSource;

    public synchronized void addResult(HostResult result) {
        results.add(result);
    }

    public List<HostResult> getResults() {
        return results;
    }

    public int getTotalTargets() {
        return totalTargets;
    }

    public void setTotalTargets(int totalTargets) {
        this.totalTargets = totalTargets;
    }

    public int getSuccessCount() {
        return successCount;
    }

    public void setSuccessCount(int successCount) {
        this.successCount = successCount;
    }

    public int getErrorCount() {
        return errorCount;
    }

    public void setErrorCount(int errorCount) {
        this.errorCount = errorCount;
    }

    public SourceProvenance getTargetSource() {
        return targetSource;
    }

    public void setTargetSource(SourceProvenance targetSource) {
        this.targetSource = targetSource;
    }

    public SourceProvenance getScanSource() {
        return scanSource;
    }

    public void setScanSource(SourceProvenance scanSource) {
        this.scanSource = scanSource;
    }

    // ---- Error column helper ----

    /**
     * Computes which columns contain at least one host that produced an error.
     */
    private boolean[] computeErrorColumns(int nBlocks) {
        boolean[] ec = new boolean[nBlocks];
        for (int i = 0; i < results.size(); i++) {
            if (!results.get(i).isSuccess()) {
                int[] range = HeatMapData.assignBlockRange(i, results.size(), nBlocks);
                for (int bi = range[0]; bi <= range[1]; bi++) ec[bi] = true;
            }
        }
        return ec;
    }

    // ---- Heat Map Builders ----

    /**
     * Builds a risk assessment heat map. Rows are individual deduction rules
     * grouped by risk category, plus a CERTIFICATE category with 3 synthetic
     * rows for trust state, validity, and expiration. Cells reflect whether
     * each rule fired on the hosts assigned to that block.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.RISK
     */
    public HeatMapData toRiskHeatMap(int nBlocks) {
        List<HostResult> successful = new ArrayList<>();
        for (HostResult hr : results) {
            if (hr.isSuccess() && hr.getRiskScore() != null) {
                successful.add(hr);
            }
        }

        if (successful.isEmpty()) {
            return new HeatMapData(MapType.RISK, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);

        // Collect unique ruleIds grouped by category, and track ruleId -> description
        // Use LinkedHashMap to maintain insertion order by category
        Map<String, LinkedHashSet<String>> categoryRuleIds = new LinkedHashMap<>();
        Map<String, String> ruleIdToDescription = new HashMap<>();

        for (HostResult hr : successful) {
            IRiskScore.ICategoryScore[] categories = hr.getRiskScore().getCategoryScores();
            if (categories == null) continue;
            for (IRiskScore.ICategoryScore cat : categories) {
                String catName = cat.getDisplayName();
                categoryRuleIds.computeIfAbsent(catName, k -> new LinkedHashSet<>());
                IRiskScore.IDeduction[] deductions = cat.getDeductions();
                if (deductions == null) continue;
                for (IRiskScore.IDeduction ded : deductions) {
                    // Skip INFO severity deductions — they are informational,
                    // not risk findings, and belong in host detail only.
                    if ("INFO".equals(ded.getSeverity())) continue;
                    categoryRuleIds.get(catName).add(ded.getRuleId());
                    ruleIdToDescription.put(ded.getRuleId(), ded.getDescription());
                }
            }
        }

        // Build a per-host index of ruleIds that fired, along with inconclusive status
        // hostIndex -> (ruleId -> isInconclusive)
        List<Map<String, Boolean>> hostDeductionMaps = new ArrayList<>();
        for (HostResult hr : successful) {
            Map<String, Boolean> dedMap = new HashMap<>();
            IRiskScore.ICategoryScore[] categories = hr.getRiskScore().getCategoryScores();
            if (categories != null) {
                for (IRiskScore.ICategoryScore cat : categories) {
                    IRiskScore.IDeduction[] deductions = cat.getDeductions();
                    if (deductions == null) continue;
                    for (IRiskScore.IDeduction ded : deductions) {
                        if ("INFO".equals(ded.getSeverity())) continue;
                        dedMap.put(ded.getRuleId(), ded.isInconclusive());
                    }
                }
            }
            hostDeductionMaps.add(dedMap);
        }

        // Build rows from deduction rules
        List<HeatMapRow> rows = new ArrayList<>();
        for (Map.Entry<String, LinkedHashSet<String>> entry : categoryRuleIds.entrySet()) {
            String category = entry.getKey();
            for (String ruleId : entry.getValue()) {
                HeatMapCell[] cells = createEmptyCells(nBlocks);

                for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                    int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                    Map<String, Boolean> dedMap = hostDeductionMaps.get(hostIdx);
                    String hostName = successful.get(hostIdx).getTargetUrl();

                    for (int bi = range[0]; bi <= range[1]; bi++) {
                        HeatMapCell cell = cells[bi];
                        if (dedMap.containsKey(ruleId)) {
                            boolean inconclusive = dedMap.get(ruleId);
                            if (inconclusive) {
                                cell.addInconclusive();
                            } else {
                                cell.addFail();
                            }
                        } else {
                            cell.addPass();
                        }
                        cell.addHostName(hostName);
                    }
                }

                String description = ruleIdToDescription.getOrDefault(ruleId, "");
                rows.add(new HeatMapRow(category, ruleId, description, null, cells));
            }
        }

        // Add synthetic CERTIFICATE category rows from scan tree cert chain data
        addSyntheticCertRows(rows, successful, totalSuccessful, nBlocks);

        return new HeatMapData(MapType.RISK, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    /**
     * Adds 3 synthetic certificate risk rows to the CERTIFICATE category:
     * cert.not.trusted, cert.validity.failed, cert.expiring.60days.
     */
    private void addSyntheticCertRows(List<HeatMapRow> rows,
            List<HostResult> successful, int totalSuccessful, int nBlocks) {

        String[] rowIds = { "cert.not.trusted", "cert.validity.failed", "cert.expiring.60days" };
        String[] descriptions = { "Certificate not trusted", "Certificate validity failed",
                "Certificate expiring within 60 days" };
        HeatMapCell[][] allCells = new HeatMapCell[3][];
        for (int r = 0; r < 3; r++) {
            allCells[r] = createEmptyCells(nBlocks);
        }

        for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
            int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
            String hostName = successful.get(hostIdx).getTargetUrl();
            ScanNode tree = successful.get(hostIdx).getScanTree();

            ScanNode certSection = tree != null ? findSection(tree, "Server certificate chain") : null;
            ScanNode endEntity = null;
            if (certSection != null) {
                for (ScanNode child : certSection.getChildren()) {
                    if (child.getType() == ScanNode.NodeType.SUBSECTION) {
                        endEntity = child;
                        break;
                    }
                }
            }

            for (int bi = range[0]; bi <= range[1]; bi++) {
                // cert.not.trusted
                String trustState = endEntity != null ? findKeyValue(endEntity, "TrustState") : null;
                if (trustState != null && trustState.contains("TRUSTED") && !trustState.contains("UNTRUSTED")) {
                    allCells[0][bi].addPass();
                } else if (trustState != null) {
                    allCells[0][bi].addFail();
                } else {
                    allCells[0][bi].addInconclusive();
                }
                allCells[0][bi].addHostName(hostName);

                // cert.validity.failed
                String validity = endEntity != null ? findKeyValue(endEntity, "ValidState") : null;
                if (validity == null) validity = endEntity != null ? findKeyValue(endEntity, "Validity") : null;
                if (validity != null && validity.toUpperCase().contains("VALID") && !validity.toUpperCase().contains("EXPIRED")) {
                    allCells[1][bi].addPass();
                } else if (validity != null) {
                    allCells[1][bi].addFail();
                } else {
                    allCells[1][bi].addInconclusive();
                }
                allCells[1][bi].addHostName(hostName);

                // cert.expiring.60days
                String daysStr = endEntity != null ? findKeyValue(endEntity, "DaysUntilExpiration") : null;
                if (daysStr != null) {
                    try {
                        int days = Integer.parseInt(daysStr.trim());
                        if (days >= 60) {
                            allCells[2][bi].addPass();
                        } else {
                            allCells[2][bi].addFail();
                        }
                    } catch (NumberFormatException e) {
                        allCells[2][bi].addInconclusive();
                    }
                } else {
                    allCells[2][bi].addInconclusive();
                }
                allCells[2][bi].addHostName(hostName);
            }
        }

        for (int r = 0; r < 3; r++) {
            rows.add(new HeatMapRow("CERTIFICATE", rowIds[r], descriptions[r], null, allCells[r]));
        }
    }

    /**
     * Builds a cipher suite heat map. Rows are individual cipher suites grouped
     * by strength (CLEAR, WEAK, MEDIUM, STRONG). All ciphers use uniform
     * "available" logic: cipher offered by host = pass, not offered = fail.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.CIPHER
     */
    public HeatMapData toCipherHeatMap(int nBlocks) {
        List<HostResult> successful = new ArrayList<>();
        for (HostResult hr : results) {
            if (hr.isSuccess() && hr.getCiphers() != null) {
                successful.add(hr);
            }
        }

        if (successful.isEmpty()) {
            return new HeatMapData(MapType.CIPHER, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);

        // Build per-host set of offered cipher names
        List<Set<String>> hostCipherSets = new ArrayList<>();
        for (HostResult hr : successful) {
            Set<String> names = new LinkedHashSet<>();
            for (ICipherSuite cs : hr.getCiphers()) {
                names.add(cs.getSuiteName());
            }
            hostCipherSets.add(names);
        }

        // Collect union of all cipher names grouped by strength in order: CLEAR, WEAK, MEDIUM, STRONG
        String[] strengthOrder = {"CLEAR", "WEAK", "MEDIUM", "STRONG"};
        Map<String, LinkedHashSet<String>> strengthToCiphers = new LinkedHashMap<>();
        for (String s : strengthOrder) {
            strengthToCiphers.put(s, new LinkedHashSet<>());
        }

        // Also track cipher name -> strength
        Map<String, String> cipherStrength = new HashMap<>();
        for (HostResult hr : successful) {
            for (ICipherSuite cs : hr.getCiphers()) {
                String name = cs.getSuiteName();
                String strength = cs.getStrengthEvaluation();
                if (!cipherStrength.containsKey(name)) {
                    cipherStrength.put(name, strength);
                    LinkedHashSet<String> group = strengthToCiphers.get(strength);
                    if (group != null) {
                        group.add(name);
                    } else {
                        // Unknown strength category; add to end
                        strengthToCiphers.computeIfAbsent(strength, k -> new LinkedHashSet<>()).add(name);
                    }
                }
            }
        }

        // Build rows - uniform "available" logic for all strength levels
        List<HeatMapRow> rows = new ArrayList<>();
        for (Map.Entry<String, LinkedHashSet<String>> entry : strengthToCiphers.entrySet()) {
            String strength = entry.getKey();
            for (String cipherName : entry.getValue()) {
                HeatMapCell[] cells = createEmptyCells(nBlocks);

                for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                    int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                    boolean offered = hostCipherSets.get(hostIdx).contains(cipherName);
                    String hostName = successful.get(hostIdx).getTargetUrl();

                    for (int bi = range[0]; bi <= range[1]; bi++) {
                        HeatMapCell cell = cells[bi];
                        if (offered) {
                            cell.addPass();
                        } else {
                            cell.addFail();
                        }
                        cell.addHostName(hostName);
                    }
                }

                rows.add(new HeatMapRow(strength, cipherName, cipherName, null, cells));
            }
        }

        return new HeatMapData(MapType.CIPHER, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    /**
     * Builds a security headers heat map. Rows are the 7 standard security
     * headers; present = pass, MISSING = fail.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.SECURITY_HEADERS
     */
    public HeatMapData toSecurityHeadersHeatMap(int nBlocks) {
        List<HostResult> successful = filterSuccessful(null);
        if (successful.isEmpty()) {
            return new HeatMapData(MapType.SECURITY_HEADERS, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);
        List<HeatMapRow> rows = new ArrayList<>();

        String[] secHeaderNames = {
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        };

        for (String headerName : secHeaderNames) {
            HeatMapCell[] cells = createEmptyCells(nBlocks);

            for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                String hostName = successful.get(hostIdx).getTargetUrl();
                Map<String, String> secHeaders = successful.get(hostIdx).getSecurityHeaders();

                for (int bi = range[0]; bi <= range[1]; bi++) {
                    HeatMapCell cell = cells[bi];
                    if (secHeaders != null) {
                        String value = secHeaders.get(headerName);
                        if (value != null && !"MISSING".equals(value)) {
                            cell.addPass();
                        } else {
                            cell.addFail();
                        }
                    } else {
                        cell.addFail();
                    }
                    cell.addHostName(hostName);
                }
            }

            rows.add(new HeatMapRow("SECURITY HEADERS", headerName, headerName, null, cells));
        }

        return new HeatMapData(MapType.SECURITY_HEADERS, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    /**
     * Builds a connection properties heat map. Rows include per-value expansion
     * for NEGOTIATED_PROTOCOL and NEGOTIATED_CIPHER_SUITE (one row per unique
     * value across hosts), plus property-specific logic for other properties
     * like DEFLATE_COMPRESSION.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.CONNECTION
     */
    public HeatMapData toConnectionHeatMap(int nBlocks) {
        List<HostResult> successful = filterSuccessful(null);
        if (successful.isEmpty()) {
            return new HeatMapData(MapType.CONNECTION, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);
        List<HeatMapRow> rows = new ArrayList<>();

        LinkedHashSet<String> allConnKeys = new LinkedHashSet<>();
        for (HostResult hr : successful) {
            if (hr.getConnProperties() != null) {
                allConnKeys.addAll(hr.getConnProperties().keySet());
            }
        }

        for (String propKey : allConnKeys) {
            if ("NEGOTIATED_PROTOCOL".equals(propKey)) {
                // Expand to per-protocol rows
                LinkedHashSet<String> uniqueProtocols = new LinkedHashSet<>();
                for (HostResult hr : successful) {
                    Map<String, String> props = hr.getConnProperties();
                    String value = (props != null) ? props.get(propKey) : null;
                    if (value != null && !value.isEmpty()) {
                        uniqueProtocols.add(value);
                    }
                }

                for (String protocol : uniqueProtocols) {
                    HeatMapCell[] cells = createEmptyCells(nBlocks);
                    for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                        int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                        String hostName = successful.get(hostIdx).getTargetUrl();
                        Map<String, String> props = successful.get(hostIdx).getConnProperties();
                        String value = (props != null) ? props.get(propKey) : null;

                        for (int bi = range[0]; bi <= range[1]; bi++) {
                            HeatMapCell cell = cells[bi];
                            if (protocol.equals(value)) {
                                cell.addPass();
                            } else {
                                cell.addFail();
                            }
                            cell.addHostName(hostName);
                        }
                    }
                    String rowId = "NEGOTIATED_PROTOCOL_" + protocol;
                    rows.add(new HeatMapRow("CONNECTION PROPERTIES", rowId, rowId, null, cells));
                }

            } else if ("NEGOTIATED_CIPHER_SUITE".equals(propKey)) {
                // Expand to per-cipher rows
                LinkedHashSet<String> uniqueCiphers = new LinkedHashSet<>();
                for (HostResult hr : successful) {
                    Map<String, String> props = hr.getConnProperties();
                    String value = (props != null) ? props.get(propKey) : null;
                    if (value != null && !value.isEmpty()) {
                        uniqueCiphers.add(value);
                    }
                }

                for (String cipher : uniqueCiphers) {
                    HeatMapCell[] cells = createEmptyCells(nBlocks);
                    for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                        int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                        String hostName = successful.get(hostIdx).getTargetUrl();
                        Map<String, String> props = successful.get(hostIdx).getConnProperties();
                        String value = (props != null) ? props.get(propKey) : null;

                        for (int bi = range[0]; bi <= range[1]; bi++) {
                            HeatMapCell cell = cells[bi];
                            if (cipher.equals(value)) {
                                cell.addPass();
                            } else {
                                cell.addFail();
                            }
                            cell.addHostName(hostName);
                        }
                    }
                    String rowId = "NEGOTIATED_CIPHER_SUITE-->" + cipher;
                    rows.add(new HeatMapRow("CONNECTION PROPERTIES", rowId, rowId, null, cells));
                }

            } else if ("DEFLATE_COMPRESSION".equals(propKey)) {
                HeatMapCell[] cells = createEmptyCells(nBlocks);
                for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                    int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                    String hostName = successful.get(hostIdx).getTargetUrl();
                    Map<String, String> props = successful.get(hostIdx).getConnProperties();
                    String value = (props != null) ? props.get(propKey) : null;

                    for (int bi = range[0]; bi <= range[1]; bi++) {
                        HeatMapCell cell = cells[bi];
                        if ("false".equalsIgnoreCase(value)) {
                            cell.addPass();
                        } else {
                            cell.addFail();
                        }
                        cell.addHostName(hostName);
                    }
                }
                rows.add(new HeatMapRow("CONNECTION PROPERTIES", propKey, propKey, null, cells));

            } else {
                // Generic property: find majority value per block, then compare
                Map<Integer, List<String>> blockValues = new HashMap<>();
                Map<Integer, List<Integer>> blockHostIndices = new HashMap<>();
                for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                    int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                    Map<String, String> props = successful.get(hostIdx).getConnProperties();
                    String value = (props != null) ? props.get(propKey) : null;
                    for (int bi = range[0]; bi <= range[1]; bi++) {
                        blockValues.computeIfAbsent(bi, k -> new ArrayList<>());
                        blockHostIndices.computeIfAbsent(bi, k -> new ArrayList<>());
                        blockValues.get(bi).add(value);
                        blockHostIndices.get(bi).add(hostIdx);
                    }
                }

                HeatMapCell[] cells = createEmptyCells(nBlocks);
                for (int blockIdx = 0; blockIdx < nBlocks; blockIdx++) {
                    HeatMapCell cell = cells[blockIdx];
                    List<String> values = blockValues.get(blockIdx);
                    List<Integer> hostIndices = blockHostIndices.get(blockIdx);
                    if (values == null || values.isEmpty()) continue;

                    String majorityValue = findMajority(values);

                    for (int i = 0; i < values.size(); i++) {
                        String v = values.get(i);
                        String hostName = successful.get(hostIndices.get(i)).getTargetUrl();
                        if (v != null && v.equals(majorityValue)) {
                            cell.addPass();
                        } else {
                            cell.addInconclusive();
                        }
                        cell.addHostName(hostName);
                    }
                }

                rows.add(new HeatMapRow("CONNECTION PROPERTIES", propKey, propKey, null, cells));
            }
        }

        return new HeatMapData(MapType.CONNECTION, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    /**
     * Builds an HTTP response headers heat map. Rows are individual HTTP headers;
     * present = pass, absent = fail.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.HTTP_RESPONSE
     */
    public HeatMapData toHttpResponseHeatMap(int nBlocks) {
        List<HostResult> successful = filterSuccessful(null);
        if (successful.isEmpty()) {
            return new HeatMapData(MapType.HTTP_RESPONSE, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);
        List<HeatMapRow> rows = new ArrayList<>();

        LinkedHashSet<String> allHttpHeaderNames = new LinkedHashSet<>();
        for (HostResult hr : successful) {
            if (hr.getHttpHeaders() != null) {
                allHttpHeaderNames.addAll(hr.getHttpHeaders().keySet());
            }
        }

        for (String headerName : allHttpHeaderNames) {
            HeatMapCell[] cells = createEmptyCells(nBlocks);

            for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                String hostName = successful.get(hostIdx).getTargetUrl();
                Map<String, String> headers = successful.get(hostIdx).getHttpHeaders();

                for (int bi = range[0]; bi <= range[1]; bi++) {
                    HeatMapCell cell = cells[bi];
                    if (headers != null && headers.containsKey(headerName)) {
                        cell.addPass();
                    } else {
                        cell.addFail();
                    }
                    cell.addHostName(hostName);
                }
            }

            rows.add(new HeatMapRow("HTTP RESPONSE HEADERS", headerName, headerName, null, cells));
        }

        return new HeatMapData(MapType.HTTP_RESPONSE, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    /**
     * Builds a revocation status heat map from the scan tree (end-entity cert only).
     * Rows: OCSP Responder, OCSP Stapling, CRL Status, OneCRL Status, CT SCTs.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.REVOCATION
     */
    public HeatMapData toRevocationHeatMap(int nBlocks) {
        List<HostResult> successful = filterSuccessful(hr -> hr.getScanTree() != null);
        if (successful.isEmpty()) {
            return new HeatMapData(MapType.REVOCATION, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);

        String[] rowNames = {
            "OCSP Responder", "OCSP Stapling", "CRL Status", "OneCRL Status", "CT SCTs"
        };
        HeatMapCell[][] allCells = new HeatMapCell[rowNames.length][];
        for (int r = 0; r < rowNames.length; r++) {
            allCells[r] = createEmptyCells(nBlocks);
        }

        for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
            int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
            String hostName = successful.get(hostIdx).getTargetUrl();
            ScanNode tree = successful.get(hostIdx).getScanTree();

            ScanNode revSection = findSection(tree, "Revocation status");
            // Look for end-entity cert subsection or OCSP subsection
            ScanNode ocspNode = revSection != null ? findSubsection(revSection, "OCSP") : null;
            ScanNode crlNode = revSection != null ? findSubsection(revSection, "CRL") : null;
            ScanNode onecrlNode = revSection != null ? findSubsection(revSection, "OneCRL") : null;
            ScanNode sctNode = revSection != null ? findSubsection(revSection, "SCT") : null;
            if (sctNode == null && revSection != null) sctNode = findSubsection(revSection, "CT");

            for (int bi = range[0]; bi <= range[1]; bi++) {
                // OCSP Responder
                String ocspStatus = ocspNode != null ? findKeyValue(ocspNode, "Status") : null;
                if (ocspStatus == null && revSection != null) ocspStatus = findKeyValue(revSection, "OCSPStatus");
                if (ocspStatus != null) {
                    String upper = ocspStatus.toUpperCase();
                    if (upper.contains("GOOD")) {
                        allCells[0][bi].addPass();
                    } else if (upper.contains("REVOKED")) {
                        allCells[0][bi].addFail();
                    } else {
                        allCells[0][bi].addInconclusive();
                    }
                } else {
                    allCells[0][bi].addInconclusive();
                }
                allCells[0][bi].addHostName(hostName);

                // OCSP Stapling
                String stapling = ocspNode != null ? findKeyValue(ocspNode, "Stapling") : null;
                if (stapling == null && revSection != null) stapling = findKeyValue(revSection, "OCSPStapling");
                if (stapling != null) {
                    String upper = stapling.toUpperCase();
                    if (upper.contains("PRESENT") || upper.contains("YES") || upper.contains("TRUE")) {
                        allCells[1][bi].addPass();
                    } else {
                        allCells[1][bi].addFail();
                    }
                } else {
                    allCells[1][bi].addInconclusive();
                }
                allCells[1][bi].addHostName(hostName);

                // CRL Status
                String crlStatus = crlNode != null ? findKeyValue(crlNode, "Status") : null;
                if (crlStatus == null && revSection != null) crlStatus = findKeyValue(revSection, "CRLStatus");
                if (crlStatus != null) {
                    String upper = crlStatus.toUpperCase();
                    if (upper.contains("GOOD") || upper.contains("NOT REVOKED")) {
                        allCells[2][bi].addPass();
                    } else if (upper.contains("REVOKED")) {
                        allCells[2][bi].addFail();
                    } else {
                        allCells[2][bi].addInconclusive();
                    }
                } else {
                    allCells[2][bi].addInconclusive();
                }
                allCells[2][bi].addHostName(hostName);

                // OneCRL Status
                String onecrlStatus = onecrlNode != null ? findKeyValue(onecrlNode, "Status") : null;
                if (onecrlStatus == null && revSection != null) onecrlStatus = findKeyValue(revSection, "OneCRLStatus");
                if (onecrlStatus != null) {
                    String upper = onecrlStatus.toUpperCase();
                    if (upper.contains("NOT FOUND") || upper.contains("GOOD")) {
                        allCells[3][bi].addPass();
                    } else if (upper.contains("FOUND") || upper.contains("REVOKED")) {
                        allCells[3][bi].addFail();
                    } else {
                        allCells[3][bi].addInconclusive();
                    }
                } else {
                    allCells[3][bi].addInconclusive();
                }
                allCells[3][bi].addHostName(hostName);

                // CT SCTs
                String sctStatus = sctNode != null ? findKeyValue(sctNode, "Status") : null;
                if (sctStatus == null && sctNode != null) sctStatus = findKeyValue(sctNode, "SCTs");
                if (sctStatus == null && revSection != null) sctStatus = findKeyValue(revSection, "SCTStatus");
                boolean hasScts = sctStatus != null
                        && !sctStatus.toUpperCase().contains("NONE")
                        && !sctStatus.toUpperCase().contains("NOT ");
                if (hasScts) {
                    allCells[4][bi].addPass();
                } else if (sctStatus != null) {
                    allCells[4][bi].addFail();
                } else {
                    allCells[4][bi].addInconclusive();
                }
                allCells[4][bi].addHostName(hostName);
            }
        }

        List<HeatMapRow> rows = new ArrayList<>();
        for (int r = 0; r < rowNames.length; r++) {
            rows.add(new HeatMapRow("REVOCATION", rowNames[r], rowNames[r], null, allCells[r]));
        }
        return new HeatMapData(MapType.REVOCATION, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    /**
     * Builds a TLS fingerprint heat map. Rows are the 10 probe codes plus the
     * extension hash. Cells compare each host's probe response to the majority
     * value across all hosts.
     *
     * @param nBlocks number of columns (blocks) in the heat map
     * @return populated HeatMapData with MapType.FINGERPRINT
     */
    public HeatMapData toFingerprintHeatMap(int nBlocks) {
        List<HostResult> successful = new ArrayList<>();
        for (HostResult hr : results) {
            if (hr.isSuccess() && hr.getTlsFingerprint() != null) {
                successful.add(hr);
            }
        }

        if (successful.isEmpty()) {
            return new HeatMapData(MapType.FINGERPRINT, new ArrayList<>(), nBlocks, 0);
        }

        int totalSuccessful = successful.size();
        int hostsPerBlock = Math.max(1, (totalSuccessful + nBlocks - 1) / nBlocks);

        String[] probeDescriptions = {
            "TLS 1.2 standard cipher order",
            "TLS 1.2 reverse cipher order",
            "TLS 1.2 with ALPN h2",
            "TLS 1.2 no ECC support",
            "TLS 1.1 only",
            "TLS 1.3 only (TLS 1.3 ciphers)",
            "TLS 1.3 with TLS 1.2 fallback",
            "TLS 1.3 with ALPN h2",
            "TLS 1.3 reverse cipher order",
            "TLS 1.2 forward secrecy only"
        };

        // Parse all fingerprints
        List<FingerprintComponents> parsed = new ArrayList<>();
        for (HostResult hr : successful) {
            parsed.add(TlsServerFingerprint.parse(hr.getTlsFingerprint()));
        }

        // 11 rows: Probe 1-10 + Ext Hash
        // Extract values for each row across all hosts
        int totalRows = 11;
        List<String[]> rowValues = new ArrayList<>(); // rowIndex -> host values
        for (int rowIdx = 0; rowIdx < totalRows; rowIdx++) {
            String[] values = new String[totalSuccessful];
            for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                FingerprintComponents fc = parsed.get(hostIdx);
                if (rowIdx < 10) {
                    values[hostIdx] = fc.getProbeCode(rowIdx + 1);
                } else {
                    values[hostIdx] = fc.getExtensionHash();
                }
            }
            rowValues.add(values);
        }

        // Build rows
        List<HeatMapRow> rows = new ArrayList<>();
        for (int rowIdx = 0; rowIdx < totalRows; rowIdx++) {
            String[] values = rowValues.get(rowIdx);

            // Find the most common non-failed value across ALL hosts
            String majorityValue = findMajority(Arrays.asList(values));

            HeatMapCell[] cells = createEmptyCells(nBlocks);

            for (int hostIdx = 0; hostIdx < totalSuccessful; hostIdx++) {
                int[] range = HeatMapData.assignBlockRange(hostIdx, totalSuccessful, nBlocks);
                String hostName = successful.get(hostIdx).getTargetUrl();
                String value = values[hostIdx];
                FingerprintComponents fc = parsed.get(hostIdx);

                for (int bi = range[0]; bi <= range[1]; bi++) {
                    HeatMapCell cell = cells[bi];
                    if (rowIdx < 10 && !fc.probeSucceeded(rowIdx + 1)) {
                        cell.addInconclusive();
                    } else if (value != null && value.equals(majorityValue)) {
                        cell.addPass();
                    } else {
                        cell.addFail();
                    }
                    cell.addHostName(hostName);
                }
            }

            String rowId;
            String description;
            String qualifier;

            if (rowIdx < 10) {
                rowId = "Probe " + (rowIdx + 1);
                description = "Probe " + (rowIdx + 1);
                qualifier = probeDescriptions[rowIdx];
            } else {
                rowId = "Ext Hash";
                description = "Extension Hash";
                qualifier = null;
            }

            rows.add(new HeatMapRow("FINGERPRINT", rowId, description, qualifier, cells));
        }

        return new HeatMapData(MapType.FINGERPRINT, rows, nBlocks, hostsPerBlock, totalSuccessful,
                computeErrorColumns(nBlocks));
    }

    // ---- Private Helpers ----

    /**
     * Filters results to successful hosts, optionally applying an additional predicate.
     */
    private List<HostResult> filterSuccessful(java.util.function.Predicate<HostResult> extra) {
        List<HostResult> successful = new ArrayList<>();
        for (HostResult hr : results) {
            if (hr.isSuccess() && (extra == null || extra.test(hr))) {
                successful.add(hr);
            }
        }
        return successful;
    }

    /**
     * Finds a SECTION child of the given root node by name (case-insensitive).
     */
    static ScanNode findSection(ScanNode root, String name) {
        if (root == null) return null;
        for (ScanNode child : root.getChildren()) {
            if (child.getType() == ScanNode.NodeType.SECTION
                    && child.getKey() != null
                    && child.getKey().equalsIgnoreCase(name)) {
                return child;
            }
        }
        return null;
    }

    /**
     * Finds a SUBSECTION child whose key contains the given substring (case-insensitive).
     */
    static ScanNode findSubsection(ScanNode parent, String nameFragment) {
        if (parent == null) return null;
        for (ScanNode child : parent.getChildren()) {
            if (child.getType() == ScanNode.NodeType.SUBSECTION
                    && child.getKey() != null
                    && child.getKey().toLowerCase().contains(nameFragment.toLowerCase())) {
                return child;
            }
        }
        return null;
    }

    /**
     * Finds the value of a KEY_VALUE child with the given key.
     * Searches recursively through subsections.
     */
    static String findKeyValue(ScanNode parent, String key) {
        if (parent == null) return null;
        for (ScanNode child : parent.getChildren()) {
            if (child.getType() == ScanNode.NodeType.KEY_VALUE
                    && key.equalsIgnoreCase(child.getKey())) {
                return child.getValue();
            }
            if (child.getType() == ScanNode.NodeType.SUBSECTION) {
                String found = findKeyValue(child, key);
                if (found != null) return found;
            }
        }
        return null;
    }

    /**
     * Creates an array of empty HeatMapCells of the given size.
     */
    private static HeatMapCell[] createEmptyCells(int nBlocks) {
        HeatMapCell[] cells = new HeatMapCell[nBlocks];
        for (int i = 0; i < nBlocks; i++) {
            cells[i] = new HeatMapCell(0, 0, 0, null, new ArrayList<>());
        }
        return cells;
    }

    /**
     * Finds the most common value in a list (simple majority/mode).
     * Null values are included in the count. Returns null if the list is empty.
     */
    private static String findMajority(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }

        Map<String, Integer> counts = new HashMap<>();
        for (String v : values) {
            String key = (v != null) ? v : "\0NULL\0";
            counts.merge(key, 1, Integer::sum);
        }

        String majorityKey = null;
        int maxCount = 0;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (e.getValue() > maxCount) {
                maxCount = e.getValue();
                majorityKey = e.getKey();
            }
        }

        return "\0NULL\0".equals(majorityKey) ? null : majorityKey;
    }
}
