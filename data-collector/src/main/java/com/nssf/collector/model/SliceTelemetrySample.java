package com.nssf.collector.model;

import java.util.Locale;
import java.util.StringJoiner;

/**
 * A Data Object (POJO) representing a single snapshot of telemetry metrics
 * for a specific 5G network slice at a given point in time.
 */
public class SliceTelemetrySample {

    // Metadata
    private long timestamp;           // Unix epoch timestamp in milliseconds
    private int sliceType;            // SST: 1=eMBB, 2=URLLC, 3=mMTC
    private String sessionLabel;      // Categorization label (e.g. "normal" or "attack")

    // AMF (Access and Mobility Management Function) features
    private double regAttemptRate;
    private double regFailureRate;
    private double regSuccessRate;
    private double authAttemptRate;
    private double authFailureRate;
    private double authSuccessRate;
    private long authMacFailures;
    private long authSqnFailures;
    private double secFailureRate;
    private int connectedUeCount;
    private int registeredUeCount;
    private double serviceRequestRate;
    private double pagingRate;
    private double ngapSetupFailureRate;

    // SMF (Session Management Function) features
    private double sessionAttemptRate;
    private double sessionFailureRate;
    private double sessionSuccessRate;
    private int activePduSessions;
    private int sessionsInThisSlice;
    private double qosFlowFailureRate;

    // UPF (User Plane Function) features
    private double ulPacketRate;
    private double dlPacketRate;
    private double ulByteRate;
    private double dlByteRate;
    private long ulDropped;
    private long dlDropped;
    private double packetLossRate;
    private long gtpuErrors;

    // NSSF (Network Slice Selection Function) features
    private double sliceSelectionFailureRate;

    // NWDAF (Network Data Analytics Function) computed features
    private int nfLoadLevel;          // Represented as categorical integer: 0=low, 1=medium, 2=high
    private int qosStatus;            // Represented as categorical integer: 0=sustainable, 1=at_risk, 2=degraded
    private int anomalyAlertCount;

    // Metadata for service health
    private int serviceUp = 1;

    // Default constructor
    public SliceTelemetrySample() {}

    /**
     * Generates a CSV header string mapping to the fields of this class.
     */
    public static String csvHeader() {
        return "timestamp,sliceType,sessionLabel," +
                "regAttemptRate,regFailureRate,regSuccessRate,authAttemptRate,authFailureRate,authSuccessRate,authMacFailures,authSqnFailures,secFailureRate," +
                "connectedUeCount,registeredUeCount,serviceRequestRate,pagingRate,ngapSetupFailureRate," +
                "sessionAttemptRate,sessionFailureRate,sessionSuccessRate,activePduSessions,sessionsInThisSlice,qosFlowFailureRate," +
                "ulPacketRate,dlPacketRate,ulByteRate,dlByteRate,ulDropped,dlDropped,packetLossRate,gtpuErrors," +
                "sliceSelectionFailureRate," +
                "nfLoadLevel,qosStatus,anomalyAlertCount,serviceUp";
    }

    /**
     * Serializes the current object state into a comma-separated string row.
     */
    public String toCsvRow() {
        StringJoiner sj = new StringJoiner(",");
        // Add metadata
        sj.add(String.valueOf(timestamp));
        sj.add(String.valueOf(sliceType));
        sj.add(sessionLabel != null ? sessionLabel : "");

        // Add AMF metrics (formatted to 4 decimal places)
        sj.add(format(regAttemptRate));
        sj.add(format(regFailureRate));
        sj.add(format(regSuccessRate));
        sj.add(format(authAttemptRate));
        sj.add(format(authFailureRate));
        sj.add(format(authSuccessRate));
        sj.add(String.valueOf(authMacFailures));
        sj.add(String.valueOf(authSqnFailures));
        sj.add(format(secFailureRate));

        sj.add(String.valueOf(connectedUeCount));
        sj.add(String.valueOf(registeredUeCount));
        sj.add(format(serviceRequestRate));
        sj.add(format(pagingRate));
        sj.add(format(ngapSetupFailureRate));

        // Add SMF metrics
        sj.add(format(sessionAttemptRate));
        sj.add(format(sessionFailureRate));
        sj.add(format(sessionSuccessRate));
        sj.add(String.valueOf(activePduSessions));
        sj.add(String.valueOf(sessionsInThisSlice));
        sj.add(format(qosFlowFailureRate));

        // Add UPF metrics
        sj.add(format(ulPacketRate));
        sj.add(format(dlPacketRate));
        sj.add(format(ulByteRate));
        sj.add(format(dlByteRate));
        sj.add(String.valueOf(ulDropped));
        sj.add(String.valueOf(dlDropped));
        sj.add(format(packetLossRate));
        sj.add(String.valueOf(gtpuErrors));

        // Add NSSF metrics
        sj.add(format(sliceSelectionFailureRate));

        // Add NWDAF metrics
        sj.add(String.valueOf(nfLoadLevel));
        sj.add(String.valueOf(qosStatus));
        sj.add(String.valueOf(anomalyAlertCount));

        // Add Service Health
        sj.add(String.valueOf(serviceUp));

        return sj.toString();
    }

    /**
     * Helper to format doubles consistently for CSV output.
     */
    private String format(double value) {
        return String.format(Locale.US, "%.4f", value);
    }

    // Standard Getters and Setters omitted for brevity in comments,
    // they just provide standard access to private fields.
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    public int getSliceType() { return sliceType; }
    public void setSliceType(int sliceType) { this.sliceType = sliceType; }
    public String getSessionLabel() { return sessionLabel; }
    public void setSessionLabel(String sessionLabel) { this.sessionLabel = sessionLabel; }
    public double getRegAttemptRate() { return regAttemptRate; }
    public void setRegAttemptRate(double regAttemptRate) { this.regAttemptRate = regAttemptRate; }
    public double getRegFailureRate() { return regFailureRate; }
    public void setRegFailureRate(double regFailureRate) { this.regFailureRate = regFailureRate; }
    public double getRegSuccessRate() { return regSuccessRate; }
    public void setRegSuccessRate(double regSuccessRate) { this.regSuccessRate = regSuccessRate; }
    public double getAuthAttemptRate() { return authAttemptRate; }
    public void setAuthAttemptRate(double authAttemptRate) { this.authAttemptRate = authAttemptRate; }
    public double getAuthFailureRate() { return authFailureRate; }
    public void setAuthFailureRate(double authFailureRate) { this.authFailureRate = authFailureRate; }
    public double getAuthSuccessRate() { return authSuccessRate; }
    public void setAuthSuccessRate(double authSuccessRate) { this.authSuccessRate = authSuccessRate; }
    public long getAuthMacFailures() { return authMacFailures; }
    public void setAuthMacFailures(long authMacFailures) { this.authMacFailures = authMacFailures; }
    public long getAuthSqnFailures() { return authSqnFailures; }
    public void setAuthSqnFailures(long authSqnFailures) { this.authSqnFailures = authSqnFailures; }
    public double getSecFailureRate() { return secFailureRate; }
    public void setSecFailureRate(double secFailureRate) { this.secFailureRate = secFailureRate; }
    public int getConnectedUeCount() { return connectedUeCount; }
    public void setConnectedUeCount(int connectedUeCount) { this.connectedUeCount = connectedUeCount; }
    public int getRegisteredUeCount() { return registeredUeCount; }
    public void setRegisteredUeCount(int registeredUeCount) { this.registeredUeCount = registeredUeCount; }
    public double getServiceRequestRate() { return serviceRequestRate; }
    public void setServiceRequestRate(double serviceRequestRate) { this.serviceRequestRate = serviceRequestRate; }
    public double getPagingRate() { return pagingRate; }
    public void setPagingRate(double pagingRate) { this.pagingRate = pagingRate; }
    public double getNgapSetupFailureRate() { return ngapSetupFailureRate; }
    public void setNgapSetupFailureRate(double ngapSetupFailureRate) { this.ngapSetupFailureRate = ngapSetupFailureRate; }
    public double getSessionAttemptRate() { return sessionAttemptRate; }
    public void setSessionAttemptRate(double sessionAttemptRate) { this.sessionAttemptRate = sessionAttemptRate; }
    public double getSessionFailureRate() { return sessionFailureRate; }
    public void setSessionFailureRate(double sessionFailureRate) { this.sessionFailureRate = sessionFailureRate; }
    public double getSessionSuccessRate() { return sessionSuccessRate; }
    public void setSessionSuccessRate(double sessionSuccessRate) { this.sessionSuccessRate = sessionSuccessRate; }
    public int getActivePduSessions() { return activePduSessions; }
    public void setActivePduSessions(int activePduSessions) { this.activePduSessions = activePduSessions; }
    public int getSessionsInThisSlice() { return sessionsInThisSlice; }
    public void setSessionsInThisSlice(int sessionsInThisSlice) { this.sessionsInThisSlice = sessionsInThisSlice; }
    public double getQosFlowFailureRate() { return qosFlowFailureRate; }
    public void setQosFlowFailureRate(double qosFlowFailureRate) { this.qosFlowFailureRate = qosFlowFailureRate; }
    public double getUlPacketRate() { return ulPacketRate; }
    public void setUlPacketRate(double ulPacketRate) { this.ulPacketRate = ulPacketRate; }
    public double getDlPacketRate() { return dlPacketRate; }
    public void setDlPacketRate(double dlPacketRate) { this.dlPacketRate = dlPacketRate; }
    public double getUlByteRate() { return ulByteRate; }
    public void setUlByteRate(double ulByteRate) { this.ulByteRate = ulByteRate; }
    public double getDlByteRate() { return dlByteRate; }
    public void setDlByteRate(double dlByteRate) { this.dlByteRate = dlByteRate; }
    public long getUlDropped() { return ulDropped; }
    public void setUlDropped(long ulDropped) { this.ulDropped = ulDropped; }
    public long getDlDropped() { return dlDropped; }
    public void setDlDropped(long dlDropped) { this.dlDropped = dlDropped; }
    public double getPacketLossRate() { return packetLossRate; }
    public void setPacketLossRate(double packetLossRate) { this.packetLossRate = packetLossRate; }
    public long getGtpuErrors() { return gtpuErrors; }
    public void setGtpuErrors(long gtpuErrors) { this.gtpuErrors = gtpuErrors; }
    public double getSliceSelectionFailureRate() { return sliceSelectionFailureRate; }
    public void setSliceSelectionFailureRate(double sliceSelectionFailureRate) { this.sliceSelectionFailureRate = sliceSelectionFailureRate; }
    public int getNfLoadLevel() { return nfLoadLevel; }
    public void setNfLoadLevel(int nfLoadLevel) { this.nfLoadLevel = nfLoadLevel; }
    public int getQosStatus() { return qosStatus; }
    public void setQosStatus(int qosStatus) { this.qosStatus = qosStatus; }
    public int getAnomalyAlertCount() { return anomalyAlertCount; }
    public void setAnomalyAlertCount(int anomalyAlertCount) { this.anomalyAlertCount = anomalyAlertCount; }
    public int getServiceUp() { return serviceUp; }
    public void setServiceUp(int serviceUp) { this.serviceUp = serviceUp; }
}