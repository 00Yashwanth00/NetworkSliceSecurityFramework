package com.nssf.collector.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.nssf.collector.config.CollectorConfig;
import com.nssf.collector.model.SliceTelemetrySample;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Service dedicated to transforming unstructured JSON API responses
 * into structured SliceTelemetrySample objects.
 */
public class FeatureExtractor {

    private static final Logger logger = LoggerFactory.getLogger(FeatureExtractor.class);

    // Previous-tick cumulative totals, used to turn MMT Studio's
    // since-process-start success ratios into real per-interval rates.
    // -1 means "no baseline yet" (first poll after startup/restart).
    private long prevRegSucc = -1, prevRegFail = -1;
    private long prevAuthSucc = -1, prevAuthFail = -1;
    private long prevSessSucc = -1, prevSessFail = -1;

    // Delta-based success rates for the CURRENT poll tick, computed once in
    // extractFeatures() before the per-slice loop and reused for every slice
    // sample generated from this same tick (fixes a subtle re-entrancy bug:
    // computing the delta separately per slice would consume the delta on
    // the first slice and show 0 for every subsequent slice in the same tick).
    private double currentRegSuccessRate = -1.0;
    private double currentAuthSuccessRate = -1.0;
    private double currentSessionSuccessRate = -1.0;

    /**
     * Primary entry point to parse data from multiple JSON sources.
     */
    public List<SliceTelemetrySample> extractFeatures(
            JsonNode kpiRaw,
            JsonNode kpiDashboard,
            JsonNode nwdafAnalytics) {

        List<SliceTelemetrySample> samples = new ArrayList<>();
        long timestamp = System.currentTimeMillis();
        String label = CollectorConfig.getInstance().getSessionLabel();

        // Discover which distinct network slices (SST) have active traffic in the payload
        Set<Integer> activeSlices = discoverActiveSlices(kpiDashboard, nwdafAnalytics);

        // Compute this tick's delta-based success rates ONCE, from the raw
        // cumulative counters, before generating per-slice samples below.
        computeDeltaSuccessRates(kpiRaw);

        // Fallback safety to ensure at least one record is generated
        if (activeSlices.isEmpty()) {
            logger.warn("No active slices discovered in the payload. Creating an empty sample for SST=1 fallback.");
            activeSlices.add(1);
        }

        // Generate one discrete sample object for every active slice discovered
        for (Integer sst : activeSlices) {
            SliceTelemetrySample sample = new SliceTelemetrySample();
            sample.setTimestamp(timestamp);
            sample.setSliceType(sst);
            sample.setSessionLabel(label);

            // Delegate field population to specific domain helpers
            populateFromKpiRaw(sample, kpiRaw);
            populateFromKpiDashboard(sample, kpiDashboard, sst);
            populateFromNwdafAnalytics(sample, nwdafAnalytics, sst);

            samples.add(sample);
        }

        return samples;
    }

    /**
     * Inspects dynamic JSON keys to compile a set of active slice identifiers (SSTs).
     */
    private Set<Integer> discoverActiveSlices(JsonNode dashboard, JsonNode nwdaf) {
        Set<Integer> slices = new HashSet<>();

        // Check Session Management Function dashboard for PDU session slice metrics
        if (dashboard != null && dashboard.has("smf") && dashboard.get("smf").has("pdu_per_slice")) {
            dashboard.get("smf").get("pdu_per_slice").fieldNames().forEachRemaining(key -> {
                try {
                    // Extract root SST (e.g., convert "1-000001" to "1")
                    String sstStr = key.contains("-") ? key.split("-")[0] : key;
                    slices.add(Integer.parseInt(sstStr));
                } catch (NumberFormatException ignored) {}
            });
        }

        // Check NWDAF analytics for slice load predictions
        if (nwdaf != null && nwdaf.has("analytics") && nwdaf.get("analytics").has("SLICE_LOAD")) {
            JsonNode sliceLoad = nwdaf.get("analytics").get("SLICE_LOAD");
            if (sliceLoad.has("result") && sliceLoad.get("result").has("slices")) {
                sliceLoad.get("result").get("slices").fieldNames().forEachRemaining(key -> {
                    try {
                        String sstStr = key.contains("-") ? key.split("-")[0] : key;
                        slices.add(Integer.parseInt(sstStr));
                    } catch (NumberFormatException ignored) {}
                });
            }
        }

        return slices;
    }

    /**
     * Extracts foundational rates and counts from the raw KPI payload.
     */
    private void populateFromKpiRaw(SliceTelemetrySample sample, JsonNode root) {
        if (root == null || !root.has("rates_per_sec")) return;

        JsonNode rates = root.get("rates_per_sec");
        // Accessing nested attributes using safe .path() which prevents null pointer exceptions
        // Provides default 0.0 if field is missing
        sample.setRegAttemptRate(rates.path("RM.RegAtt").asDouble(0.0));
        sample.setRegFailureRate(rates.path("RM.RegFail").asDouble(0.0));
        sample.setAuthAttemptRate(rates.path("AUTH.Att").asDouble(0.0));
        sample.setAuthFailureRate(rates.path("AUTH.Fail").asDouble(0.0));
        sample.setSecFailureRate(rates.path("SEC.Fail").asDouble(0.0));
        sample.setServiceRequestRate(rates.path("MM.SvcReqAtt").asDouble(0.0));
        sample.setPagingRate(rates.path("MM.PagingAtt").asDouble(0.0));
        sample.setNgapSetupFailureRate(rates.path("NGAP.SetupFail").asDouble(0.0));

        sample.setSessionAttemptRate(rates.path("SM.SessAtt").asDouble(0.0));
        sample.setSessionFailureRate(rates.path("SM.SessFail").asDouble(0.0));
        sample.setQosFlowFailureRate(rates.path("SM.FlowFail").asDouble(0.0));

        sample.setSliceSelectionFailureRate(rates.path("NSSF.SelFail").asDouble(0.0));

        // Delta-based success rates for THIS interval (see computeDeltaSuccessRates),
        // not MMT Studio's since-process-start cumulative ratio. The cumulative
        // version climbs briefly after boot then freezes for the rest of a run,
        // fingerprinting "how long has this process been up" rather than "what's
        // happening right now" — exactly the leak that made normal-vs-attack
        // separation look artificially perfect in earlier datasets.
        sample.setRegSuccessRate(currentRegSuccessRate);
        sample.setAuthSuccessRate(currentAuthSuccessRate);
        sample.setSessionSuccessRate(currentSessionSuccessRate);

        // Get absolute counter totals from the "counters" nested object
        JsonNode counters = root.path("counters");
        sample.setAuthMacFailures(counters.path("AUTH.FailMAC").asLong(0));
        sample.setAuthSqnFailures(counters.path("AUTH.FailSQN").asLong(0));
    }

    /**
     * Turns MMT Studio's since-process-start cumulative success/fail totals
     * into a real per-interval success rate, by diffing against the totals
     * seen on the previous poll. Called once per poll tick (not per slice —
     * these counters are process-wide, not slice-scoped).
     *
     * Sentinel -1.0 means "no attempts this interval" (consistent with the
     * existing convention elsewhere in this class), which covers both the
     * very first poll after startup (no baseline yet) and any tick where
     * nothing happened.
     */
    private void computeDeltaSuccessRates(JsonNode kpiRaw) {
        if (kpiRaw == null || !kpiRaw.has("counters")) {
            currentRegSuccessRate = -1.0;
            currentAuthSuccessRate = -1.0;
            currentSessionSuccessRate = -1.0;
            return;
        }
        JsonNode counters = kpiRaw.get("counters");

        long regSucc = counters.path("RM.RegSucc").asLong(0);
        long regFail = counters.path("RM.RegFail").asLong(0);
        long authSucc = counters.path("AUTH.Succ").asLong(0);
        long authFail = counters.path("AUTH.Fail").asLong(0);
        long sessSucc = counters.path("SM.SessSucc").asLong(0);
        long sessFail = counters.path("SM.SessFail").asLong(0);

        currentRegSuccessRate = deltaRate(regSucc, regFail, prevRegSucc, prevRegFail);
        currentAuthSuccessRate = deltaRate(authSucc, authFail, prevAuthSucc, prevAuthFail);
        currentSessionSuccessRate = deltaRate(sessSucc, sessFail, prevSessSucc, prevSessFail);

        prevRegSucc = regSucc;
        prevRegFail = regFail;
        prevAuthSucc = authSucc;
        prevAuthFail = authFail;
        prevSessSucc = sessSucc;
        prevSessFail = sessFail;
    }

    /**
     * (successNow - successPrev) / ((successNow - successPrev) + (failNow - failPrev)) * 100,
     * guarding against the first-ever poll (prev == -1, no baseline) and
     * against a counter reset/process restart producing a negative delta
     * (falls back to treating this tick as "no baseline" rather than
     * reporting a nonsensical rate).
     */
    private double deltaRate(long succNow, long failNow, long succPrev, long failPrev) {
        if (succPrev < 0 || failPrev < 0) return -1.0; // no baseline yet
        long dSucc = succNow - succPrev;
        long dFail = failNow - failPrev;
        if (dSucc < 0 || dFail < 0) return -1.0; // counters reset underneath us (e.g. core restart)
        long total = dSucc + dFail;
        if (total == 0) return -1.0; // nothing happened this interval
        return (dSucc * 100.0) / total;
    }

    /**
     * Extracts high-level dashboard metrics, correlating them to the specific target SST.
     */
    private void populateFromKpiDashboard(SliceTelemetrySample sample, JsonNode root, int targetSst) {
        if (root == null) return;

        JsonNode amf = root.path("amf");
        sample.setConnectedUeCount(amf.path("connected_ue").asInt(0));
        sample.setRegisteredUeCount(amf.path("registered_ue").asInt(0));

        JsonNode smf = root.path("smf");
        sample.setActivePduSessions(smf.path("active_pdu_sessions").asInt(0));

        // Count specific sessions allocated solely to this target slice
        JsonNode pduPerSlice = smf.path("pdu_per_slice");
        int sliceSessions = 0;
        if (!pduPerSlice.isMissingNode()) {
            String exactKey = String.valueOf(targetSst);
            // Scenario 1: Exact match found for SST
            if (pduPerSlice.has(exactKey)) {
                sliceSessions = pduPerSlice.get(exactKey).asInt(0);
            } else {
                // Scenario 2: Search for variations using the SST prefix (e.g., "1-xxxxxx")
                String prefix = exactKey + "-";
                pduPerSlice.fieldNames().forEachRemaining(key -> {
                    if (key.startsWith(prefix)) {
                        sample.setSessionsInThisSlice(pduPerSlice.get(key).asInt(0));
                    }
                });
            }
        }
        if (sliceSessions > 0) {
            sample.setSessionsInThisSlice(sliceSessions);
        }

        JsonNode upf = root.path("upf");
        sample.setUlPacketRate(upf.path("ul_pkts").asDouble(0.0));
        sample.setDlPacketRate(upf.path("dl_pkts").asDouble(0.0));
        sample.setUlByteRate(upf.path("ul_bytes").asDouble(0.0));
        sample.setDlByteRate(upf.path("dl_bytes").asDouble(0.0));
        sample.setUlDropped(upf.path("ul_dropped").asLong(0));
        sample.setDlDropped(upf.path("dl_dropped").asLong(0));
        sample.setPacketLossRate(upf.path("packet_loss_rate").asDouble(0.0));
        sample.setGtpuErrors(upf.path("gtpu_errors").asLong(0));
    }

    /**
     * Translates qualitative predictive analytics text into numerical categories.
     */
    private void populateFromNwdafAnalytics(SliceTelemetrySample sample, JsonNode root, int targetSst) {
        if (root == null || !root.has("analytics")) return;

        JsonNode analytics = root.get("analytics");

        // Translate NF Load text ("low", "medium", "high") to integers (0, 1, 2)
        JsonNode nfLoad = analytics.path("NF_LOAD").path("result");
        String loadLevelStr = nfLoad.path("load_level").asText("low");
        sample.setNfLoadLevel(switch (loadLevelStr) {
            case "high" -> 2;
            case "medium" -> 1;
            default -> 0;
        });

        // Translate QoS status to integers
        JsonNode qos = analytics.path("QOS_SUSTAINABILITY").path("result");
        String qosStatusStr = qos.path("qos_status").asText("sustainable");
        sample.setQosStatus(switch (qosStatusStr) {
            case "degraded" -> 2;
            case "at_risk" -> 1;
            default -> 0;
        });

        // Capture exact anomaly counts
        JsonNode abnormal = analytics.path("ABNORMAL_BEHAVIOUR").path("result");
        sample.setAnomalyAlertCount(abnormal.path("alert_count").asInt(0));
    }
}