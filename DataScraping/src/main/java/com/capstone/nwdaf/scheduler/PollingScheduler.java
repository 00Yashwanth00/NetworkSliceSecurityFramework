package com.capstone.nwdaf.scheduler;

import com.capstone.nwdaf.client.McoreClient;
import com.capstone.nwdaf.client.NwdafClient;
import com.capstone.nwdaf.config.AppConfig;
import com.capstone.nwdaf.transform.DataReshaper;
import org.json.JSONObject;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class PollingScheduler {

    private static final Logger log = Logger.getLogger(PollingScheduler.class.getName());

    private static final String[] ALL_ANALYTICS_IDS = {
            "NF_LOAD", "UE_MOBILITY", "UE_COMMUNICATION", "QOS_SUSTAINABILITY",
            "ABNORMAL_BEHAVIOUR", "PDU_SESSION", "SLICE_LOAD"
    };

    private final McoreClient mcoreClient = new McoreClient();
    private final NwdafClient nwdafClient = new NwdafClient();
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private int cycleCount = 0;

    public void start() {
        executor.scheduleAtFixedRate(this::pollCycle, 0, AppConfig.POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    public void stop() {
        executor.shutdownNow();
    }

    private void pollCycle() {
        cycleCount++;
        long nowEpochSec = System.currentTimeMillis() / 1000L;

        try {
            JSONObject benchmark = mcoreClient.getBenchmarkResults();
            Object sliceStats = mcoreClient.getSliceStats();
            JSONObject ioStats = mcoreClient.getIoStats();
            Object ueStats = mcoreClient.getUeStats();

            push("AMF", "NF_LOAD", DataReshaper.buildNfLoad(benchmark), nowEpochSec);
            push("AMF", "ABNORMAL_BEHAVIOUR", DataReshaper.buildAbnormalBehaviour(benchmark), nowEpochSec);
            push("AMF", "UE_MOBILITY", DataReshaper.buildUeMobility(ueStats), nowEpochSec);
            push("SMF", "UE_COMMUNICATION", DataReshaper.buildPduSession(ueStats), nowEpochSec);
            push("SMF", "PDU_SESSION", DataReshaper.buildPduSession(ueStats), nowEpochSec);
            push("UPF", "QOS_SUSTAINABILITY", DataReshaper.buildQosSustainability(ioStats, AppConfig.UL_IS_TX), nowEpochSec);
            push("SMF", "SLICE_LOAD", DataReshaper.buildSliceLoad(sliceStats), nowEpochSec);

            log.info("Cycle " + cycleCount + ": polled 4 endpoints, pushed 7 analytics IDs.");
        } catch (Exception e) {
            log.severe("Poll cycle " + cycleCount + " failed while fetching from mmt-studio: " + e.getMessage());
        }

        if (cycleCount % AppConfig.READBACK_EVERY_N_CYCLES == 0) {
            readBackAndVerify();
        }
    }

    private void push(String sourceNf, String analyticsId, String dataJson, long timestamp) {
        try {
            JSONObject response = nwdafClient.pushDataPoint(sourceNf, analyticsId, "", "", dataJson, timestamp);
            if (!response.optBoolean("ok", false)) {
                log.warning("Push " + analyticsId + " returned a non-ok response: " + response);
            }
        } catch (Exception e) {
            log.warning("Push " + analyticsId + " failed: " + e.getMessage());
        }
    }

    private void readBackAndVerify() {
        try {
            JSONObject status = nwdafClient.getStatus();
            log.info("NWDAF status (ingest counts should be increasing): " + status);
        } catch (Exception e) {
            log.warning("Failed to fetch /api/nwdaf/status: " + e.getMessage());
        }

        for (String analyticsId : ALL_ANALYTICS_IDS) {
            try {
                JSONObject result = nwdafClient.getAnalytics(analyticsId, AppConfig.ANALYTICS_WINDOW_SEC);
                log.info(analyticsId + " => " + result);
            } catch (Exception e) {
                log.warning("Failed to read analytics for " + analyticsId + ": " + e.getMessage());
            }
        }
    }
}