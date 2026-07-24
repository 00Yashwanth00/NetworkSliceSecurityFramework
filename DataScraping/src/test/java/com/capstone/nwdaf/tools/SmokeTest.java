package com.capstone.nwdaf.tools;

import com.capstone.nwdaf.client.NwdafClient;
import com.capstone.nwdaf.config.AppConfig;
import com.capstone.nwdaf.scheduler.PollingScheduler;
import org.json.JSONObject;

/**
 * Stage 3 — run the real poller against a live, IDLE mmt-studio (no UE activity) for
 * a few cycles. Proves plumbing works with zero real signal to worry about.
 */
public class SmokeTest {

    private static final int CYCLES_TO_RUN = 3;

    public static void main(String[] args) throws Exception {
        NwdafClient nwdafClient = new NwdafClient();

        long totalBefore = ingestTotal(nwdafClient);
        System.out.println("ingest.total before: " + totalBefore);

        PollingScheduler scheduler = new PollingScheduler();
        scheduler.start();
        long waitMs = (long) (CYCLES_TO_RUN + 1) * AppConfig.POLL_INTERVAL_SECONDS * 1000L;
        System.out.println("Running poller for ~" + (waitMs / 1000) + "s (" + CYCLES_TO_RUN + " cycles)...");
        Thread.sleep(waitMs);
        scheduler.stop();

        long totalAfter = ingestTotal(nwdafClient);
        System.out.println("ingest.total after:  " + totalAfter);
        System.out.println(totalAfter > totalBefore
                ? "[PASS] ingest.total increased."
                : "[FAIL] ingest.total did not increase.");

        System.out.println("\n=== GET /api/nwdaf/recent?analytics_id=NF_LOAD&limit=5 ===");
        System.out.println(nwdafClient.getRecent("NF_LOAD", 5).toString(2));
        System.out.println("Values above should be sane (likely all-zero since idle), not null/error.");
    }

    private static long ingestTotal(NwdafClient client) throws Exception {
        return client.getStatus().optJSONObject("ingest", new JSONObject()).optLong("total", 0);
    }
}