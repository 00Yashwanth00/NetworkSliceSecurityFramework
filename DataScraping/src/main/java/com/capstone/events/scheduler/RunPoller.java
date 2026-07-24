package com.capstone.events.scheduler;

import com.capstone.events.client.SatesterClient;
import com.capstone.events.config.EventConfig;
import com.capstone.events.model.TestRunLabel;
import com.capstone.events.store.LabelStore;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * §3.1/§3.2/§6.1-2 — The background worker responsible for detecting and processing test runs.
 * It continuously polls the Satester API, detects when tests finish, fetches their details,
 * and converts them into TestRunLabel objects for Machine Learning.
 */
public class RunPoller {

    private static final Logger log = Logger.getLogger(RunPoller.class.getName());

    // A quick-lookup set of statuses that indicate a test is completely finished
    // (e.g., "completed", "failed", "error", "cancelled")[cite: 1].
    private static final Set<String> TERMINAL_STATUSES =
            new HashSet<>(Arrays.asList(EventConfig.TERMINAL_RUN_STATUSES));

    private final SatesterClient satesterClient;
    private final LabelStore store;

    /**
     * Tracks runs that the API has returned, but are still running/pending.
     * Prevents the poller from constantly logging "new run found" for tests it already knows about.
     */
    private final Set<String> knownRunIds = new HashSet<>();

    /**
     * Tracks runs that have been fully processed, labeled, and saved to disk.
     * Ensures we never duplicate labels in our final dataset.
     */
    private final Set<String> processedRunIds = new HashSet<>();

    public RunPoller(SatesterClient satesterClient, LabelStore store) {
        this.satesterClient = satesterClient;
        this.store = store;
    }

    /**
     * Executes a single polling cycle to check for finished test runs.
     */
    public void pollOnce() {
        JSONArray items;
        try {
            // Fetch the most recent batch of test runs from the orchestrator
            JSONObject response = satesterClient.getRuns(EventConfig.RUN_POLL_LIMIT);
            items = response.optJSONArray("items");
        } catch (Exception e) {
            log.warning("Failed to poll GET /api/runs: " + e.getMessage());
            return; // Exit the cycle cleanly without crashing the JVM
        }
        if (items == null) return;

        // Iterate through the fetched runs
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.optJSONObject(i);
            if (item == null) continue;

            String runId = item.optString("id", null);
            if (runId == null) continue;

            knownRunIds.add(runId);

            // If this run is already saved to disk, skip it entirely
            if (processedRunIds.contains(runId)) continue;

            String status = item.optString("status", "");

            // If the test is not in a terminal state (it is still running), skip it.
            // We will check it again on the next polling cycle.
            if (!TERMINAL_STATUSES.contains(status)) {
                continue;
            }

            // The test is finished; proceed to fetch details and label it.
            processRun(runId);
        }
    }

    /**
     * Fetches the full details of a finished run, parses the results, and saves them.
     */
    private void processRun(String runId) {
        try {
            // Fetch the deep metadata for this specific test
            JSONObject run = satesterClient.getRun(runId);
            double startedAt = run.optDouble("started_at", 0.0);
            double completedAt = run.optDouble("completed_at", 0.0);

            // A single run can execute multiple tests, so we iterate through the results
            JSONArray results = run.optJSONArray("results");
            if (results == null || results.isEmpty()) {
                log.warning("Run " + runId + " has no results array; nothing to label.");
            } else {
                for (int i = 0; i < results.length(); i++) {
                    JSONObject result = results.optJSONObject(i);
                    if (result == null) continue;

                    // Build the ML Label object
                    TestRunLabel label = new TestRunLabel(
                            runId,
                            result.optString("test_name", ""),
                            result.optString("tc_id", ""),
                            result.optString("suite", ""),
                            result.optString("category", ""),
                            result.optString("status", ""),
                            startedAt,
                            completedAt,
                            result.optLong("duration_ms", 0),
                            result.isNull("error") ? null : result.optString("error", null)
                    );

                    // Push the label to the central warehouse to be saved to disk
                    store.addRunLabel(label);
                }
                log.info("Run " + runId + " (" + results.length() + " result(s)) labeled and stored.");
            }

            // Mark the run as processed ONLY if everything succeeded.
            // If the code crashes before this line, it will be safely retried next cycle.
            processedRunIds.add(runId);
        } catch (Exception e) {
            log.warning("Failed to fetch/process run " + runId + ": " + e.getMessage());
        }
    }
}