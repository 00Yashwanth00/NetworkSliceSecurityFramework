package com.capstone.events.scheduler;

import com.capstone.events.client.CoreLogClient;
import com.capstone.events.config.EventConfig;
import com.capstone.events.model.CoreLogEvent;
import com.capstone.events.store.LabelStore;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * §4.1/§6.3 — The background worker responsible for continuously scraping
 * the 5G core network log stream.
 *
 * It uses cursor-based pagination to safely pull batches of logs without duplicates.
 * Filtering is performed client-side against a predefined allowlist because the
 * upstream API does not support multi-module filtering.
 */
public class CoreLogPoller {

    private static final Logger log = Logger.getLogger(CoreLogPoller.class.getName());

    // A highly optimized lookup set containing the specific network functions
    // (e.g., AMF, SMF, UPF) that we actually care about for Machine Learning.
    private static final Set<String> MODULE_ALLOWLIST =
            new HashSet<>(Arrays.asList(EventConfig.LOG_MODULE_ALLOWLIST));

    private final CoreLogClient coreLogClient;
    private final LabelStore store;

    // The cursor tracking the highest Sequence ID processed so far.
    // Starts at 0 to fetch from the very beginning of the simulator's lifetime.
    private long lastSeenSeq = 0;

    public CoreLogPoller(CoreLogClient coreLogClient, LabelStore store) {
        this.coreLogClient = coreLogClient;
        this.store = store;
    }

    /**
     * Executes a single polling cycle to fetch, filter, and store new network logs.
     */
    public void pollOnce() {
        JSONArray entries;
        try {
            // Fetch a batch of logs starting immediately after the last seen sequence
            JSONObject response = coreLogClient.getLogEntries(lastSeenSeq, EventConfig.LOG_POLL_LIMIT);
            entries = response.optJSONArray("entries");
        } catch (Exception e) {
            log.warning("Failed to poll GET /api/logger/entries: " + e.getMessage());
            return; // Exit cleanly on network failure; retry on the next scheduled cycle
        }

        // If the array is null or empty, no new events have occurred. Exit early.
        if (entries == null || entries.isEmpty()) return;

        int matched = 0; // Tracks how many logs actually passed our filter

        // Iterate through the fetched log entries
        for (int i = 0; i < entries.length(); i++) {
            JSONObject entry = entries.optJSONObject(i);
            if (entry == null) continue;

            // Extract the sequence ID of the current log
            long seq = entry.optLong("seq", -1);

            // CRITICAL STEP: Always advance the cursor if the sequence is higher.
            // This MUST happen before the filter check, otherwise the poller
            // will get permanently stuck on a block of filtered-out logs.
            if (seq > lastSeenSeq) lastSeenSeq = seq;

            // Extract the module name (e.g., "amf.gmm.registration")
            String module = entry.optString("module", "");

            // Client-side filtering: Ignore background noise that isn't in our allowlist
            if (!MODULE_ALLOWLIST.contains(module)) continue;

            // The log is relevant. Map the raw JSON into our structured Data Model.
            CoreLogEvent event = new CoreLogEvent(
                    seq,
                    entry.optDouble("ts", 0.0),
                    entry.optString("level", ""),
                    module,
                    entry.optString("message", ""),
                    entry.optString("imsi", "")
            );

            // Persist the relevant event to disk via the LabelStore
            store.addLogEvent(event);
            matched++;
        }

        // Only log to the console if we actually found something useful, keeping output clean
        if (matched > 0) {
            log.info(matched + " core log event(s) matched the module allowlist and were stored.");
        }
    }
}