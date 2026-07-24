package com.capstone.events.model;

import org.json.JSONObject;

/**
 * §6.3 — Data model representing a single log event scraped from the 5G Core.
 * In a Machine Learning context, these events form the raw "features" that
 * corroborate network behavior during a specific test run.
 */
public class CoreLogEvent {

    // All fields are declared 'final' to make the object immutable,
    // ensuring thread safety and preventing data corruption in the pipeline.

    public final long seq;       // Sequence number used for cursor-based pagination
    public final double ts;      // Unix timestamp of when the event occurred in the core
    public final String level;   // Log severity (e.g., "info", "debug", "error")
    public final String module;  // The network function/module (e.g., "amf.gmm.registration")
    public final String message; // The raw description of the event
    public final String imsi;    // The unique subscriber ID (phone) involved, if applicable

    /**
     * Constructor to initialize all fields of the CoreLogEvent.
     */
    public CoreLogEvent(long seq, double ts, String level, String module, String message, String imsi) {
        this.seq = seq;
        this.ts = ts;
        this.level = level;
        this.module = module;
        this.message = message;
        this.imsi = imsi;
    }

    /**
     * Serializes this Java object into a JSON format.
     * This prepares the event to be appended to the core_log_events.jsonl output file.
     *
     * @return A formatted JSONObject representing this specific log event.
     */
    public JSONObject toJson() {
        JSONObject o = new JSONObject();

        // Map the Java variables to standard JSON keys
        o.put("seq", seq);
        o.put("ts", ts);
        o.put("level", level);
        o.put("module", module);
        o.put("message", message);
        o.put("imsi", imsi);

        return o;
    }
}