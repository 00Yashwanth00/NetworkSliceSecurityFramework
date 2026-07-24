package com.capstone.events.model;

import org.json.JSONObject;

/**
 * §6.2 — Data model representing a single test run result.
 * This class acts as the "Ground Truth" label for the Machine Learning pipeline.
 * It holds the metadata and final outcome of a specific test executed by the Satester.
 */
public class TestRunLabel {

    // All fields are declared 'final' to make the object immutable.
    // Once instantiated, this data cannot be modified, preventing accidental corruption.
    public final String runId;       // Unique ID for this specific test execution
    public final String testName;    // Human-readable name of the test
    public final String tcId;        // Test Case Identifier mapping to the test requirements
    public final String suite;       // The test suite this run belongs to (e.g., "Load Tests")
    public final String category;    // The category of the test (e.g., "eMBB", "URLLC")
    public final String status;      // Final outcome (e.g., "completed", "failed", "error")
    public final double startedAt;   // Unix timestamp (with milliseconds) when the test began
    public final double completedAt; // Unix timestamp (with milliseconds) when the test finished
    public final long durationMs;    // Total execution time in milliseconds
    public final String error;       // Error message if the test failed, or null if successful

    /**
     * Constructor to initialize all fields of the TestRunLabel.
     */
    public TestRunLabel(String runId, String testName, String tcId, String suite, String category,
                        String status, double startedAt, double completedAt, long durationMs, String error) {
        this.runId = runId;
        this.testName = testName;
        this.tcId = tcId;
        this.suite = suite;
        this.category = category;
        this.status = status;
        this.startedAt = startedAt;
        this.completedAt = completedAt;
        this.durationMs = durationMs;
        this.error = error;
    }

    /**
     * Serializes this Java object into a JSON format.
     * This is used before writing the label to the run_labels.jsonl output file.
     *
     * @return A formatted JSONObject representing this test run.
     */
    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        o.put("run_id", runId);
        o.put("test_name", testName);
        o.put("tc_id", tcId);
        o.put("suite", suite);
        o.put("category", category);
        o.put("status", status);
        o.put("started_at", startedAt);
        o.put("completed_at", completedAt);
        o.put("duration_ms", durationMs);

        // Defensive null handling: If there is no error, explicitly insert a JSON 'null'
        // value rather than dropping the key entirely or throwing a NullPointerException.
        o.put("error", error == null ? JSONObject.NULL : error);

        return o;
    }
}