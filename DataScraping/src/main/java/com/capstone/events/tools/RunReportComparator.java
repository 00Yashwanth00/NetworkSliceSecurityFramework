package com.capstone.events.tools;

import com.capstone.events.client.SatesterClient;
import org.json.JSONObject;

/**
 * Diagnostic tool to compare the payload shapes of two Satester API endpoints:
 * GET /api/runs/{id} versus GET /api/runs/{id}/report/json.
 *
 * Used by developers to determine if the report endpoint contains extra,
 * valuable ML features that the standard run endpoint omits.
 */
public class RunReportComparator {

    public static void main(String[] args) throws Exception {
        // 1. Input Validation
        // Ensures the user passed a run_id via the command line arguments.
        if (args.length < 1) {
            System.out.println("Usage: RunReportComparator <run_id>");
            return;
        }
        String runId = args[0];

        // Initialize the HTTP client
        SatesterClient client = new SatesterClient();

        // 2. Fetch and print the standard run metadata
        JSONObject plainRun = client.getRun(runId);
        System.out.println("=== GET /api/runs/" + runId + " ===");
        System.out.println(plainRun.toString(2)); // '2' adds pretty-printing indentation

        // 3. Fetch and print the detailed run report
        String reportRaw = client.getRunReportRaw(runId, "json");
        System.out.println("\n=== GET /api/runs/" + runId + "/report/json ===");
        System.out.println(reportRaw);

        // Parse the raw report string into a JSON Object for programmatic comparison
        JSONObject report = new JSONObject(reportRaw);

        System.out.println("\nKeys only in report/json, not in plain run response:");

        // 4. The Diffing Logic
        // Loop through every top-level key in the report JSON
        for (String key : report.keySet()) {
            // If the basic 'plainRun' object does NOT have this key, print it out.
            // This highlights the exact data fields unique to the report endpoint.
            if (!plainRun.has(key)) {
                System.out.println("  " + key);
            }
        }
    }
}