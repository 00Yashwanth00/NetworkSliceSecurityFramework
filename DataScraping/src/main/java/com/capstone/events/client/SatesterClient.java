package com.capstone.events.client;

import com.capstone.events.config.EventConfig;
import com.capstone.nwdaf.http.HttpUtil;
import org.json.JSONObject;

/**
 * HTTP Client dedicated to communicating with the Satester API.
 * Satester acts as the test orchestrator/traffic generator in the 5G simulator.
 * This class abstracts the raw HTTP calls into easy-to-use Java methods.
 */
public class SatesterClient {

    private final String baseUrl;

    /**
     * Default constructor.
     * Automatically pulls the default Satester URL from the centralized EventConfig.
     */
    public SatesterClient() {
        this(EventConfig.SATESTER_BASE_URL);
    }

    /**
     * Overloaded constructor.
     * Allows injecting a custom URL. This is highly useful for writing unit tests
     * (pointing to a mock server) or if the Satester service moves to a remote server.
     *
     * @param baseUrl The base URL of the Satester API (e.g., http://localhost:5001)
     */
    public SatesterClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * §3.1: Retrieves a paginated list of recent simulation runs.
     *
     * @param limit The maximum number of runs to retrieve in this single HTTP request.
     * @return A parsed JSONObject containing the list of runs and their basic metadata.
     * @throws Exception if the HTTP request fails or the response is invalid JSON.
     */
    public JSONObject getRuns(int limit) throws Exception {
        // Appends the limit query parameter to control the payload size returned by the server
        return new JSONObject(HttpUtil.get(baseUrl + "/api/runs?limit=" + limit));
    }

    /**
     * §3.2: Retrieves detailed metadata for one specific simulation run.
     *
     * @param runId The unique identifier of the run (e.g., "run_12345").
     * @return A parsed JSONObject containing all configuration and status details for the run.
     * @throws Exception if the HTTP request fails or the response is invalid JSON.
     */
    public JSONObject getRun(String runId) throws Exception {
        // Dynamically constructs the path to fetch a specific run resource by its ID
        return new JSONObject(HttpUtil.get(baseUrl + "/api/runs/" + runId));
    }

    /**
     * §3.4: Retrieves the actual output report of a completed run in a specific format.
     *
     * NOTE: Unlike the other methods, this returns a raw String instead of a JSONObject.
     * This is intentional because the requested format might not be JSON (e.g., it could be CSV).
     * Attempting to parse a CSV string into a JSONObject would cause a crash.
     *
     * @param runId The unique identifier of the run.
     * @param fmt The desired format of the report (e.g., "json", "csv").
     * @return The raw string payload of the downloaded report.
     * @throws Exception if the HTTP request fails.
     */
    public String getRunReportRaw(String runId, String fmt) throws Exception {
        // Constructs the path requesting a specific format extension for the report
        return HttpUtil.get(baseUrl + "/api/runs/" + runId + "/report/" + fmt);
    }
}