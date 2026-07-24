package com.capstone.events.client;

import com.capstone.events.config.EventConfig;
import com.capstone.nwdaf.http.HttpUtil;
import org.json.JSONObject;

/**
 * HTTP Client dedicated to communicating with the SACore API.
 * The SACore represents the actual 5G network simulator. This class is used
 * to continuously scrape internal network logs (like AMF and SMF events).
 */
public class CoreLogClient {

    private final String baseUrl;

    /**
     * Default constructor.
     * Automatically pulls the default SACore URL (e.g., http://localhost:5000)
     * from the centralized EventConfig.
     */
    public CoreLogClient() {
        this(EventConfig.SACORE_BASE_URL);
    }

    /**
     * Overloaded constructor.
     * Allows injecting a custom URL for testing or remote deployments.
     *
     * @param baseUrl The base URL of the SACore API.
     */
    public CoreLogClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * §4.1 — Retrieves a batch of network logs using cursor-based pagination.
     *
     * Cursor-based pagination is used to safely continuously poll for logs.
     * By providing the highest sequence number we have already seen, the server
     * only sends newly generated logs, preventing duplicate data.
     *
     * @param afterSeq The sequence number of the last log successfully processed.
     *                 Pass 0 to start fetching from the very beginning.
     * @param limit    The maximum number of log entries to retrieve in this request
     *                 (prevents out-of-memory errors on massive log bursts).
     * @return A parsed JSONObject containing the batch of new log entries.
     * @throws Exception if the HTTP request fails or the response is invalid JSON.
     */
    public JSONObject getLogEntries(long afterSeq, int limit) throws Exception {
        // Construct the URL.
        // Note: level, imsi, and module are left intentionally blank to bypass
        // server-side filtering, ensuring we pull the raw firehose of logs.
        String url = baseUrl + "/api/logger/entries?after_seq=" + afterSeq + "&level=&imsi=&module=&limit=" + limit;

        return new JSONObject((HttpUtil.get(url)));
    }
}