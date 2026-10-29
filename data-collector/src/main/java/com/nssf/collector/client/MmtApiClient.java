package com.nssf.collector.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nssf.collector.config.CollectorConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Client responsible for making HTTP GET requests to the external MMT Core API.
 */
public class MmtApiClient {

    private static final Logger logger = LoggerFactory.getLogger(MmtApiClient.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl;

    public MmtApiClient() {
        // Initialize an HTTP client with a strict 5-second connection timeout and force HTTP/1.1
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        // Jackson object mapper to convert raw JSON strings into JsonNode trees
        this.objectMapper = new ObjectMapper();
        // Fetch the base API URL from the central configuration singleton
        this.baseUrl = CollectorConfig.getInstance().getCoreBaseUrl();
    }

    /**
     * Fetches raw KPI metrics for a specified time window.
     */
    public JsonNode fetchKpiRaw(int windowSec) {
        String url = String.format("%s/api/kpis/raw?window_sec=%d", baseUrl, windowSec);
        return fetchJson(url);
    }

    /**
     * Fetches high-level KPI dashboard metrics.
     */
    public JsonNode fetchKpiDashboard() {
        String url = String.format("%s/api/kpis", baseUrl);
        return fetchJson(url);
    }

    /**
     * Fetches Network Data Analytics Function (NWDAF) predictions and metrics.
     */
    public JsonNode fetchNwdafAnalytics(int windowSec) {
        String url = String.format("%s/api/nwdaf/analytics?window_sec=%d", baseUrl, windowSec);
        return fetchJson(url);
    }

    /**
     * Core helper method that executes the HTTP GET request and parses the JSON response.
     *
     * @param url The full endpoint URL to call
     * @return A parsed JsonNode if successful, or null if an error/failure occurred
     */
    private JsonNode fetchJson(String url) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5)) // Prevents thread hanging on slow servers
                .GET()
                .build();

        long startTime = System.currentTimeMillis();
        try {
            // Send request synchronously and read the response body as a String
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            long latency = System.currentTimeMillis() - startTime;

            // Check for HTTP Success (200-299)
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                logger.debug("Successfully fetched {} ({} ms)", url, latency);
                // Convert the raw JSON string into a structured JsonNode tree
                return objectMapper.readTree(response.body());
            } else {
                // Log non-success responses (e.g., 404, 500)
                logger.error("Failed to fetch {}. Status: {}, Body: {}", url, response.statusCode(), response.body());
                return null;
            }
        } catch (IOException | InterruptedException e) {
            long latency = System.currentTimeMillis() - startTime;
            logger.error("Exception fetching {} after {} ms: {}", url, latency, e.getMessage());
            // Best practice: Restore interrupted state if an InterruptedException was caught
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }
}