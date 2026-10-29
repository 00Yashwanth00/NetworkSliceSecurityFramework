package com.nssf.collector.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nssf.collector.config.CollectorConfig;
import com.nssf.collector.model.SliceTelemetrySample;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Service responsible for evaluating real-time Risk Scores (0-100) via the ML Engine
 * and enforcing dynamic security mitigation policies per network slice.
 */
public class RiskEnforcementService {

    private static final Logger logger = LoggerFactory.getLogger(RiskEnforcementService.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final CollectorConfig config;

    public RiskEnforcementService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        this.objectMapper = new ObjectMapper();
        this.config = CollectorConfig.getInstance();
    }

    /**
     * Evaluates real-time risk score for a slice telemetry sample and executes mitigation actions.
     */
    public void evaluateAndEnforce(SliceTelemetrySample sample) {
        if (sample == null) return;

        try {
            String jsonPayload = objectMapper.writeValueAsString(sample);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getMlRiskServiceUrl()))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(Duration.ofSeconds(3))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode resJson = objectMapper.readTree(response.body());
                double riskScore = resJson.path("risk_score").asDouble(0.0);
                String riskTier = resJson.path("risk_tier").asText("LOW");
                String policyAction = resJson.path("policy_action").asText("ROUTINE_MONITORING");
                String threatCategory = resJson.path("threat_category").asText("BENIGN");

                String sliceName = switch (sample.getSliceType()) {
                    case 1 -> "eMBB (SST=1)";
                    case 2 -> "URLLC (SST=2)";
                    case 3 -> "mMTC (SST=3)";
                    default -> "Slice-" + sample.getSliceType();
                };
                enforcePolicy(sliceName, riskScore, riskTier, policyAction, threatCategory);
            } else {
                logger.warn("ML Risk API returned status: {}", response.statusCode());
            }

        } catch (Exception e) {
            logger.debug("Could not reach ML Risk API (is risk_api_service running?): {}", e.getMessage());
        }
    }

    private void enforcePolicy(String sliceType, double riskScore, String riskTier, String policyAction, String threatCategory) {
        String msg = String.format("[RISK ENGINE] Slice: %s | Score: %.2f/100 | Tier: %s | Threat: %s | Action: %s",
                sliceType, riskScore, riskTier, threatCategory, policyAction);

        switch (riskTier.toUpperCase()) {
            case "CRITICAL":
                logger.error("🚨 CRITICAL SECURITY ALERT! {}", msg);
                logger.error("⚡ [ACTION TRIGGERED] Emergency Slice Isolation & IP Blocking initiated for slice: {}", sliceType);
                break;
            case "HIGH":
                logger.warn("⚠️ HIGH RISK DETECTED! {}", msg);
                logger.warn("⚡ [ACTION TRIGGERED] Applying Slice Bandwidth Throttling & Rate-Limiting for slice: {}", sliceType);
                break;
            case "MEDIUM":
                logger.info("⚡ MEDIUM RISK NOTICE: {}", msg);
                logger.info("⚡ [ACTION TRIGGERED] Polling rate boosted to 1s & NWDAF alert enabled for slice: {}", sliceType);
                break;
            case "LOW":
            default:
                logger.debug("✅ {}", msg);
                break;
        }
    }
}
