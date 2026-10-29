package com.nssf.collector.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.nssf.collector.client.MmtApiClient;
import com.nssf.collector.config.CollectorConfig;
import com.nssf.collector.model.SliceTelemetrySample;
import com.nssf.collector.publisher.RedisPublisher;
import com.nssf.collector.writer.CsvWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Orchestrator service responsible for running collection cycles.
 * It manages fetching data from APIs concurrently, parsing the results, and saving them.
 */
public class DataCollectionService {

    private static final Logger logger = LoggerFactory.getLogger(DataCollectionService.class);

    private final MmtApiClient apiClient;
    private final FeatureExtractor featureExtractor;
    private final CsvWriter csvWriter;
    private final RedisPublisher redisPublisher;
    private final RiskEnforcementService riskEnforcementService;
    private final CollectorConfig config;
    private final ExecutorService fetchExecutor;

    public DataCollectionService() {
        this.apiClient = new MmtApiClient();
        this.featureExtractor = new FeatureExtractor();
        this.csvWriter = new CsvWriter();
        this.redisPublisher = new RedisPublisher();
        this.riskEnforcementService = new RiskEnforcementService();
        this.config = CollectorConfig.getInstance();
        // Fixed thread pool to allow exactly 3 API calls to happen simultaneously
        this.fetchExecutor = Executors.newFixedThreadPool(3);
    }

    /**
     * Executes a single "tick" or cycle of data collection.
     */
    public void collectAndWrite() {
        logger.debug("Starting collection tick...");
        long startTick = System.currentTimeMillis();

        // PHASE 1: Dispatch concurrent asynchronous tasks to fetch data from all 4 endpoints

        CompletableFuture<JsonNode> kpiRawFuture = CompletableFuture.supplyAsync(
                () -> apiClient.fetchKpiRaw(config.getKpiRawWindowSec()), fetchExecutor);

        CompletableFuture<JsonNode> kpiDashboardFuture = CompletableFuture.supplyAsync(
                apiClient::fetchKpiDashboard, fetchExecutor);

        CompletableFuture<JsonNode> nwdafFuture = CompletableFuture.supplyAsync(
                () -> apiClient.fetchNwdafAnalytics(config.getNwdafWindowSec()), fetchExecutor);

        // PHASE 2: Wait for all asynchronous tasks to complete
        // The join() method blocks the main thread until all 3 requests are fully processed
        CompletableFuture.allOf(kpiRawFuture, kpiDashboardFuture, nwdafFuture).join();

        // Retrieve the payload results from the futures
        JsonNode kpiRaw = kpiRawFuture.join();
        JsonNode kpiDashboard = kpiDashboardFuture.join();
        JsonNode nwdaf = nwdafFuture.join();

        // Abort the tick if critical systems are non-responsive
        if (kpiDashboard == null && kpiRaw == null) {
            logger.warn("Primary API endpoints failed to respond. Emitting downtime record.");
            SliceTelemetrySample downtimeSample = new SliceTelemetrySample();
            downtimeSample.setTimestamp(System.currentTimeMillis());
            downtimeSample.setSliceType(0); // 0 indicates system-wide downtime
            downtimeSample.setSessionLabel(config.getSessionLabel());
            downtimeSample.setServiceUp(0);
            csvWriter.writeSamples(List.of(downtimeSample));
            redisPublisher.publish(downtimeSample);
            return;
        }

        // PHASE 3: Extract structured features from raw JSON payloads (handled per network slice)
        List<SliceTelemetrySample> samples = featureExtractor.extractFeatures(kpiRaw, kpiDashboard, nwdaf);

        // PHASE 4: Write structured data out to disk
        csvWriter.writeSamples(samples);
        for (SliceTelemetrySample sample : samples) {
            redisPublisher.publish(sample);
        }

        // Calculate and log total execution time for the cycle
        long latency = System.currentTimeMillis() - startTick;
        logger.info("Tick complete. Extracted and wrote {} samples in {} ms", samples.size(), latency);
    }

    /**
     * Gracefully stops the internal thread pool to allow the app to shut down.
     */
    public void shutdown() {
        fetchExecutor.shutdown();
        redisPublisher.shutdown();
    }
}