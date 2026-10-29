package com.nssf.collector;

import com.nssf.collector.config.CollectorConfig;
import com.nssf.collector.service.DataCollectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Main application runner for the Telemetry Collector.
 */
public class App {

    private static final Logger logger = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        // Initialize configurations
        CollectorConfig config = CollectorConfig.getInstance();

        logger.info("==================================================");
        logger.info("  NSSF 5G Slice Telemetry Data Collector Started  ");
        logger.info("==================================================");
        logger.info("Core URL     : {}", config.getCoreBaseUrl());
        logger.info("Interval     : {} seconds", config.getIntervalSeconds());
        logger.info("Session Label: {}", config.getSessionLabel());
        logger.info("Output Dir   : {}", config.getOutputDir());
        logger.info("==================================================");

        DataCollectionService collectionService = new DataCollectionService();

        // Create a single-threaded scheduler to handle periodic data polling
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

        // Define the task wrapper capturing uncaught exceptions to prevent silent thread crashes
        Runnable task = () -> {
            try {
                collectionService.collectAndWrite();
            } catch (Exception e) {
                logger.error("Unhandled exception during collection tick", e);
            }
        };

        // Schedule the task to run repeatedly at a fixed rate using the configured interval
        scheduler.scheduleAtFixedRate(task, 0, config.getIntervalSeconds(), TimeUnit.SECONDS);

        // Register a JVM shutdown hook (triggered by Ctrl+C or SIGTERM)
        // Ensures threads stop cleanly and data writers can flush buffers
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown signal received. Stopping collection...");
            scheduler.shutdown();
            collectionService.shutdown();
            try {
                // Wait up to 5 seconds for current tasks to finish
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow(); // Force kill if they take too long
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt(); // Restore interrupt flag
            }
            logger.info("Collector stopped.");
        }));
    }
}