package com.nssf.collector.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * A Singleton class responsible for managing application configuration.
 * It loads properties from an application.properties file and provides
 * fallback mechanisms using System properties.
 */
public class CollectorConfig {

    // Eagerly instantiated Singleton instance
    private static final CollectorConfig INSTANCE = new CollectorConfig();
    private final Properties properties;

    /**
     * Private constructor to prevent external instantiation.
     * Loads the 'application.properties' file from the classpath on startup.
     */
    private CollectorConfig() {
        properties = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("application.properties")) {
            if (input == null) {
                System.err.println("Sorry, unable to find application.properties");
                return;
            }
            properties.load(input); // Parse the file stream into key-value pairs
        } catch (IOException ex) {
            // Crash the application if critical configs cannot be read
            throw new RuntimeException("Failed to load configuration", ex);
        }
    }

    /**
     * @return The single, global instance of the configuration manager.
     */
    public static CollectorConfig getInstance() {
        return INSTANCE;
    }

    // --- Configuration Getters ---
    // All getters follow a 3-tier fallback strategy:
    // 1. System Property (-D flag) -> 2. Properties File -> 3. Hardcoded Default

    public String getCoreBaseUrl() {
        return System.getProperty("mmt.core.baseUrl", properties.getProperty("mmt.core.baseUrl", "http://localhost:5000"));
    }

    public int getIntervalSeconds() {
        return Integer.parseInt(System.getProperty("collector.intervalSeconds", properties.getProperty("collector.intervalSeconds", "5")));
    }

    public String getOutputDir() {
        return System.getProperty("collector.outputDir", properties.getProperty("collector.outputDir", "./collected-data"));
    }

    public String getSessionLabel() {
        return System.getProperty("collector.sessionLabel", properties.getProperty("collector.sessionLabel", "normal"));
    }

    public int getKpiRawWindowSec() {
        return Integer.parseInt(System.getProperty("collector.kpiRawWindowSec", properties.getProperty("collector.kpiRawWindowSec", "5")));
    }

    public int getNwdafWindowSec() {
        return Integer.parseInt(System.getProperty("collector.nwdafWindowSec", properties.getProperty("collector.nwdafWindowSec", "300")));
    }

    public String getMlRiskServiceUrl() {
        return System.getProperty("ml.riskServiceUrl", properties.getProperty("ml.riskServiceUrl", "http://localhost:5002/api/v1/evaluate-risk"));
    }

    public String getRedisHost() {
        return System.getProperty("redis.host", properties.getProperty("redis.host", "localhost"));
    }

    public int getRedisPort() {
        return Integer.parseInt(System.getProperty("redis.port", properties.getProperty("redis.port", "6379")));
    }

    public String getRedisStream() {
        return System.getProperty("redis.stream", properties.getProperty("redis.stream", "telemetry.network"));
    }

    public boolean isRedisEnabled() {
        return Boolean.parseBoolean(System.getProperty("redis.enabled", properties.getProperty("redis.enabled", "true")));
    }
}