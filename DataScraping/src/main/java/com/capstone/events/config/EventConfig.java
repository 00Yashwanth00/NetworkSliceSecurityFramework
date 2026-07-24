package com.capstone.events.config;

/**
 * Centralized configuration for the event-scraping module (Phase B).
 * Stores constants for API endpoints, polling behaviors, and file paths.
 */
public class EventConfig {

    // Private constructor prevents accidental instantiation of this utility class
    private EventConfig() {}

    // ==========================================
    // API Endpoints
    // ==========================================

    // Satester acts as the test orchestrator and traffic generator
    public static final String SATESTER_BASE_URL = "http://localhost:5001";
    // SACore represents the actual 5G core network simulator API
    public static final String SACORE_BASE_URL = "http://localhost:5000";


    // ==========================================
    // Polling Behavior Configuration
    // ==========================================

    // How often to poll the Satester API for new simulation runs (in seconds)
    public static final int RUN_POLL_INTERVAL_SECONDS = 5;
    // Maximum number of runs to fetch in a single API request to prevent server overload
    public static final int RUN_POLL_LIMIT = 500;

    // How often to poll the SACore for new network logs (in seconds)
    public static final int LOG_POLL_INTERVAL_SECONDS = 5;
    // Maximum number of logs to fetch in a single API request
    public static final int LOG_POLL_LIMIT = 500;


    // ==========================================
    // State and Filtering Definitions
    // ==========================================

    // Defines the final states of a test run. If a run reaches one of these statuses,
    // it means the execution is completely finished and no new data will be generated for it.
    public static final String[] TERMINAL_RUN_STATUSES = {"completed", "failed", "error", "cancelled"};

    // A whitelist filter for 5G core logs.
    // The 5G core generates massive amounts of background noise. This array ensures we only
    // keep critical lifecycle events (registration, session management, UPF reporting, etc.)
    public static final String[] LOG_MODULE_ALLOWLIST = {
            "amf.gmm.registration", "amf.gmm.authentication", "amf.gmm.smc", "amf.gmm.dereg",
            "amf.gmm.service", "amf.gmm.fsm", "amf.ctx",
            "smf.establish", "smf.release", "smf.modify", "smf.policymod.qos", "smf.reject", "smf.pfcp.fsm",
            "upf.report", "upf.stats", "upf.context", "upf.upfloop"
    };


    // ==========================================
    // Output File Paths
    // ==========================================

    // File paths where the scraped and processed data will be saved.
    // JSONL (JSON Lines) format is used here because it is excellent for appending continuous streams of data.
    public static final String RUN_LABELS_OUTPUT_FILE = "phase-b-output/run_labels.jsonl";
    public static final String CORE_LOG_EVENTS_OUTPUT_FILE = "phase-b-output/core_log_events.jsonl";

}