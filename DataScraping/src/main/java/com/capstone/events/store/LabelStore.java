package com.capstone.events.store;

import com.capstone.events.model.CoreLogEvent;
import com.capstone.events.model.TestRunLabel;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

/**
 * §6.4 — Centralized storage engine for test run labels and core network events.
 * Implements a dual-storage strategy: keeping records in memory for fast querying
 * while simultaneously appending them to local JSONL files for persistence.
 *
 * Implements AutoCloseable to ensure file streams are safely closed when the app shuts down.
 */
public class LabelStore implements AutoCloseable {

    private static final Logger log = Logger.getLogger(LabelStore.class.getName());

    // Thread-safe in-memory lists. Collections.synchronizedList ensures that multiple
    // polling threads won't cause ConcurrentModificationExceptions when adding items.
    private final List<TestRunLabel> runLabels = Collections.synchronizedList(new ArrayList<>());
    private final List<CoreLogEvent> logEvents = Collections.synchronizedList(new ArrayList<>());

    // BufferedWriters for fast, efficient disk I/O.
    private final BufferedWriter runLabelsWriter;
    private final BufferedWriter logEventsWriter;

    /**
     * Initializes the store, ensuring output directories exist and opening file streams.
     *
     * @param runLabelsPath The file path for saving test labels.
     * @param logEventsPath The file path for saving core logs.
     * @throws IOException If the files cannot be created or opened.
     */
    public LabelStore(String runLabelsPath, String logEventsPath) throws IOException {
        Path runPath = Paths.get(runLabelsPath);
        Path logPath = Paths.get(logEventsPath);

        // Ensure the parent directories (e.g., "phase-b-output") exist before writing
        if (runPath.getParent() != null) Files.createDirectories(runPath.getParent());
        if (logPath.getParent() != null) Files.createDirectories(logPath.getParent());

        // Initialize the writers. The 'true' flag tells FileWriter to APPEND to the file
        // rather than overwriting it, preserving data across application restarts.
        this.runLabelsWriter = new BufferedWriter(new FileWriter(runPath.toFile(), true));
        this.logEventsWriter = new BufferedWriter(new FileWriter(logPath.toFile(), true));
    }

    /**
     * Adds a new test run label to memory and persists it to the JSONL file.
     * The 'synchronized' keyword prevents two threads from writing to the file simultaneously.
     */
    public synchronized void addRunLabel(TestRunLabel label) {
        runLabels.add(label);
        try {
            runLabelsWriter.write(label.toJson().toString());
            runLabelsWriter.newLine(); // Creates the JSON Lines format
            runLabelsWriter.flush();   // Forces the OS to write to disk immediately
        } catch (IOException e) {
            log.warning("Failed to persist run label to file: " + e.getMessage());
        }
    }

    /**
     * Adds a new core log event to memory and persists it to the JSONL file.
     */
    public synchronized void addLogEvent(CoreLogEvent event) {
        logEvents.add(event);
        try {
            logEventsWriter.write(event.toJson().toString());
            logEventsWriter.newLine();
            logEventsWriter.flush();
        } catch (IOException e) {
            log.warning("Failed to persist log event to file: " + e.getMessage());
        }
    }

    /**
     * Queries the in-memory store for any test runs that OVERLAP with a given time window.
     * This is used to join the outcomes of a test (Phase A) with the network events happening at that time.
     *
     * @param fromEpochSec The start of the time window.
     * @param toEpochSec The end of the time window.
     * @return A list of overlapping TestRunLabels.
     */
    public List<TestRunLabel> queryRunLabels(double fromEpochSec, double toEpochSec) {
        List<TestRunLabel> result = new ArrayList<>();
        // Must synchronize on the list while iterating to prevent concurrent modifications
        synchronized (runLabels) {
            for (TestRunLabel l : runLabels) {
                // Overlap logic: The test completed after our window started,
                // AND it started before our window ended.
                if (l.completedAt >= fromEpochSec && l.startedAt <= toEpochSec) {
                    result.add(l);
                }
            }
        }
        return result;
    }

    /**
     * Queries the in-memory store for core log events occurring strictly within a time window.
     *
     * @param fromEpochSec The start of the time window.
     * @param toEpochSec The end of the time window.
     * @return A list of log events that occurred in that exact timeframe.
     */
    public List<CoreLogEvent> queryLogEvents(double fromEpochSec, double toEpochSec) {
        List<CoreLogEvent> result = new ArrayList<>();
        synchronized (logEvents) {
            for (CoreLogEvent e : logEvents) {
                if (e.ts >= fromEpochSec && e.ts <= toEpochSec) {
                    result.add(e);
                }
            }
        }
        return result;
    }

    public int runLabelCount() {
        return runLabels.size();
    }

    public int logEventCount() {
        return logEvents.size();
    }

    /**
     * Cleans up file resources when the application shuts down.
     */
    @Override
    public void close() throws IOException {
        runLabelsWriter.close();
        logEventsWriter.close();
    }
}