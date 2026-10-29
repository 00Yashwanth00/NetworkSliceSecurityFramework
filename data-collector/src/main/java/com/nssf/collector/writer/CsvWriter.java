package com.nssf.collector.writer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nssf.collector.config.CollectorConfig;
import com.nssf.collector.model.SliceTelemetrySample;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service responsible for writing telemetry samples to CSV files
 * and generating a metadata tracking JSON file.
 */
public class CsvWriter {

    private static final Logger logger = LoggerFactory.getLogger(CsvWriter.class);
    private final Path outputDir;
    // Map to cache active file references grouped by their slice type (SST)
    private final Map<Integer, File> sliceFiles = new HashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();
    private final long startTime;
    private long totalSamplesWritten = 0;

    public CsvWriter() {
        this.outputDir = Paths.get(CollectorConfig.getInstance().getOutputDir());
        this.startTime = System.currentTimeMillis();
        try {
            // Ensure the destination folder exists before attempting to write files
            Files.createDirectories(outputDir);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create output directory: " + outputDir, e);
        }
    }

    /**
     * Loops through an extracted list of samples, writes them to their respective
     * slice files, and updates the session metadata file.
     */
    public void writeSamples(List<SliceTelemetrySample> samples) {
        if (samples == null || samples.isEmpty()) {
            return;
        }
        for (SliceTelemetrySample sample : samples) {
            writeSample(sample);
            totalSamplesWritten++;
        }
        writeMetadata();
    }

    /**
     * Appends a single sample to the appropriate CSV file based on its slice ID.
     */
    private void writeSample(SliceTelemetrySample sample) {
        int sst = sample.getSliceType();
        // Retrieve the file reference for this SST, or initialize it if it doesn't
        // exist yet
        File csvFile = sliceFiles.computeIfAbsent(sst, this::initCsvFile);

        try (FileWriter fw = new FileWriter(csvFile, true)) { // 'true' enables append mode
            fw.write(sample.toCsvRow() + "\n");
        } catch (IOException e) {
            logger.error("Failed to write to CSV for slice {}: {}", sst, e.getMessage());
        }
    }

    /**
     * Initializes a new CSV file for a given network slice and inserts the header
     * row.
     * Output is routed to a separate file based on the sessionLabel:
     * - "normal" → slice_telemetry.csv (baseline dataset)
     * - any attack label → slice_telemetry_attacks.csv (attack dataset)
     */
    private File initCsvFile(int sst) {
        CollectorConfig config = CollectorConfig.getInstance();
        String sessionLabel = config.getSessionLabel();

        // Route to separate file so attack data never contaminates the normal baseline
        String filename = "normal".equalsIgnoreCase(sessionLabel)
                ? "new_slice_telemetry_1.csv"
                : "new_slice_telemetry_attacks.csv";

        File file = outputDir.resolve(filename).toFile();

        // Only write headers if the file is completely new or empty
        boolean isNew = !file.exists() || file.length() == 0;
        if (isNew) {
            try (FileWriter fw = new FileWriter(file)) {
                fw.write(SliceTelemetrySample.csvHeader() + "\n");
                logger.info("Created new CSV file: {} (sessionLabel={})", filename, sessionLabel);
            } catch (IOException e) {
                logger.error("Failed to create CSV header for slice {}: {}", sst, e.getMessage());
            }
        }
        return file;
    }

    /**
     * Generates a "collection_meta.json" file tracking high-level statistics about
     * the run.
     * Useful for parsing datasets later to identify session bounds and total
     * samples.
     */
    private void writeMetadata() {
        File metaFile = outputDir.resolve("collection_meta.json").toFile();
        CollectorConfig config = CollectorConfig.getInstance();

        // Build JSON structure programmatically using Jackson's ObjectNode
        ObjectNode meta = mapper.createObjectNode();
        meta.put("sessionLabel", config.getSessionLabel());
        meta.put("startTime", Instant.ofEpochMilli(startTime).toString());
        meta.put("lastUpdate", Instant.now().toString());
        meta.put("intervalSeconds", config.getIntervalSeconds());
        meta.put("coreBaseUrl", config.getCoreBaseUrl());
        meta.put("totalSamplesWritten", totalSamplesWritten);

        try {
            // Write JSON structure directly to the file with formatting (pretty print)
            mapper.writerWithDefaultPrettyPrinter().writeValue(metaFile, meta);
        } catch (IOException e) {
            logger.error("Failed to write metadata JSON: {}", e.getMessage());
        }
    }
}