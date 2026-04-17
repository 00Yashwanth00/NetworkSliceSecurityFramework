package edu.pes.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.pes.agent.collection.ApiCollector;
import edu.pes.agent.collection.LogTailerListener;
import edu.pes.agent.collection.MetricsSource;
import edu.pes.agent.model.TelemetryEvent;
import edu.pes.agent.util.MockOpen5gsServer;
import org.apache.commons.io.input.Tailer;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

public class AgentApp {

//    public static void main(String[] args) {
//        try {
//            MockOpen5gsServer.start(9090);
//
//            // 2. Initialize Collector and JSON Mapper
//            ApiCollector collector = new ApiCollector();
//            ObjectMapper mapper = new ObjectMapper();
//
//            System.out.println("Sidecar Agent starting data collection...");
//
//            for(int i = 0; i < 3; i++) {
//                String rawJson = collector.fetchRawData("http://localhost:9090/ue-info");
//                System.out.println("\n[RAW DATA FETCHED]: " + rawJson);
//
//                // Populate your TelemetryEvent model
//                TelemetryEvent event = new TelemetryEvent();
//                event.eventId = UUID.randomUUID().toString();
//                event.timestamp = Instant.now().toString();
//                event.eventType = "api";
//
//                // Simplified mapping for the demo
//                event.context = new TelemetryEvent.Context();
//                event.context.ueId = "imsi-901700000000001"; // Extracted from rawJson
//                event.context.sliceId = "1-000001";
//
//                // Convert back to your specific JSON schema for logging/Kafka
//                String schemaJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event);
//                System.out.println("[STRUCTURED SCHEMA]:\n" + schemaJson);
//
//                Thread.sleep(3000);
//            }
//        } catch (IOException | InterruptedException e) {
//            throw new RuntimeException(e);
//        }
//    }


//    public static void main(String[] args) {
//        File logFile = new File("mock_amf.log");
//
//        LogTailerListener listener = new LogTailerListener();
//        Tailer tailer = new Tailer(logFile, listener, 500, true);
//        Thread tailerThread = new Thread(tailer);
//        tailerThread.setDaemon(true);
//        tailerThread.start();
//
//        System.out.println("Sidecar Agent: Monitoring " + logFile.getAbsolutePath() + "...");
//
//        // Keep the app running
//        while (true) {
//            try { Thread.sleep(1000); } catch (InterruptedException e) { break; }
//        }
//    }

    public static void main(String[] args) {
        try {
            // 1. Initialize all sensors
            ApiCollector apiCollector = new ApiCollector();
            MetricsSource metricsSource = new MetricsSource();
            ObjectMapper mapper = new ObjectMapper();

            // 2. Start Log Monitoring in background [cite: 453]
            // For lab: point to /var/log/open5gs/amf.log
            System.out.println("Starting Log Monitoring...");
            // (LogTailer setup from previous step goes here)

            System.out.println("Starting Metrics & API Polling...");

            while (true) {
                // Create a single telemetry event for this heartbeat [cite: 1]
                TelemetryEvent event = new TelemetryEvent();
                event.eventId = UUID.randomUUID().toString();
                event.timestamp = Instant.now().toString();
                event.eventType = "system";

                // A. Collect Metrics [cite: 361, 394]
                event.metrics = metricsSource.collectMetrics();

                // B. Collect API Context (Mocked locally, real in Lab)
                // try { String raw = apiCollector.fetchRawData("http://localhost:9090/ue-info"); ... }

                // C. Set Labels [cite: 1]
                event.labels = new TelemetryEvent.Labels();
                event.labels.environment = "dev";
                event.labels.severity = (double) event.metrics.get("cpu_usage_percent") > 80 ? "high" : "low";

                // Print the final structured JSON conforming to DataSchema.txt
                System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event));

                Thread.sleep(5000); // 5-second interval for monitoring [cite: 363]
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
