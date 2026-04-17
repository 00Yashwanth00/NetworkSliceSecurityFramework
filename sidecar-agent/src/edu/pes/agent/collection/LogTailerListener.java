package edu.pes.agent.collection;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.pes.agent.model.TelemetryEvent;
import org.apache.commons.io.input.TailerListenerAdapter;

import java.time.Instant;
import java.util.UUID;

public class LogTailerListener extends TailerListenerAdapter {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void handle(String line) {
        // Look for registration or session events in Open5GS logs
        if(line.contains("Registration Request") || line.contains("Initial Context Setup")) {
            processEvent(line, "control");
        } else if (line.contains("error") || line.contains("critical")) {
            processEvent(line, "system");
        }
    }

    private void processEvent(String rawLine, String type) {
        try {
            TelemetryEvent event = new TelemetryEvent();
            event.eventId = UUID.randomUUID().toString();
            event.timestamp = Instant.now().toString();
            event.eventType = type;

            // Populate Entity [cite: 1]
            event.entity = new TelemetryEvent.Entity();
            event.entity.nfType = "AMF"; // AMF handles registrations [cite: 435]

            // Add raw log as a feature for the ML model [cite: 368, 394]
            event.features.put("raw_log", rawLine);

            System.out.println("\n[LOG DETECTED]: " + type.toUpperCase());
            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event));

        } catch (Exception e) {
            System.err.println("Error processing log line: " + e.getMessage());
        }
    }

}
