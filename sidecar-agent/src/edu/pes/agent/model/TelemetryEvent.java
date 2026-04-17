package edu.pes.agent.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.HashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TelemetryEvent {

    @JsonProperty("event_id")
    public String eventId; // UUID

    public String timestamp; // ISO-8601

    public Entity entity;

    public Context context;

    @JsonProperty("event_type")
    public String eventType; // control | api | traffic | system | config

    @JsonProperty("feature_group")
    public String featureGroup;

    public Map<String, Object> features = new HashMap<>(); // Flexible object

    public Map<String, Object> metrics = new HashMap<>(); // Flexible object

    public Labels labels;

    // --- Nested Classes ---

    public static class Entity {
        @JsonProperty("nf_type")
        public String nfType; // AMF | SMF | UPF | NRF

        @JsonProperty("nf_id")
        public String nfId;

        @JsonProperty("component_id")
        public String componentId;
    }

    public static class Context {
        @JsonProperty("slice_id")
        public String sliceId; // SST-SD

        @JsonProperty("ue_id")
        public String ueId; // imsi-xxx

        public String guti;

        @JsonProperty("pdu_session_id")
        public Integer pduSessionId;

        public Integer teid;

        @JsonProperty("ip_address")
        public String ipAddress;
    }

    public static class Labels {
        public String environment; // dev | test | prod
        public String severity; // low | medium | high
    }

    public static void main(String[] args) {
        try {
            // Create object
            TelemetryEvent event = new TelemetryEvent();
            event.eventId = "evt-123";
            event.timestamp = "2026-04-17T10:15:30Z";
            event.eventType = "CPU_USAGE";

            // Entity
            Entity entity = new Entity();
            entity.nfType = "AMF";
            entity.nfId = "amf-01";
            event.entity = entity;

            // Context
            Context context = new Context();
            context.sliceId = "1-001";
            context.ueId = "ue-999";
            context.ipAddress = "10.0.0.5";
            event.context = context;

            // Metrics
            event.metrics = new HashMap<>();
            event.metrics.put("cpu", 75.5);
            event.metrics.put("memory", 60);

            // Labels
            Labels labels = new Labels();
            labels.environment = "dev";
            labels.severity = "medium";
            event.labels = labels;

            // ObjectMapper
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            // Convert to JSON
            String json = mapper.writeValueAsString(event);

            // Print
            System.out.println(json);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}