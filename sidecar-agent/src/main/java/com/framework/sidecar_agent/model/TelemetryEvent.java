package com.framework.sidecar_agent.model;

import lombok.Data;

import java.util.Map;

@Data
public class TelemetryEvent {

    private String eventId;
    private String timestamp;

    private Entity entity;
    private Context context;

    private String eventType;
    private String featureGroup;

    private Map<String, Object> features;
}
