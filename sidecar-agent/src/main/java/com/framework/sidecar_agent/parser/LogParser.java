package com.framework.sidecar_agent.parser;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class LogParser {

    public Map<String, Object> parse(String logLine) {

        Map<String, Object> features = new HashMap<>();

        if (logLine.contains("Registration request")) {
            features.put("registration_request", 1);
        }

        if (logLine.contains("Authentication")) {
            features.put("auth_event", 1);
        }

        if (logLine.contains("PDU session")) {
            features.put("session_event", 1);
        }

        return features;
    }

    public String detectFeatureGroup(String logLine) {

        if (logLine.contains("Registration")) return "registration";
        if (logLine.contains("Authentication")) return "authentication";
        if (logLine.contains("session")) return "session";

        return "unknown";
    }
}
