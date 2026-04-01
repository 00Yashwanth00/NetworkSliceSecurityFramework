package com.framework.sidecar_agent.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LogEvent {
    private LogSource source;
    private String message;
    private long timestamp;
}
