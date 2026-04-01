package com.framework.sidecar_agent.collector.log;

import com.framework.sidecar_agent.model.LogEvent;

public interface LogHandler {

    void handle(LogEvent event);

}
