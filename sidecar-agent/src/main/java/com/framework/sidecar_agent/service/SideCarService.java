package com.framework.sidecar_agent.service;

import com.framework.sidecar_agent.collector.log.LogHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SideCarService implements LogHandler {

    @Autowired
    private LogParser parser;

    @Autowired
    private Enricher enricher;

    @Autowired
    private Publisher publisher;



}
