package com.framework.sidecar_agent.collector.log;

import com.framework.sidecar_agent.model.LogSource;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class LogCollector {

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    public void start(LogHandler handler) {

        Map<LogSource, String> logFiles = Map.of(
                LogSource.AMF, "/var/log/open5gs/amf.log",
                LogSource.SMF, "/var/log/open5gs/smf.log",
                LogSource.UPF, "/var/log/open5gs/upf.log",
                LogSource.NRF, "/var/log/open5gs/nrf.log",
                LogSource.AUSF, "/var/log/open5gs/ausf.log"
        );

        for(var entry : logFiles.entrySet()) {
            FileTailer tailer = new FileTailer(
                    entry.getValue(),
                    entry.getKey(),
                    handler
            );

            executor.submit(tailer);

            System.out.println("LogCollector started for all Open5GS logs...");
        }

    }

}
