package com.framework.sidecar_agent.collector.log;

import com.framework.sidecar_agent.model.LogEvent;
import com.framework.sidecar_agent.model.LogSource;

import java.io.RandomAccessFile;

public class FileTailer implements Runnable {

    private final String filePath;
    private final LogSource source;
    private final LogHandler handler;

    public FileTailer(String filePath, LogSource source, LogHandler handler) {
        this.filePath = filePath;
        this.source = source;
        this.handler = handler;
    }

    @Override
    public void run() {

        try (RandomAccessFile file = new RandomAccessFile(filePath, "r")) {

            long filePointer = file.length();

            while (true) {

                long fileLength = file.length();

                if (fileLength < filePointer) {
                    filePointer = fileLength;
                }

                if (fileLength > filePointer) {

                    file.seek(filePointer);

                    String line;
                    while ((line = file.readLine()) != null) {

                        LogEvent event = new LogEvent(
                                source,
                                line,
                                System.currentTimeMillis()
                        );

                        handler.handle(event);
                    }

                    filePointer = file.getFilePointer();
                }

                Thread.sleep(500); // fast polling

            }

        } catch (Exception e) {
            System.err.println("Error reading file: " + filePath);
            e.printStackTrace();
        }
    }
}