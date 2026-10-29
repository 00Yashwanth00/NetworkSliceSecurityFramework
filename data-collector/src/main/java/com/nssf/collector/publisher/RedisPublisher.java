package com.nssf.collector.publisher;

import com.nssf.collector.config.CollectorConfig;
import com.nssf.collector.model.SliceTelemetrySample;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class RedisPublisher {

    private static final Logger logger = LoggerFactory.getLogger(RedisPublisher.class);
    
    private final JedisPool jedisPool;
    private final String streamName;
    private final boolean enabled;
    
    private final BlockingQueue<SliceTelemetrySample> queue;
    private final Thread workerThread;
    private volatile boolean isRunning = true;
    private int droppedCount = 0;
    
    public RedisPublisher() {
        CollectorConfig config = CollectorConfig.getInstance();
        this.enabled = config.isRedisEnabled();
        this.streamName = config.getRedisStream();
        
        if (this.enabled) {
            String host = config.getRedisHost();
            int port = config.getRedisPort();
            this.jedisPool = new JedisPool(host, port);
            
            // Fail fast check on startup
            try (Jedis jedis = jedisPool.getResource()) {
                jedis.ping();
                logger.info("Connected to Redis at {}:{}, publishing to stream '{}'", host, port, streamName);
            } catch (Exception e) {
                logger.error("Failed to connect to Redis on startup: {}", e.getMessage());
                // Don't crash, let it run in degraded mode (CSV only)
            }
            
            this.queue = new ArrayBlockingQueue<>(10000);
            this.workerThread = new Thread(this::publishLoop, "redis-publish-worker");
            this.workerThread.setDaemon(true);
            this.workerThread.start();
        } else {
            this.jedisPool = null;
            this.queue = null;
            this.workerThread = null;
        }
    }
    
    public void publish(SliceTelemetrySample sample) {
        if (!enabled) return;
        
        if (!queue.offer(sample)) {
            droppedCount++;
            if (droppedCount % 100 == 1) {
                logger.warn("Redis publish queue full! Dropped {} samples from stream so far.", droppedCount);
            }
        }
    }
    
    private void publishLoop() {
        while (isRunning || !queue.isEmpty()) {
            try {
                SliceTelemetrySample sample = queue.poll(1, TimeUnit.SECONDS);
                if (sample != null) {
                    try (Jedis jedis = jedisPool.getResource()) {
                        Map<String, String> data = serializeSample(sample);
                        jedis.xadd(streamName, (redis.clients.jedis.StreamEntryID) null, data);
                    } catch (Exception e) {
                        logger.error("Failed to publish to Redis stream: {}. Dropping sample.", e.getMessage());
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
    
    private Map<String, String> serializeSample(SliceTelemetrySample s) {
        Map<String, String> map = new HashMap<>();
        map.put("timestamp", String.valueOf(s.getTimestamp()));
        map.put("sliceType", String.valueOf(s.getSliceType()));
        map.put("sessionLabel", s.getSessionLabel() != null ? s.getSessionLabel() : "");
        
        map.put("regAttemptRate", String.valueOf(s.getRegAttemptRate()));
        map.put("regFailureRate", String.valueOf(s.getRegFailureRate()));
        map.put("regSuccessRate", String.valueOf(s.getRegSuccessRate()));
        map.put("authAttemptRate", String.valueOf(s.getAuthAttemptRate()));
        map.put("authFailureRate", String.valueOf(s.getAuthFailureRate()));
        map.put("authSuccessRate", String.valueOf(s.getAuthSuccessRate()));
        map.put("authMacFailures", String.valueOf(s.getAuthMacFailures()));
        map.put("authSqnFailures", String.valueOf(s.getAuthSqnFailures()));
        map.put("secFailureRate", String.valueOf(s.getSecFailureRate()));
        
        map.put("connectedUeCount", String.valueOf(s.getConnectedUeCount()));
        map.put("registeredUeCount", String.valueOf(s.getRegisteredUeCount()));
        map.put("serviceRequestRate", String.valueOf(s.getServiceRequestRate()));
        map.put("pagingRate", String.valueOf(s.getPagingRate()));
        map.put("ngapSetupFailureRate", String.valueOf(s.getNgapSetupFailureRate()));
        
        map.put("sessionAttemptRate", String.valueOf(s.getSessionAttemptRate()));
        map.put("sessionFailureRate", String.valueOf(s.getSessionFailureRate()));
        map.put("sessionSuccessRate", String.valueOf(s.getSessionSuccessRate()));
        map.put("activePduSessions", String.valueOf(s.getActivePduSessions()));
        map.put("sessionsInThisSlice", String.valueOf(s.getSessionsInThisSlice()));
        map.put("qosFlowFailureRate", String.valueOf(s.getQosFlowFailureRate()));
        
        map.put("ulPacketRate", String.valueOf(s.getUlPacketRate()));
        map.put("dlPacketRate", String.valueOf(s.getDlPacketRate()));
        map.put("ulByteRate", String.valueOf(s.getUlByteRate()));
        map.put("dlByteRate", String.valueOf(s.getDlByteRate()));
        map.put("ulDropped", String.valueOf(s.getUlDropped()));
        map.put("dlDropped", String.valueOf(s.getDlDropped()));
        map.put("packetLossRate", String.valueOf(s.getPacketLossRate()));
        map.put("gtpuErrors", String.valueOf(s.getGtpuErrors()));
        
        map.put("sliceSelectionFailureRate", String.valueOf(s.getSliceSelectionFailureRate()));
        
        map.put("nfLoadLevel", String.valueOf(s.getNfLoadLevel()));
        map.put("qosStatus", String.valueOf(s.getQosStatus()));
        map.put("anomalyAlertCount", String.valueOf(s.getAnomalyAlertCount()));
        map.put("serviceUp", String.valueOf(s.getServiceUp()));
        
        return map;
    }
    
    public void shutdown() {
        isRunning = false;
        if (workerThread != null) {
            try {
                workerThread.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (jedisPool != null) {
            jedisPool.close();
        }
    }
}
