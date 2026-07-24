package com.capstone.events;

import com.capstone.events.client.CoreLogClient;
import com.capstone.events.client.SatesterClient;
import com.capstone.events.config.EventConfig;
import com.capstone.events.scheduler.CoreLogPoller;
import com.capstone.events.scheduler.RunPoller;
import com.capstone.events.store.LabelStore;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Phase B entry point — Event & Label Collection.
 * This is the main runnable class that orchestrates the data pipeline.
 * It initializes the clients and the shared storage, and spins up background
 * threads to scrape test runs and network logs in parallel.
 */
public class EventCollectorMain {

    public static void main(String[] args) throws Exception {
        // 1. Startup Logging
        System.out.println("Phase B: Event & Label Collection");
        System.out.println("satester (test runs): " + EventConfig.SATESTER_BASE_URL);
        System.out.println("sacore   (core logs):  " + EventConfig.SACORE_BASE_URL);
        System.out.println("Press Ctrl+C to stop.\n");

        // 2. Initialize the Central Warehouse (LabelStore)
        // This single instance is shared between both pollers so all data
        // flows into the same synchronized storage engine.
        LabelStore store = new LabelStore(
                EventConfig.RUN_LABELS_OUTPUT_FILE,
                EventConfig.CORE_LOG_EVENTS_OUTPUT_FILE
        );

        // 3. Initialize the Pollers (The Background Workers)
        // We inject the respective HTTP clients and the shared store into each poller.
        RunPoller runPoller = new RunPoller(new SatesterClient(), store);
        CoreLogPoller logPoller = new CoreLogPoller(new CoreLogClient(), store);

        // 4. Thread Pool Configuration
        // We use a ScheduledThreadPool of size 2.
        // This gives exactly one dedicated background thread to the RunPoller
        // and one dedicated thread to the CoreLogPoller, allowing them to run concurrently.
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);

        // 5. Start the Timers
        // Schedule both pollers to execute their pollOnce() methods automatically
        // at the intervals defined in the centralized EventConfig.
        executor.scheduleAtFixedRate(runPoller::pollOnce, 0, EventConfig.RUN_POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);
        executor.scheduleAtFixedRate(logPoller::pollOnce, 0, EventConfig.LOG_POLL_INTERVAL_SECONDS, TimeUnit.SECONDS);

        // 6. Graceful Shutdown Hook
        // When you press Ctrl+C in the terminal, the JVM doesn't just instantly die.
        // It triggers this specific block of code first, ensuring data integrity.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutting down Phase B pollers...");

            // Stop the timers and kill the background scraping threads
            executor.shutdownNow();

            try {
                // Safely flush the remaining JSON lines from RAM to the hard drive
                // and release the OS file locks (leveraging AutoCloseable)
                store.close();
            } catch (Exception e) {
                System.out.println("Error closing label store: " + e.getMessage());
            }

            // Print a final summary of exactly how much data was collected during this session
            System.out.println("Run labels stored: " + store.runLabelCount());
            System.out.println("Core log events stored: " + store.logEventCount());
        }));
    }
}