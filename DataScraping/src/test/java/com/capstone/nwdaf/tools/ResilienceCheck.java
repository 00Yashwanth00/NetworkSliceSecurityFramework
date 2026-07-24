package com.capstone.nwdaf.tools;

import com.capstone.nwdaf.client.McoreClient;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stage 6a — mmt-studio unreachable should throw a clean exception, not crash the JVM
 * (PollingScheduler.pollCycle() already wraps this and logs — this proves the client
 * layer fails the way that catch block expects).
 * Stage 6d — confirms scheduleAtFixedRate on a single-thread executor never overlaps,
 * even if one cycle takes longer than the poll interval.
 */
public class ResilienceCheck {

    public static void main(String[] args) throws Exception {
        checkUnreachableServer();
        checkOverlappingPollsDontOverlap();
    }

    private static void checkUnreachableServer() {
        System.out.println("=== Unreachable server check ===");
        McoreClient deadClient = new McoreClient("http://localhost:1"); // (almost) never listening
        try {
            deadClient.getBenchmarkResults();
            System.out.println("[FAIL] Expected an exception, got none.");
        } catch (Exception e) {
            System.out.println("[PASS] Clean exception, PollingScheduler will log-and-skip: "
                    + e.getClass().getSimpleName());
        }
    }

    private static void checkOverlappingPollsDontOverlap() throws InterruptedException {
        System.out.println("\n=== Overlapping-poll check ===");
        AtomicInteger concurrentRunners = new AtomicInteger(0);
        AtomicInteger maxObserved = new AtomicInteger(0);
        int fastPeriodSeconds = 1;
        int simulatedWorkMillis = 2500; // longer than the period, on purpose

        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        CountDownLatch done = new CountDownLatch(4);

        executor.scheduleAtFixedRate(() -> {
            int concurrent = concurrentRunners.incrementAndGet();
            maxObserved.updateAndGet(max -> Math.max(max, concurrent));
            try {
                Thread.sleep(simulatedWorkMillis);
            } catch (InterruptedException ignored) {
            } finally {
                concurrentRunners.decrementAndGet();
                done.countDown();
            }
        }, 0, fastPeriodSeconds, TimeUnit.SECONDS);

        done.await();
        executor.shutdownNow();

        System.out.println("Max concurrent executions observed: " + maxObserved.get());
        System.out.println(maxObserved.get() <= 1
                ? "[PASS] Single-thread scheduleAtFixedRate never overlaps — a slow cycle just "
                + "delays the next one. PollingScheduler is safe as-is."
                : "[UNEXPECTED] Overlap detected — investigate.");
    }
}