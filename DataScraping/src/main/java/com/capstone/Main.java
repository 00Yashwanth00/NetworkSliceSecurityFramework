package com.capstone;

import com.capstone.nwdaf.config.AppConfig;
import com.capstone.nwdaf.scheduler.PollingScheduler;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        System.out.println("Phase A: NWDAF Data Feeder");
        System.out.println("Target mmt-studio core: " + AppConfig.CORE_BASE_URL);
        System.out.println("Poll interval: " + AppConfig.POLL_INTERVAL_SECONDS + "s, "
                + "readback every " + AppConfig.READBACK_EVERY_N_CYCLES + " cycles");
        System.out.println("Press Ctrl+C to stop.\n");

        PollingScheduler scheduler = new PollingScheduler();
        scheduler.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutting down poller...");
            scheduler.stop();
        }));
    }
}