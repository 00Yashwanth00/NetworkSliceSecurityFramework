package com.capstone.events.tools;

import com.capstone.events.client.SatesterClient;
import com.capstone.nwdaf.client.NwdafClient;

/**
 * Diagnostic health-check tool.
 * Confirms that the external dependencies (satester and sacore) are actually
 * online and accepting HTTP requests before relying on them for data collection.
 */
public class ServiceReachabilityCheck {

    public static void main(String[] args) {

        // ==========================================
        // 1. Check the Satester (Test Orchestrator)
        // ==========================================
        System.out.println("Checking satester (http://localhost:5001)...");
        try {
            // Attempt to fetch a single run. We don't save the result because
            // we only care whether the network connection succeeds or fails.
            new SatesterClient().getRuns(1);
            System.out.println("[OK] satester responded to GET /api/runs.");
        } catch (Exception e) {
            // If the connection is refused (e.g., the server is turned off), catch the error gracefully
            System.out.println("[FAIL] satester not reachable/healthy yet: " + e.getMessage());

            // Print a helpful bash command for the developer to debug the simulator
            System.out.println("Check: ./run_studio.sh status");
        }

        // ==========================================
        // 2. Check the SACore (5G Network Simulator)
        // ==========================================
        System.out.println("\nChecking sacore (http://localhost:5000)...");
        try {
            // Use the NWDAF client to hit the lightweight status endpoint.
            // Since NWDAF and Core Logging live on the same port (5000), this proves the server is up.
            new NwdafClient().getStatus();
            System.out.println("[OK] sacore responded to GET /api/nwdaf/status.");
        } catch (Exception e) {
            System.out.println("[FAIL] sacore not reachable: " + e.getMessage());
        }
    }
}