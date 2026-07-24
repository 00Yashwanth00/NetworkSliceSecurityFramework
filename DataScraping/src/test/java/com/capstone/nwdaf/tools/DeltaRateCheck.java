package com.capstone.nwdaf.tools;

import com.capstone.nwdaf.client.NwdafClient;
import com.capstone.nwdaf.scheduler.PollingScheduler;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Stage 5 — NF_LOAD/ABNORMAL_BEHAVIOUR compute RATES by diffing successive snapshots.
 * A single push won't show meaningful output; push twice with real activity in
 * between and confirm avg_registration_rate actually moves.
 */
public class DeltaRateCheck {

    public static void main(String[] args) throws Exception {
        PollingScheduler scheduler = new PollingScheduler();
        NwdafClient nwdafClient = new NwdafClient();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Pushing first snapshot...");
        scheduler.runOnePushCycle();

        System.out.println("Now register a few UEs / trigger traffic, then press Enter.");
        in.readLine();

        System.out.println("Pushing second snapshot...");
        scheduler.runOnePushCycle();

        JSONObject nfLoad = nwdafClient.getAnalytics("NF_LOAD", 300);
        System.out.println("NF_LOAD => " + nfLoad);

        double rate = nfLoad.optJSONObject("result", new JSONObject()).optDouble("avg_registration_rate", 0.0);
        System.out.println(rate != 0.0
                ? "[PASS] avg_registration_rate is non-trivial: " + rate
                : "[FAIL] avg_registration_rate is 0 — either no activity happened, or check timestamps/window_sec.");
    }
}