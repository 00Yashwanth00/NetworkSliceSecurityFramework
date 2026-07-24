package com.capstone.nwdaf.tools;

import com.capstone.nwdaf.client.NwdafClient;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Stage 4 — interactive: pauses so you can perform a known action with your tester
 * tool between checks, then reads back analytics and prints values to compare against
 * ground truth. Also covers Stage 6b (SST=02 / URLLC not provisioned by default, §6).
 */
public class GroundTruthCheck {

    public static void main(String[] args) throws Exception {
        NwdafClient client = new NwdafClient();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("=== Stage 6b: unprovisioned-slice check ===");
        JSONObject sliceLoadInitial = client.getAnalytics("SLICE_LOAD", 300);
        JSONObject bySliceInitial = sliceLoadInitial.optJSONObject("result", new JSONObject())
                .optJSONObject("sessions_by_slice", new JSONObject());
        System.out.println("SST \"02\" (URLLC) present? " + bySliceInitial.has("02")
                + " — check GET /api/slices first to confirm whether URLLC is actually provisioned "
                + "in your current run; if not, this should be absent/zero, not an error.");

        waitForUser(in, "\nRegister exactly 2 UEs now, then press Enter.");
        System.out.println("UE_MOBILITY => " + client.getAnalytics("UE_MOBILITY", 300));
        System.out.println("Expected total_ues/registered == 2.");

        waitForUser(in, "\nEstablish a PDU session on the eMBB slice (SST=01) now, then press Enter.");
        System.out.println("SLICE_LOAD => " + client.getAnalytics("SLICE_LOAD", 300));
        System.out.println("Expected: SST \"01\" incremented, SST \"03\" unchanged.");

        waitForUser(in, "\nPush uplink traffic through one session (e.g. iperf) now, then press Enter.");
        System.out.println("QOS_SUSTAINABILITY => " + client.getAnalytics("QOS_SUSTAINABILITY", 300));
        System.out.println("Expected: tx_pkts/rx_pkts moved as expected. If backwards, flip AppConfig.UL_IS_TX.");
    }

    private static void waitForUser(BufferedReader in, String prompt) throws Exception {
        System.out.println(prompt);
        in.readLine();
    }
}