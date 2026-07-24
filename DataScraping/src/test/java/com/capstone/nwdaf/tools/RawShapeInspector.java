package com.capstone.nwdaf.tools;

import com.capstone.nwdaf.client.McoreClient;
import org.json.JSONArray;
import org.json.JSONObject;

public class RawShapeInspector {
    private static final String[] SLICE_STATS_GUESSED_FIELDS =
            {"sst", "sd", "imsis", "sessions", "upfIDs", "dnns", "ulBytes", "dlBytes"};


    private static String prettyPrint(Object obj) {
        if (obj instanceof JSONObject) return ((JSONObject) obj).toString(2);
        if (obj instanceof JSONArray) return ((JSONArray) obj).toString(2);
        return String.valueOf(obj);
    }

    public static void main(String[] args) throws Exception {
        McoreClient client = new McoreClient();

        System.out.println("=== GET /api/upf/slice-stats ===");
        Object sliceStats = client.getSliceStats();
        System.out.println(prettyPrint(sliceStats));
        checkGuessedFields(sliceStats);

        System.out.println("\n=== GET /api/upf/io-stats ===");
        JSONObject ioStats = client.getIoStats();
        System.out.println(ioStats.toString(2));
        System.out.println("\nTrigger uplink-heavy traffic on one UE and see which counter moves, "
                + "to confirm AppConfig.UL_IS_TX is set correctly (§8.2).");
    }

    private static void checkGuessedFields(Object sliceStats) {
        JSONObject sample = null;
        if (sliceStats instanceof JSONArray && ((JSONArray) sliceStats).length() > 0) {
            sample = ((JSONArray) sliceStats).optJSONObject(0);
        } else if (sliceStats instanceof JSONObject) {
            JSONArray arr = ((JSONObject) sliceStats).optJSONArray("slices");
            if (arr != null && arr.length() > 0) sample = arr.optJSONObject(0);
        }
        if (sample == null) {
            System.out.println("[WARN] No sample slice entry found — empty response, or shape not recognized.");
            return;
        }
        System.out.println("\nField-name check against DataReshaper.buildSliceLoad()'s guesses:");
        for (String field : SLICE_STATS_GUESSED_FIELDS) {
            System.out.println("  " + field + " present? " + sample.has(field));
        }
    }
}
