package com.capstone.nwdaf.transform;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.logging.Logger;

public final class DataReshaper {

    private static final Logger log = Logger.getLogger(DataReshaper.class.getName());

    private DataReshaper() {
    }

    public static String buildNfLoad(JSONObject benchmarkResults) {
        JSONObject counters = benchmarkResults.optJSONObject("counters", new JSONObject());

        JSONObject pmCounters = new JSONObject();
        pmCounters.put("RM.RegAtt", counters.optLong("RM.RegAtt", 0));
        pmCounters.put("SM.SessAtt", counters.optLong("SM.SessAtt", 0));

        JSONObject payload = new JSONObject();
        payload.put("pm_counters", pmCounters);
        return payload.toString();
    }

    public static String buildAbnormalBehaviour(JSONObject benchmarkResults) {
        JSONObject counters = benchmarkResults.optJSONObject("counters", new JSONObject());

        JSONObject pmCounters = new JSONObject();
        pmCounters.put("AUTH.Fail", counters.optLong("AUTH.Fail", 0));
        pmCounters.put("AUTH.Att", counters.optLong("AUTH.Att", 0));
        pmCounters.put("AUTH.FailMAC", counters.optLong("AUTH.FailMAC", 0));
        pmCounters.put("SM.SessFail", counters.optLong("SM.SessFail", 0));
        pmCounters.put("SM.SessAtt", counters.optLong("SM.SessAtt", 0));

        JSONObject payload = new JSONObject();
        payload.put("pm_counters", pmCounters);
        return payload.toString();
    }

    public static String buildUeMobility(Object ueStatsRaw) {
        long totalUes;
        long registered;
        long connected;

        JSONArray ueList = extractUeArray(ueStatsRaw);
        if (ueList != null) {
            totalUes = ueList.length();
            registered = totalUes;
            connected = totalUes;
        } else {
            JSONObject obj = (JSONObject) ueStatsRaw;
            log.warning("ue-stats: no per-UE array found; using session_count as a UE-count proxy. "
                    + "VERIFY against live server (§8.1): curl http://localhost:5000/api/upf/ue-stats");
            totalUes = obj.optLong("session_count", 0);
            registered = totalUes;
            connected = totalUes;
        }

        JSONObject payload = new JSONObject();
        payload.put("total_ues", totalUes);
        payload.put("registered", registered);
        payload.put("connected", connected);
        return payload.toString();
    }

    public static String buildPduSession(Object ueStatsRaw) {
        long totalSessions;
        JSONObject sessionsByDnn = new JSONObject();
        JSONObject ipPoolUsage = new JSONObject();

        JSONArray ueList = extractUeArray(ueStatsRaw);
        if (ueList != null) {
            totalSessions = ueList.length();
            for (int i = 0; i < ueList.length(); i++) {
                JSONObject ue = ueList.optJSONObject(i);
                if (ue == null) continue;
                String dnn = ue.optString("dnn", "unknown");
                sessionsByDnn.put(dnn, sessionsByDnn.optLong(dnn, 0) + 1);
            }
        } else {
            JSONObject obj = (JSONObject) ueStatsRaw;
            log.warning("ue-stats: no per-UE array found; sessions_by_dnn will be empty, "
                    + "total_sessions falls back to session_count. VERIFY against live server (§8.1).");
            totalSessions = obj.optLong("session_count", 0);
        }

        JSONObject payload = new JSONObject();
        payload.put("total_sessions", totalSessions);
        payload.put("sessions_by_dnn", sessionsByDnn);
        payload.put("ip_pool_usage", ipPoolUsage);
        return payload.toString();
    }

    public static String buildQosSustainability(JSONObject ioStats, boolean ulIsTx) {
        long ulPkts = ioStats.optLong("ul_pkts", 0);
        long dlPkts = ioStats.optLong("dl_pkts", 0);
        long ulBytes = ioStats.optLong("ul_bytes", 0);
        long dlBytes = ioStats.optLong("dl_bytes", 0);
        long dropped = ioStats.optLong("ul_dropped", 0) + ioStats.optLong("dl_dropped", 0);

        long txPkts = ulIsTx ? ulPkts : dlPkts;
        long rxPkts = ulIsTx ? dlPkts : ulPkts;
        long txBytes = ulIsTx ? ulBytes : dlBytes;
        long rxBytes = ulIsTx ? dlBytes : ulBytes;

        JSONObject payload = new JSONObject();
        payload.put("rx_pkts", rxPkts);
        payload.put("tx_pkts", txPkts);
        payload.put("dropped", dropped);
        payload.put("rx_bytes", rxBytes);
        payload.put("tx_bytes", txBytes);
        return payload.toString();
    }

    public static String buildSliceLoad(Object sliceStatsRaw) {
        JSONObject sessionsBySlice = new JSONObject();

        JSONArray entries;
        if (sliceStatsRaw instanceof JSONArray) {
            entries = (JSONArray) sliceStatsRaw;
        } else {
            JSONObject obj = (JSONObject) sliceStatsRaw;
            entries = obj.optJSONArray("slices");
            if (entries == null) {
                log.warning("slice-stats: response shape not recognized (expected array or "
                        + "{\"slices\": [...]}); SLICE_LOAD payload will be empty. "
                        + "VERIFY against live server (§8.1): curl http://localhost:5000/api/upf/slice-stats");
                entries = new JSONArray();
            }
        }

        for (int i = 0; i < entries.length(); i++) {
            JSONObject entry = entries.optJSONObject(i);
            if (entry == null) continue;
            String sst = entry.has("sst") ? String.valueOf(entry.get("sst")) : entry.optString("SST", "unknown");
            long sessionCount = entry.optLong("session_count", entry.optLong("sessions", 0));
            sessionsBySlice.put(sst, sessionsBySlice.optLong(sst, 0) + sessionCount);
        }

        JSONObject payload = new JSONObject();
        payload.put("sessions_by_slice", sessionsBySlice);
        return payload.toString();
    }

    private static JSONArray extractUeArray(Object ueStatsRaw) {
        if (ueStatsRaw instanceof JSONArray) {
            return (JSONArray) ueStatsRaw;
        }
        if (ueStatsRaw instanceof JSONObject) {
            JSONObject obj = (JSONObject) ueStatsRaw;
            if (obj.optJSONArray("ues") != null) {
                return obj.getJSONArray("ues");
            }
        }
        return null;
    }
}