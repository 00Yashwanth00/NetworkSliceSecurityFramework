package com.capstone.nwdaf.transform;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Stage 1 — hand-written sample JSON mirroring the handoff doc's §3 shapes, checked
 * against the §5 schema table. No live server. Fastest debugging loop.
 * Also covers Stage 6c — malformed input should fail loudly, not silently push zeros.
 */
class DataReshaperTest {

    @Test
    void buildNfLoad_producesJsonEncodedStringWithExpectedFields() {
        JSONObject benchmark = new JSONObject()
                .put("counters", new JSONObject()
                        .put("RM.RegAtt", 142)
                        .put("SM.SessAtt", 89));

        String dataJsonString = DataReshaper.buildNfLoad(benchmark);

        // §4.1: data_json must round-trip as valid JSON when re-parsed as a plain string.
        JSONObject parsed = new JSONObject(dataJsonString);
        JSONObject pmCounters = parsed.getJSONObject("pm_counters");
        assertEquals(142, pmCounters.getLong("RM.RegAtt"));
        assertEquals(89, pmCounters.getLong("SM.SessAtt"));
        assertEquals(1, parsed.length(), "only pm_counters should be at the top level per §5");
    }

    @Test
    void buildNfLoad_missingCountersKeyEntirely_failsLoudly() {
        JSONObject malformed = new JSONObject().put("timestamp", 123.0); // no "counters" at all

        assertThrows(IllegalArgumentException.class, () -> DataReshaper.buildNfLoad(malformed),
                "a benchmark response missing \"counters\" entirely should throw, not silently push zeros");
    }

    @Test
    void buildAbnormalBehaviour_producesExpectedFields() {
        JSONObject benchmark = new JSONObject()
                .put("counters", new JSONObject()
                        .put("AUTH.Fail", 2).put("AUTH.Att", 142).put("AUTH.FailMAC", 0)
                        .put("SM.SessFail", 2).put("SM.SessAtt", 89));

        JSONObject pm = new JSONObject(DataReshaper.buildAbnormalBehaviour(benchmark)).getJSONObject("pm_counters");
        assertEquals(2, pm.getLong("AUTH.Fail"));
        assertEquals(142, pm.getLong("AUTH.Att"));
        assertEquals(0, pm.getLong("AUTH.FailMAC"));
        assertEquals(2, pm.getLong("SM.SessFail"));
        assertEquals(89, pm.getLong("SM.SessAtt"));
    }

    @Test
    void buildUeMobility_withUeArray_countsUes() {
        JSONArray ues = new JSONArray()
                .put(new JSONObject().put("imsi", "001").put("dnn", "internet"))
                .put(new JSONObject().put("imsi", "002").put("dnn", "iot"));

        JSONObject parsed = new JSONObject(DataReshaper.buildUeMobility(ues));
        assertEquals(2, parsed.getLong("total_ues"));
        assertEquals(2, parsed.getLong("registered"));
        assertEquals(2, parsed.getLong("connected"));
    }

    @Test
    void buildUeMobility_noArrayFound_fallsBackToSessionCount() {
        JSONObject aggregateOnly = new JSONObject().put("session_count", 5);

        JSONObject parsed = new JSONObject(DataReshaper.buildUeMobility(aggregateOnly));
        assertEquals(5, parsed.getLong("total_ues"));
    }

    @Test
    void buildPduSession_withUeArray_groupsSessionsByDnn() {
        JSONArray ues = new JSONArray()
                .put(new JSONObject().put("dnn", "internet"))
                .put(new JSONObject().put("dnn", "internet"))
                .put(new JSONObject().put("dnn", "iot"));

        JSONObject parsed = new JSONObject(DataReshaper.buildPduSession(ues));
        assertEquals(3, parsed.getLong("total_sessions"));
        JSONObject byDnn = parsed.getJSONObject("sessions_by_dnn");
        assertEquals(2, byDnn.getLong("internet"));
        assertEquals(1, byDnn.getLong("iot"));
    }

    @Test
    void buildQosSustainability_ulIsTxTrue_mapsUlToTx() {
        JSONObject ioStats = new JSONObject()
                .put("ul_pkts", 100).put("dl_pkts", 50)
                .put("ul_bytes", 10000).put("dl_bytes", 5000)
                .put("ul_dropped", 1).put("dl_dropped", 2);

        JSONObject parsed = new JSONObject(DataReshaper.buildQosSustainability(ioStats, true));
        assertEquals(100, parsed.getLong("tx_pkts"));
        assertEquals(50, parsed.getLong("rx_pkts"));
        assertEquals(10000, parsed.getLong("tx_bytes"));
        assertEquals(5000, parsed.getLong("rx_bytes"));
        assertEquals(3, parsed.getLong("dropped"));
    }

    @Test
    void buildQosSustainability_ulIsTxFalse_flipsDirection() {
        JSONObject ioStats = new JSONObject()
                .put("ul_pkts", 100).put("dl_pkts", 50)
                .put("ul_bytes", 10000).put("dl_bytes", 5000);

        JSONObject parsed = new JSONObject(DataReshaper.buildQosSustainability(ioStats, false));
        assertEquals(50, parsed.getLong("tx_pkts"));
        assertEquals(100, parsed.getLong("rx_pkts"));
    }

    @Test
    void buildQosSustainability_completelyMalformedInput_failsLoudly() {
        JSONObject malformed = new JSONObject().put("unrelated_field", "oops");

        assertThrows(IllegalArgumentException.class,
                () -> DataReshaper.buildQosSustainability(malformed, true),
                "io-stats with none of the known counters should throw, not push all-zero data");
    }

    @Test
    void buildSliceLoad_arrayShape_sumsSessionCountPerSst() {
        JSONArray sliceStats = new JSONArray()
                .put(new JSONObject().put("sst", "01").put("session_count", 3))
                .put(new JSONObject().put("sst", "03").put("session_count", 1));

        JSONObject bySlice = new JSONObject(DataReshaper.buildSliceLoad(sliceStats)).getJSONObject("sessions_by_slice");
        assertEquals(3, bySlice.getLong("01"));
        assertEquals(1, bySlice.getLong("03"));
    }

    @Test
    void buildSliceLoad_alternateFieldNames_stillParses() {
        // covers the "SST"/"sessions" naming convention alternative from §3.2
        JSONArray sliceStats = new JSONArray().put(new JSONObject().put("SST", "01").put("sessions", 3));

        JSONObject parsed = new JSONObject(DataReshaper.buildSliceLoad(sliceStats));
        assertEquals(3, parsed.getJSONObject("sessions_by_slice").getLong("01"));
    }

    @Test
    void buildSliceLoad_unrecognizedShape_degradesGracefullyRatherThanThrowing() {
        // Unlike the confirmed-shape builders above, slice-stats is explicitly UNVERIFIED
        // (§8.1) — an unrecognized shape logs a warning and returns empty, since this is
        // expected variance until the real shape is confirmed live, not corruption.
        JSONObject unrecognized = new JSONObject().put("something_else", 1);

        JSONObject parsed = new JSONObject(DataReshaper.buildSliceLoad(unrecognized));
        assertTrue(parsed.getJSONObject("sessions_by_slice").isEmpty());
    }
}