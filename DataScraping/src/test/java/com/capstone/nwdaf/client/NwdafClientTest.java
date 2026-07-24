package com.capstone.nwdaf.client;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NwdafClientTest {

    @Test
    void buildEnvelope_embedsDataJsonAsStringNotNestedObject() {
        NwdafClient client = new NwdafClient();
        String reshaped = "{\"pm_counters\":{\"RM.RegAtt\":142}}";

        JSONObject envelope = client.buildEnvelope("AMF", "NF_LOAD", "", "", reshaped, 0L);

        // The exact mistake §4.1 warns about: data_json must be a STRING, not a nested object.
        assertTrue(envelope.get("data_json") instanceof String);
        assertEquals(reshaped, envelope.getString("data_json"));

        JSONObject reparsed = new JSONObject(envelope.getString("data_json"));
        assertEquals(142, reparsed.getJSONObject("pm_counters").getLong("RM.RegAtt"));
    }

}