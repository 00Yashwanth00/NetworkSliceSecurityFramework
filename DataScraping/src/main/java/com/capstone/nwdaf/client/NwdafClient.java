package com.capstone.nwdaf.client;

import com.capstone.nwdaf.config.AppConfig;
import com.capstone.nwdaf.http.HttpUtil;
import org.json.JSONObject;

public class NwdafClient {

    private final String baseUrl;

    public NwdafClient() {
        this.baseUrl = AppConfig.CORE_BASE_URL;
    }

    public JSONObject pushDataPoint(String sourceNf, String analyticsId, String imsi, String dnn, String dataJsonString, long collectedAtEpochSec) throws Exception {
        JSONObject body = new JSONObject();
        body.put("source_nf", sourceNf);
        body.put("analytics_id", analyticsId);
        body.put("imsi", imsi == null ? "" : imsi);
        body.put("dnn", dnn == null ? "" : dnn);
        body.put("data_json", dataJsonString);
        body.put("collected_at", collectedAtEpochSec);

        String response = HttpUtil.postJson(baseUrl + "/api/nwdaf/data", body.toString());
        return new JSONObject(response);
    }

    public JSONObject getAnalytics(String analyticsId, int windowSec) throws Exception {
        String url = baseUrl + "/api/nwdaf/analytics/" + analyticsId + "?window_sec=" + windowSec;
        return new JSONObject(HttpUtil.get(url));
    }

    public JSONObject getAllAnalytics() throws Exception {
        return new JSONObject(HttpUtil.get(baseUrl + "/api/nwdaf/analytics"));
    }

    public JSONObject getRecent(String analyticsId, int limit) throws Exception {
        String url = baseUrl + "/api/nwdaf/recent?analytics_id=" + analyticsId + "&limit=" + limit;
        return new JSONObject(HttpUtil.get(url));
    }

    public JSONObject getStatus() throws Exception {
        return new JSONObject(HttpUtil.get(baseUrl + "/api/nwdaf/status"));
    }
}
