package com.capstone.nwdaf.client;

import com.capstone.nwdaf.config.AppConfig;
import com.capstone.nwdaf.http.HttpUtil;
import org.json.JSONArray;
import org.json.JSONObject;

public class McoreClient {

    private final String baseUrl;

    public McoreClient() {
        this(AppConfig.CORE_BASE_URL);
    }

    public McoreClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public JSONObject getBenchmarkResults() throws Exception {
        return new JSONObject(HttpUtil.get(baseUrl + "/api/benchmark/results"));
    }

    public Object getSliceStats() throws Exception {
        return parseFlexible(HttpUtil.get(baseUrl + "/api/upf/slice-stats"));
    }

    public JSONObject getIoStats() throws Exception {
        return new JSONObject(HttpUtil.get(baseUrl + "/api/upf/io-stats"));
    }

    public Object getUeStats() throws Exception {
        return parseFlexible(HttpUtil.get(baseUrl + "/api/upf/ue-stats"));
    }

    private Object parseFlexible(String body) {
        String trimmed = body.trim();
        if (trimmed.startsWith("[")) {
            return new JSONArray(trimmed);
        }
        return new JSONObject(trimmed);
    }
}