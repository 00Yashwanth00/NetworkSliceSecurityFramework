package edu.pes.agent.collection;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

//This class will fetch raw JSON strings from the Open5GS components (AMF for UE info and SMF for session info).
public class ApiCollector {

    private final OkHttpClient client;

    public ApiCollector() {
        // Build a client with timeouts to handle potential Wi-Fi latency
        this.client = new OkHttpClient.Builder()
                .connectTimeout(2, TimeUnit.SECONDS)
                .readTimeout(2, TimeUnit.SECONDS)
                .build();
    }

    //Fetched raw JSON from a specific Open5Gs component endpoint.

    public String fetchRawData(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Accept", "application/json")
                .build();

        try(Response response = client.newCall(request).execute()) {
            if(!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }
            return response.body() != null ? response.body().toString() : "";
        }
    }
}
