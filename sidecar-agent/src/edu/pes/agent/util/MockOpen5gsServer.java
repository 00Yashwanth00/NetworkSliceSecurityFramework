package edu.pes.agent.util;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class MockOpen5gsServer {

    public static void start(int port) throws IOException {

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // Simulate AMF /ue-info endpoint
        server.createContext("/ue-info", exchange -> {
            String response = "[{\"ue_id\": \"imsi-901700000000001\", \"slice_id\": \"1-000001\", \"guti\": \"5G-GUTI-XYZ\"}]";
            sendResponse(exchange, response);
        });

        // Simulate SMF /pdu-info endpoint
        server.createContext("/pdu-info", exchange -> {
            String response = "[{\"pdu_session_id\": 1, \"ip_address\": \"10.45.0.2\", \"teid\": 1234}]";
            sendResponse(exchange, response);
        });

        server.setExecutor(null);
        server.start();
        System.out.println("Mock Open5GS Server started on port " + port);
    }

    private static void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length());

        try(OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

}
