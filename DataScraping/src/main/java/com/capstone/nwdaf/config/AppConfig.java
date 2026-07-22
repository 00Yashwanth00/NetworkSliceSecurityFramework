package com.capstone.nwdaf.config;

public final class AppConfig {

    private AppConfig() {}

    public static final String CORE_BASE_URL = "http://localhost:5000";
    public static final int POLL_INTERVAL_SECONDS = 10;
    public static final int READBACK_EVERY_N_CYCLES = 3;
    public static final int ANALYTICS_WINDOW_SEC = 300;
    public static final boolean UL_IS_TX = true;

}
