package edu.pes.agent.collection;

import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;
import java.util.HashMap;
import java.util.Map;

public class MetricsSource {
    private final OperatingSystemMXBean osBean;

    public MetricsSource() {
        // Access the Sun-specific bean for detailed memory/CPU data
        this.osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
    }

    /**
     * Captures CPU and Memory metrics to populate the 'metrics' map in the schema.
     * [cite: 89, 396]
     */
    public Map<String, Object> collectMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        // Capture CPU Load (0.0 to 1.0) and convert to percentage
        double cpuLoad = osBean.getCpuLoad();
        metrics.put("cpu_usage_percent", cpuLoad < 0 ? 0.0 : cpuLoad * 100);

        // Capture Memory stats in MB [cite: 396]
        long totalMemory = osBean.getTotalMemorySize() / (1024 * 1024);
        long freeMemory = osBean.getFreeMemorySize() / (1024 * 1024);
        long usedMemory = totalMemory - freeMemory;

        metrics.put("total_memory_mb", totalMemory);
        metrics.put("used_memory_mb", usedMemory);

        double memoryPercent = ((double) usedMemory / totalMemory) * 100;
        metrics.put("memory_usage_percent", memoryPercent);

        return metrics;
    }
}
