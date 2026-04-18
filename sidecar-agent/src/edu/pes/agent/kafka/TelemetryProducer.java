package edu.pes.agent.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.pes.agent.model.TelemetryEvent;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;

public class TelemetryProducer {
    private final KafkaProducer<String, String> producer;
    private final String topic;
    private final ObjectMapper mapper = new ObjectMapper();

    public TelemetryProducer(String bootstrapServers, String topic) {
        this.topic = topic;

        Properties props = new Properties();
        // Point to your Central Node's IP
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        // Reliability settings for Wi-Fi
        props.put(ProducerConfig.ACKS_CONFIG, "1"); // Wait for leader acknowledgment
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10); // Batch for 10ms to improve throughput

        this.producer = new KafkaProducer<>(props);
    }

    public void sendEvent(TelemetryEvent event) {
        try {
            String json = mapper.writeValueAsString(event);
            // Use eventType as the key to ensure same-type events go to same partition
            ProducerRecord<String, String> record = new ProducerRecord<>(topic, event.eventType, json);

            producer.send(record, (metadata, exception) -> {
                if (exception != null) {
                    System.err.println("Error sending to Kafka: " + exception.getMessage());
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void close() {
        producer.close();
    }
}
