import redis, time, json

# Disable the socket timeout so block=0 doesn't raise a TimeoutError
r = redis.Redis(
    host='localhost', 
    port=6379, 
    decode_responses=True,
    socket_timeout=None,
    socket_keepalive=True
)
last_id = '$'

print("Listening for verdicts...")
while True:
    try:
        # Use a 5-second block instead of 0 (infinite) just to be safe with the socket
        result = r.xread({'verdicts': last_id}, count=10, block=5000)
        if result:
            for stream, messages in result:
                for message_id, data in messages:
                    last_id = message_id
                    print(f"\n--- Verdict at {data['timestamp']} ---")
                    print(f"Verdict: {data['verdict']} (Score: {data['final_score']})")
                    print(f"Line 1 (Net/Pkt): {data['line1_network_score']} / {data['line1_packet_score']}")
                    print(f"Line 2 Invoked: {bool(int(data['line2_invoked']))}")
                    
                    try:
                        details_dict = json.loads(data['details'])
                        print(f"Details: {json.dumps(details_dict, indent=2)}")
                    except:
                        print(f"Details: {data['details']}")
    except Exception as e:
        # Catch unexpected disconnects and just loop
        time.sleep(1)
