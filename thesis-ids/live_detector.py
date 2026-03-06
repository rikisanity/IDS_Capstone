import time
import os

LOG_FILE = "/app/captures/conn.log"

def predict_attack(features):
    # TODO for Thesis Phase 3: Insert your trained Machine Learning model here!
    # Example: model.predict([features])
    
    # For now, just a placeholder rule: if bytes > 5000, flag it.
    orig_bytes = float(features[9]) # Index 9 is orig_bytes in Zeek
    if orig_bytes > 5000:
        return True 
    return False

def tail_live_log():
    print(f"[*] Waiting for {LOG_FILE} to be created...")
    while not os.path.exists(LOG_FILE):
        time.sleep(1)
        
    print("[*] Log found! Listening for real-time traffic...\n")
    
    with open(LOG_FILE, 'r') as file:
        # Move to the end of the file
        file.seek(0, 2)
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1) # Wait briefly for new data
                continue
                
            # Ignore Zeek headers
            if line.startswith("#"):
                continue
                
            # Process new traffic instantly
            columns = line.strip().split('\t')
            if len(columns) >= 11:
                src_ip = columns[2]
                dst_ip = columns[4]
                orig_bytes = columns[9]
                
                # Treat empty fields as 0
                if orig_bytes == '-': orig_bytes = '0'
                columns[9] = orig_bytes
                
                # Run through the "AI"
                is_attack = predict_attack(columns)
                
                if is_attack:
                    print(f"🚨 [ALERT] Malicious traffic detected from {src_ip} -> {dst_ip} ({orig_bytes} bytes)")
                else:
                    print(f"✅ [OK] Normal flow: {src_ip} -> {dst_ip}")

if __name__ == "__main__":
    try:
        tail_live_log()
    except KeyboardInterrupt:
        print("\n[*] Stopping live monitor.")