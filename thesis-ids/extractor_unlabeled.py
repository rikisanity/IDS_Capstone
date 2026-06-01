import subprocess
import pandas as pd
import os

# CONFIGURATION
PCAP_FILE = "iot_traffic.pcap"
CAPTURE_DIR = "/app/captures"
DATASET_FILE = "/app/dataset_unlabeled_live.csv"

def process_unlabeled_batch():
    print("[*] Processing UNLABELED Features (No Timestamp) for Inference...")
    
    os.system(f"rm -f {CAPTURE_DIR}/*.log")
    try:
        subprocess.run(f"zeek -C -r {PCAP_FILE}", shell=True, cwd=CAPTURE_DIR, check=True)
    except subprocess.CalledProcessError:
        print("[-] Zeek failed to process the PCAP.")
        return

    # --- 1. CONNECTION & STATISTICAL ACTIVITY ---
    conn_path = os.path.join(CAPTURE_DIR, "conn.log")
    if not os.path.exists(conn_path): 
        print("[-] No network traffic found.")
        return

    df = pd.read_csv(conn_path, sep="\t", comment="#", header=None)
    
    # We must read 'ts' here because Zeek outputs it, but we drop it later
    df.columns = [
        "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", 
        "proto", "service", "duration", "src_bytes", "dst_bytes", 
        "conn_state", "local_orig", "local_resp", "missed_bytes", 
        "history", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes", 
        "tunnel_parents", "ip_proto"
    ]
    df = df.replace('-', 0).replace('(empty)', 0)
    for col in ["duration", "src_bytes", "dst_bytes", "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes"]:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # --- INITIALIZE APPLICATION PROTOCOL COLUMNS ---
    for col in ["dns_query", "dns_qclass", "dns_qtype", "dns_rcode"]: df[col] = "-"
    for col in ["dns_AA", "dns_RD", "dns_RA", "dns_rejected"]: df[col] = "F"
    for col in ["ssl_version", "ssl_cipher", "ssl_subject", "ssl_issuer"]: df[col] = "-"
    for col in ["ssl_resumed", "ssl_established"]: df[col] = "F"
    for col in ["http_method", "http_uri", "http_version", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types"]: df[col] = "-"
    for col in ["http_trans_depth", "http_request_body_len", "http_response_body_len", "http_status_code"]: df[col] = 0
    df['weird_name'] = "-"
    df['weird_addl'] = "-"
    df['weird_notice'] = "F"

    # --- 2. EXTRACT LOGS ---
    dns_path = os.path.join(CAPTURE_DIR, "dns.log")
    if os.path.exists(dns_path):
        try:
            df_dns = pd.read_csv(dns_path, sep="\t", comment="#", header=None)
            df['dns_query'] = df['uid'].map(dict(zip(df_dns[1], df_dns[9]))).fillna(df['dns_query'])
            df['dns_rejected'] = df['uid'].map(dict(zip(df_dns[1], df_dns[23]))).fillna(df['dns_rejected'])
        except Exception: pass

    http_path = os.path.join(CAPTURE_DIR, "http.log")
    if os.path.exists(http_path):
        try:
            df_http = pd.read_csv(http_path, sep="\t", comment="#", header=None)
            df['http_method'] = df['uid'].map(dict(zip(df_http[1], df_http[7]))).fillna(df['http_method'])
            df['http_uri'] = df['uid'].map(dict(zip(df_http[1], df_http[9]))).fillna(df['http_uri'])
            df['http_status_code'] = df['uid'].map(dict(zip(df_http[1], df_http[16]))).fillna(df['http_status_code'])
        except Exception: pass

    weird_path = os.path.join(CAPTURE_DIR, "weird.log")
    if os.path.exists(weird_path):
        try:
            df_weird = pd.read_csv(weird_path, sep="\t", comment="#", header=None)
            df['weird_name'] = df['uid'].map(dict(zip(df_weird[1], df_weird[6]))).fillna(df['weird_name'])
            df['weird_addl'] = df['uid'].map(dict(zip(df_weird[1], df_weird[7]))).fillna(df['weird_addl'])
            df['weird_notice'] = df['uid'].map(dict(zip(df_weird[1], df_weird[8]))).fillna(df['weird_notice'])
        except Exception: pass

    # --- 3. MQTT LOGIC ---
    # mqtt_path = os.path.join(CAPTURE_DIR, "mqtt.log")
    # df['mqtt_topic_len'] = 0
    # df['mqtt_payload_len'] = 0
    # df['mqtt_operation'] = 0
    
    # if os.path.exists(mqtt_path):
    #     try:
    #         df_mqtt = pd.read_csv(mqtt_path, sep="\t", comment="#", header=None)
    #         df['mqtt_operation'] = df_mqtt.iloc[:, 3].apply(lambda x: 2 if 'publish' in str(x) else (3 if 'subscribe' in str(x) else 1))
    #         df['mqtt_topic_len'] = df_mqtt.iloc[:, 4].astype(str).str.len()
    #         df['mqtt_payload_len'] = pd.to_numeric(df_mqtt.iloc[:, 5], errors='coerce').fillna(0)
    #     except Exception: pass

    # --- 4. FINALIZE 45-FEATURE ARCHITECTURE (Removed 'ts', 'label', 'type') ---
    features = [
        "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", 
        "duration", "src_bytes", "dst_bytes", "conn_state", "missed_bytes", 
        "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
        "dns_query", "dns_qclass", "dns_qtype", "dns_rcode", "dns_AA", "dns_RD", "dns_RA", "dns_rejected",
        "ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established", "ssl_subject", "ssl_issuer",
        "http_trans_depth", "http_method", "http_uri", "http_version", 
        "http_request_body_len", "http_response_body_len", "http_status_code", 
        "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
        "weird_name", "weird_addl", "weird_notice",
        # "mqtt_topic_len", "mqtt_payload_len", "mqtt_operation"
    ]
    
    df_final = df.reindex(columns=features, fill_value='-')

    if not os.path.isfile(DATASET_FILE):
        df_final.to_csv(DATASET_FILE, index=False)
        print(f"[+] Created NEW Unlabeled Dataset: {DATASET_FILE}")
    else:
        df_final.to_csv(DATASET_FILE, mode='a', header=False, index=False)
        print(f"[+] Appended {len(df_final)} unlabeled rows to {DATASET_FILE}")

if __name__ == "__main__":
    process_unlabeled_batch()