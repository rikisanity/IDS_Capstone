# live_monitor.py
# Real-time intrusion detection by watching Zeek's conn.log as it gets written.

import csv
import logging
import os
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
from IDS_inferencing import TONIoTInferencer

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

CAPTURE_DIR       = os.environ.get("CAPTURE_DIR",     "/app/captures")
MODEL_NAME        = os.environ.get("MODEL_NAME",      "xgb")
MODEL_DIR         = os.environ.get("MODEL_DIR",       "/app/live_inferencing")
FEATURES_PATH     = os.environ.get("FEATURES_PATH",   "/app/live_inferencing/selected_feature_names.pkl")

STALE_SECS        = int(os.environ.get("STALE_SECS",   "10"))   
HEARTBEAT_SECS    = int(os.environ.get("HEARTBEAT_SECS","15"))  
SKIP_INTERNAL     = os.environ.get("SKIP_INTERNAL", "1") == "1" 
LOG_FILE          = os.environ.get("LOG_FILE",        "/app/datasets/detection_log.csv")
BACKFILL          = os.environ.get("BACKFILL",        "0") == "1"
HIGH_CONF         = float(os.environ.get("HIGH_CONF", "0.80"))
MED_CONF          = float(os.environ.get("MED_CONF",  "0.50"))
ZEEK_STARTUP_WAIT = int(os.environ.get("ZEEK_STARTUP_WAIT", "5"))

CONN_LOG    = os.path.join(CAPTURE_DIR, "conn.log")
MQTT_LOG    = os.path.join(CAPTURE_DIR, "mqtt_publish.log")

NUMERIC_COLS = [
    "duration", "src_bytes", "dst_bytes", "missed_bytes",
    "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
]

def parse_zeek_header(filepath):
    col_map = {}
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]  
                    col_map = {name: idx for idx, name in enumerate(fields)}
                    break
                if not line.startswith("#"):
                    break  
    except Exception as e:
        log.warning("Couldn't parse header from %s: %s", filepath, e)
    return col_map

class SideLogCache:
    def __init__(self, capture_dir):
        self.capture_dir = capture_dir
        self.cache = {}    
        self.mtimes = {}   

    def log_path(self, name):
        return os.path.join(self.capture_dir, f"{name}.log")

    def needs_refresh(self, name):
        path = self.log_path(name)
        if not os.path.exists(path):
            return False
        mtime = os.path.getmtime(path)
        if self.mtimes.get(name, 0) != mtime:
            self.mtimes[name] = mtime
            return True
        return False

    def load_log(self, log_name):
        path = self.log_path(log_name)
        if not os.path.exists(path):
            return None, {}
        try:
            col_map = parse_zeek_header(path)
            df = pd.read_csv(path, sep="\t", comment="#", header=None)
            if col_map and df.shape[1] == len(col_map):
                df.columns = list(col_map.keys())
            return df, col_map
        except Exception as e:
            log.warning("Problem loading %s.log: %s", log_name, e)
            return None, {}

    def refresh_mqtt(self):
        connect_df, _ = self.load_log("mqtt_connect")
        if connect_df is not None and not connect_df.empty:
            uid_col = "uid" if "uid" in connect_df.columns else connect_df.columns[1]
            for _, row in connect_df.iterrows():
                self.cache.setdefault(row[uid_col], {}).update({"mqtt_operation": 1})

        publish_df, _ = self.load_log("mqtt_publish")
        if publish_df is not None and not publish_df.empty:
            uid_col   = "uid" if "uid" in publish_df.columns else publish_df.columns[1]
            topic_col = next((c for c in ("topic", "msg_topic") if c in publish_df.columns), None)
            size_col  = next((c for c in ("payload_size", "msg_len", "data_len") if c in publish_df.columns), None)

            for _, row in publish_df.iterrows():
                uid   = row[uid_col]
                entry = {"mqtt_operation": 2}
                if topic_col:
                    entry["mqtt_topic_len"]   = len(str(row[topic_col]))
                if size_col:
                    entry["mqtt_payload_len"] = pd.to_numeric(row[size_col], errors="coerce") or 0
                self.cache.setdefault(uid, {}).update(entry)

    def refresh_dns(self):
        df, _ = self.load_log("dns")
        if df is None or df.empty: return
        uid_col = "uid" if "uid" in df.columns else df.columns[1]
        q_col   = "query" if "query" in df.columns else None
        rej_col = "rejected" if "rejected" in df.columns else None
        for _, row in df.iterrows():
            uid = row[uid_col]
            entry = {}
            if q_col:   entry["dns_query"]    = str(row[q_col])
            if rej_col: entry["dns_rejected"] = str(row[rej_col])
            self.cache.setdefault(uid, {}).update(entry)

    def refresh_http(self):
        df, _ = self.load_log("http")
        if df is None or df.empty: return
        uid_col    = "uid" if "uid" in df.columns else df.columns[1]
        meth_col   = "method" if "method" in df.columns else None
        uri_col    = "uri" if "uri" in df.columns else None
        status_col = "status_code" if "status_code" in df.columns else None
        for _, row in df.iterrows():
            uid = row[uid_col]
            entry = {}
            if meth_col:   entry["http_method"]      = str(row[meth_col])
            if uri_col:    entry["http_uri"]         = str(row[uri_col])
            if status_col: entry["http_status_code"] = pd.to_numeric(row[status_col], errors="coerce") or 0
            self.cache.setdefault(uid, {}).update(entry)

    def refresh_weird(self):
        df, _ = self.load_log("weird")
        if df is None or df.empty: return
        uid_col    = "uid" if "uid" in df.columns else df.columns[1]
        name_col   = "name" if "name" in df.columns else None
        addl_col   = "addl" if "addl" in df.columns else None   
        notice_col = "notice" if "notice" in df.columns else None
        for _, row in df.iterrows():
            uid = row[uid_col]
            entry = {}
            if name_col:   entry["weird_name"]   = str(row[name_col])
            if addl_col:   entry["weird_addl"]   = str(row[addl_col])
            if notice_col: entry["weird_notice"] = str(row[notice_col])
            self.cache.setdefault(uid, {}).update(entry)

    def refresh_if_needed(self):
        if self.needs_refresh("mqtt_connect") or self.needs_refresh("mqtt_publish"):
            self.refresh_mqtt()
        if self.needs_refresh("dns"):   self.refresh_dns()
        if self.needs_refresh("http"):  self.refresh_http()
        if self.needs_refresh("weird"): self.refresh_weird()

    def get(self, uid):
        return self.cache.get(uid, {})


def parse_conn_line(line, col_map, side_cache):
    if line.startswith("#") or not line.strip():
        return None

    parts = line.strip().split("\t")

    if SKIP_INTERNAL:
        src_raw = parts[col_map.get("id.orig_h", 2)] if len(parts) > 2 else ""
        dst_raw = parts[col_map.get("id.resp_h", 4)] if len(parts) > 4 else ""
        NOISY_DST = ("224.", "239.", "255.255.255.255", "fe80:", "ff02:", "ff00:", "::1")
        NOISY_SRC = ("fe80:", "ff02:", "ff00:", "127.", "::1")
        if any(dst_raw.startswith(p) for p in NOISY_DST): return None
        if any(src_raw.startswith(p) for p in NOISY_SRC): return None

    def get(field_name, default="-"):
        idx = col_map.get(field_name)
        if idx is None or idx >= len(parts): return default
        val = parts[idx]
        return default if val in ("-", "(empty)", "") else val

    features = {
        "src_ip":       get("id.orig_h"), "src_port":     get("id.orig_p", 0),
        "dst_ip":       get("id.resp_h"), "dst_port":     get("id.resp_p", 0),
        "proto":        get("proto"),     "service":      get("service"),
        "conn_state":   get("conn_state"),"duration":     get("duration", 0),
        "src_bytes":    get("orig_bytes", 0), "dst_bytes":    get("resp_bytes", 0),
        "missed_bytes": get("missed_bytes", 0), "src_pkts":   get("orig_pkts", 0),
        "src_ip_bytes": get("orig_ip_bytes", 0), "dst_pkts":  get("resp_pkts", 0),
        "dst_ip_bytes": get("resp_ip_bytes", 0),
        "dns_query": "-", "dns_qclass": "-", "dns_qtype": "-", "dns_rcode": "-",
        "dns_AA": "F", "dns_RD": "F", "dns_RA": "F", "dns_rejected": "F",
        "ssl_version": "-", "ssl_cipher": "-", "ssl_subject": "-", "ssl_issuer": "-",
        "ssl_resumed": "F", "ssl_established": "F",
        "http_trans_depth": 0, "http_method": "-", "http_uri": "-", "http_version": "-",
        "http_request_body_len": 0, "http_response_body_len": 0, "http_status_code": 0,
        "http_user_agent": "-", "http_orig_mime_types": "-", "http_resp_mime_types": "-",
        "weird_name": "-", "weird_addl": "-", "weird_notice": "F",
        "mqtt_topic_len": 0, "mqtt_payload_len": 0, "mqtt_operation": 0,
    }

    for col in NUMERIC_COLS:
        try: features[col] = float(features[col])
        except (ValueError, TypeError): features[col] = 0.0

    uid_idx = col_map.get("uid")
    if uid_idx is not None and uid_idx < len(parts):
        features.update(side_cache.get(parts[uid_idx]))

    return pd.DataFrame([features])


def init_detection_log(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "src_ip", "dst_ip", "label", "tier", "confidence"])


def write_detection(path, src, dst, label, tier, conf):
    with open(path, "a", newline="") as f:
        csv.writer(f).writerow([datetime.now().isoformat(), src, dst, label, tier, f"{conf:.4f}"])


def classify_and_log(inferencer, model_name, df, src, dst):
    """Run inference on one connection row, print the result, and save it to the log."""
    result = inferencer.predict(df, model=model_name)
    row    = result.iloc[0]
    
    # --- THE THRESHOLD OVERRIDE FIX ---
    # We bypass the model's default 0.5 label and test our custom 0.003 threshold directly.
    prob_attack = float(row.get("prob_attack", 0.0))
    prob_normal = float(row.get("prob_normal", 1.0))
    
    if prob_attack >= HIGH_CONF:
        label = "attack"
        tier  = "ALERT"
        conf  = prob_attack
        print(f"[ALERT]   Attack detected  | {src} -> {dst} | Confidence: {conf*100:.1f}%")
    elif prob_attack >= MED_CONF:
        label = "attack"
        tier  = "WARNING"
        conf  = prob_attack
        print(f"[WARNING] Suspicious traffic | {src} -> {dst} | Confidence: {conf*100:.1f}%")
    else:
        label = "normal"
        tier  = "NORMAL"
        conf  = prob_normal
        print(f"[NORMAL]  Traffic OK       | {src} -> {dst}")
        
    write_detection(LOG_FILE, src, dst, label, tier, conf)


def main():
    available_models = {
        name: os.path.join(MODEL_DIR, f"{name}_final_model.pkl")
        for name in ("xgb", "dt", "rf")
        if os.path.exists(os.path.join(MODEL_DIR, f"{name}_final_model.pkl"))
    }
    if not available_models:
        log.error("No model .pkl files found in %s.", MODEL_DIR)
        raise SystemExit(1)
    
    active_model = MODEL_NAME if MODEL_NAME in available_models else next(iter(available_models))
    log.info("Loading models from %s...", MODEL_DIR)
    
    ActiveInferencer = TONIoTInferencer
    log.info("Using Group Zero's newly trained TONIoTInferencer models.")

    inferencer = ActiveInferencer(
        model_paths=available_models,
        feature_names_path=FEATURES_PATH,
        label_encoder_path=os.environ.get("LABEL_ENCODER_PATH",
                           os.path.join(MODEL_DIR, "label_encoder.pkl")),
    )
    log.info("Active model : %s", active_model)
    log.info("Alert at     : >= %.2f%% confidence", HIGH_CONF * 100)
    log.info("Warning at   : >= %.2f%% confidence", MED_CONF * 100)

    waited = 0
    while not os.path.exists(MQTT_LOG) and not os.path.exists(CONN_LOG):
        time.sleep(1)
        waited += 1
        if waited % 5 == 0:
            log.info("Waiting for Zeek logs in %s... (%ds elapsed)", CAPTURE_DIR, waited)

    primary_log = CONN_LOG  

    init_detection_log(LOG_FILE)
    side_cache = SideLogCache(CAPTURE_DIR)

    if os.path.exists(primary_log):
        col_map = parse_zeek_header(primary_log)
    else:
        col_map = None
    if not col_map:
        log.info("conn.log not yet present — using default field positions")
        default_fields = [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
            "tunnel_parents",
        ]
        col_map = {name: idx for idx, name in enumerate(default_fields)}

    log.info("Watching %s for new entries (model=%s)...\n", primary_log, active_model)

    last_heartbeat = time.time()
    last_size      = 0

    # Open the live log and jump to the very end instantly
    
    conn_f = open(primary_log, "r") if os.path.exists(primary_log) else None
    if conn_f:
        conn_f.seek(0, 2)  # Jump to the end of the file
        last_size = os.path.getsize(primary_log)
    else:
        last_size = 0 

    while True:
        if os.path.exists(primary_log):
            current_size = os.path.getsize(primary_log)
            if conn_f is None:
                conn_f = open(primary_log, "r")
                conn_f.seek(0, 2)
                last_size = current_size
            elif current_size < last_size:
                log.info("conn.log rewritten (SIGHUP) — rereading all entries")
                conn_f.close()
                conn_f = open(primary_log, "r")
                last_size = current_size

        line = conn_f.readline() if conn_f else ""
        if not line:
            side_cache.refresh_if_needed()
            now = time.time()
            if now - last_heartbeat >= HEARTBEAT_SECS:
                print(f"[IDLE]    No new connections in {HEARTBEAT_SECS}s — monitor running...")
                last_heartbeat = now
            time.sleep(0.05)
            continue

        parts = line.strip().split("\t")
        if len(parts) > 1:
            try:
                ts_idx = col_map.get("ts", 0)
                if ts_idx < len(parts):
                    zeek_ts = float(parts[ts_idx])
                    now = time.time()
                    
                    if now - zeek_ts > STALE_SECS:
                        continue
                        
                    # if now - zeek_ts < 1.0:
                    #     time.sleep(0.15)
            except (ValueError, TypeError):
                pass

        last_heartbeat = time.time()
        if conn_f:
            last_size = os.path.getsize(primary_log)
        side_cache.refresh_if_needed()

        df = parse_conn_line(line, col_map, side_cache)
        if df is None:
            continue

        try:
            src = str(df["src_ip"].iloc[0])
            dst = str(df["dst_ip"].iloc[0])
            classify_and_log(inferencer, active_model, df, src, dst)
        except Exception as e:
            log.error("Inference error: %s", e)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped.")
    except Exception as e:
        log.error("Fatal error in main(): %s", e)
        import time as _time
        _time.sleep(5)
        main()