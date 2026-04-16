# realtime_detector.py
# Real-time Network Intrusion Detection Backend

import time
import pickle
import numpy as np
from flask import Flask, jsonify
from threading import Thread, Lock

# Scapy import with error handling
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"[WARNING] Scapy unavailable: {e}")

app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
MODEL_PATH    = "model/intrusion_model.pkl"
PACKET_WINDOW = 50       # packets per analysis window
TIME_WINDOW   = 5        # seconds per analysis window
INTERFACE     = None     # None = auto-detect default interface

# ─────────────────────────────────────────
# LOAD MODEL
# ─────────────────────────────────────────
def load_model(path: str):
    try:
        with open(path, "rb") as f:
            model = pickle.load(f)
        print("[OK] Model loaded successfully.")
        return model
    except FileNotFoundError:
        print(f"[ERROR] Model not found at {path}")
        return None

model = load_model(MODEL_PATH)

# ─────────────────────────────────────────
# PROTOCOL MAP
# ─────────────────────────────────────────
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

def map_protocol(proto_num: int) -> str:
    return PROTO_MAP.get(proto_num, "other")

# ─────────────────────────────────────────
# PACKET CAPTURE
# ─────────────────────────────────────────
def capture_packets(max_packets: int = PACKET_WINDOW,
                    timeout: int = TIME_WINDOW) -> list:
    """
    Capture live packets using Scapy.
    Returns list of raw packets.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not available on this system.")
    try:
        packets = sniff(
            count=max_packets,
            timeout=timeout,
            iface=INTERFACE,
            filter="ip",          # Only capture IP packets
            store=True
        )
        print(f"[CAPTURE] Captured {len(packets)} packets.")
        return list(packets)
    except PermissionError:
        raise RuntimeError("Permission denied. Run as Administrator/root.")
    except Exception as e:
        raise RuntimeError(f"Capture failed: {e}")

# ─────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────
def extract_features(packets: list) -> dict:
    """
    Extract ML-ready features from a list of packets.
    Returns feature dict.
    """
    if not packets:
        raise ValueError("No packets to extract features from.")

    protocol_counts = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
    total_src_bytes = 0
    total_dst_bytes = 0
    timestamps = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        proto_name = map_protocol(ip_layer.proto)
        protocol_counts[proto_name] += 1

        pkt_size = len(pkt)
        total_src_bytes += pkt_size
        total_dst_bytes += pkt_size   # approximation

        timestamps.append(float(pkt.time))

    # Duration = time between first and last packet
    duration = round(max(timestamps) - min(timestamps), 4) \
               if len(timestamps) >= 2 else 0.0

    # Dominant protocol
    dominant_proto = max(protocol_counts, key=protocol_counts.get)

    # Counts
    total_pkts = len(packets)
    conn_count = total_pkts
    srv_count  = max(1, total_pkts // 2)

    return {
        "protocol_type":       dominant_proto,
        "src_bytes":           total_src_bytes,
        "dst_bytes":           total_dst_bytes,
        "duration":            duration,
        "count":               conn_count,
        "srv_count":           srv_count,
        "dst_host_count":      min(conn_count * 2, 255),
        "dst_host_srv_count":  min(srv_count * 2, 255),
        "protocol_breakdown":  protocol_counts,
        "total_packets":       total_pkts,
    }

# ─────────────────────────────────────────
# FEATURE ENCODING (for ML model)
# ─────────────────────────────────────────
PROTOCOL_MAP_INT = {"tcp": 0, "udp": 1, "icmp": 2, "other": 0}
SERVICE_DEFAULT  = 0   # http
FLAG_DEFAULT     = 0   # SF

def encode_features(feat: dict) -> np.ndarray:
    """
    Encode extracted features into the 41-column
    vector the Random Forest model expects.
    """
    proto_int = PROTOCOL_MAP_INT.get(feat["protocol_type"], 0)

    vector = [
        feat["duration"],           # 0
        proto_int,                  # 1 - protocol_type
        SERVICE_DEFAULT,            # 2 - service
        FLAG_DEFAULT,               # 3 - flag
        feat["src_bytes"],          # 4
        feat["dst_bytes"],          # 5
        0, 0, 0, 0,                 # 6-9
        0,                          # 10 - num_failed_logins
        1,                          # 11 - logged_in
        0, 0, 0, 0, 0, 0, 0, 0,    # 12-19
        0, 0,                       # 20-21
        feat["count"],              # 22
        feat["srv_count"],          # 23
        0, 0, 0, 0,                 # 24-27
        1, 0, 0,                    # 28-30
        feat["dst_host_count"],     # 31
        feat["dst_host_srv_count"], # 32
        1, 0, 0, 0, 0, 0, 0, 0     # 33-40
    ]
    return np.array(vector, dtype=float).reshape(1, -1)

# ─────────────────────────────────────────
# PREDICTION
# ─────────────────────────────────────────
def predict(encoded: np.ndarray) -> dict:
    """
    Run ML prediction on encoded feature vector.
    Returns prediction label and confidence score.
    """
    if model is None:
        raise RuntimeError("Model is not loaded.")

    label      = model.predict(encoded)[0]
    proba      = model.predict_proba(encoded)[0]
    confidence = round(float(max(proba)) * 100, 2)

    return {
        "prediction": label,
        "confidence": confidence,
        "is_attack":  label == "attack"
    }

# ─────────────────────────────────────────
# PIPELINE: capture → extract → encode → predict
# ─────────────────────────────────────────
def run_pipeline() -> dict:
    """
    Full real-time detection pipeline.
    Returns combined result dict.
    """
    start = time.time()

    # Step 1: Capture
    packets = capture_packets()

    if not packets:
        return {
            "error": "No packets captured. Check network interface or permissions.",
            "success": False
        }

    # Step 2: Extract features
    features = extract_features(packets)

    # Step 3: Encode for model
    encoded = encode_features(features)

    # Step 4: Predict
    result = predict(encoded)

    elapsed = round(time.time() - start, 3)

    return {
        "success":    True,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "is_attack":  result["is_attack"],
        "features":   features,
        "latency_s":  elapsed
    }

# ─────────────────────────────────────────
# FLASK API
# ─────────────────────────────────────────
@app.route("/analyze", methods=["GET"])
def analyze():
    """
    GET /analyze
    Captures live packets, runs prediction, returns JSON.
    """
    try:
        result = run_pipeline()
        status = 200 if result.get("success") else 500
        return jsonify(result), status

    except RuntimeError as e:
        return jsonify({
            "success": False,
            "error":   str(e)
        }), 500

    except Exception as e:
        return jsonify({
            "success": False,
            "error":   f"Unexpected error: {str(e)}"
        }), 500

@app.route("/health", methods=["GET"])
def health():
    """GET /health — quick system check"""
    return jsonify({
        "status":          "online",
        "model_loaded":    model is not None,
        "scapy_available": SCAPY_AVAILABLE,
        "packet_window":   PACKET_WINDOW,
        "time_window_s":   TIME_WINDOW
    })

# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  CyberGuard Real-Time Detection API")
    print("=" * 50)
    print(f"  Model loaded  : {model is not None}")
    print(f"  Scapy ready   : {SCAPY_AVAILABLE}")
    print(f"  Packet window : {PACKET_WINDOW} packets")
    print(f"  Time window   : {TIME_WINDOW}s")
    print(f"  Endpoint      : GET /analyze")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5001, debug=False)