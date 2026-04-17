from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
import os
import warnings

warnings.filterwarnings("ignore")

app = Flask(__name__)

# ===================== LOAD MODEL =====================
MODEL_PATH = "model.pkl"

model = None
le = None
scaler = None
pca = None
MODEL_LOADED = False

if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        model_data = pickle.load(f)

    if isinstance(model_data, dict):
        model  = model_data.get("model")
        le     = model_data.get("labels")
        scaler = model_data.get("scaler")
        pca    = model_data.get("pca")
    else:
        model = model_data

    MODEL_LOADED = True

    expected_features = scaler.n_features_in_ if scaler else "Unknown"

    print(f"✅ model.pkl loaded — expects {expected_features} features, "
          f"scaler={'yes' if scaler else 'NO'}, pca={'yes' if pca else 'NO'}")
else:
    print("⚠️ model.pkl not found — DEMO mode")


# ===================== BUILD FEATURE VECTOR =====================
def build_feature_vector(data):

    pkts  = max(float(data.get("pktsFlow", 1)), 1)
    bflow = float(data.get("bytesFlow", 0))
    avg_p = bflow / pkts

    # -------- NUMERIC (14) --------
    numeric = [
        float(data.get("srcPort", 443)),
        float(data.get("dstPort", 80)),
        float(data.get("pktSize", 512)),
        float(data.get("payloadLen", 480)),
        float(data.get("flowDur", 3000)),
        bflow,
        pkts,
        avg_p,
        float(data.get("interArrival", 10)),
        float(data.get("pktRate", 50)),
        float(data.get("uniqueSrc", 1)),
        float(data.get("uniqueDst", 1)),
        float(data.get("anomScore", 0.1)),
        float(data.get("attackDur", 0)),
    ]

    # -------- PROTOCOL (2) --------
    proto = data.get("protocol", "TCP").upper()
    protocol_icmp = 1 if proto == "ICMP" else 0
    protocol_udp  = 1 if proto == "UDP" else 0

    # -------- DEVICE (5 possible, but safe) --------
    dev = data.get("deviceType", "")
    device_camera     = 1 if dev == "Camera" else 0
    device_router     = 1 if dev == "Router" else 0
    device_sensor     = 1 if dev == "Sensor" else 0
    device_smarttv    = 1 if dev == "Smart TV" else 0
    device_thermostat = 1 if dev == "Thermostat" else 0

    # -------- OS (2 possible, but safe) --------
    os_str = data.get("operatingSystem", "")
    os_linux   = 1 if os_str == "Linux" else 0
    os_windows = 1 if os_str == "Windows" else 0

    # -------- FIRMWARE --------
    fw = float(data.get("firmwareEncoded", 0))

    # -------- RAW VECTOR --------
    full_vec = (
        numeric +
        [protocol_icmp, protocol_udp] +
        [device_camera, device_router, device_sensor, device_smarttv, device_thermostat] +
        [os_linux, os_windows] +
        [fw]
    )

    X = np.array(full_vec)

    # ===================== 🔥 AUTO FIX =====================
    if scaler:
        expected = scaler.n_features_in_

        if len(X) > expected:
            X = X[:expected]  # trim extra
        elif len(X) < expected:
            X = np.pad(X, (0, expected - len(X)))  # pad missing

    X = X.reshape(1, -1)

    print("FINAL shape:", X.shape)

    # -------- APPLY SCALER + PCA --------
    if scaler:
        X = scaler.transform(X)
    if pca:
        X = pca.transform(X)

    return X


# ===================== DEMO MODE =====================
def demo_classify(data):
    score = 0
    pkt_rate = float(data.get("pktRate", 50))
    anom = float(data.get("anomScore", 0.1))

    if anom > 0.6: score += 4
    if pkt_rate > 800: score += 3

    if score >= 5:
        return "Attack", 90
    elif score >= 3:
        return "Suspicious", 65
    else:
        return "Normal", 95


# ===================== ROUTES =====================
@app.route("/")
def index():
    return render_template("index.html", model_loaded=MODEL_LOADED)


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        if MODEL_LOADED:

            if scaler is None or pca is None:
                return jsonify({
                    "status": "error",
                    "message": "Scaler/PCA missing. Re-export model.pkl"
                }), 400

            X = build_feature_vector(data)

            y_pred = model.predict(X)[0]

            if le:
                label = le.inverse_transform([y_pred])[0]
            else:
                label = str(y_pred)

            if hasattr(model, "predict_proba"):
                conf = round(max(model.predict_proba(X)[0]) * 100)
            else:
                conf = 85

            status = "ok"
            
        else:
            label, conf = demo_classify(data)
            status = "ok"

        # ===================== SAVE TO LOGS =====================
        try:
            log_dir = "logs"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            log_file = os.path.join(log_dir, "prediction_history.csv")
            is_new = not os.path.exists(log_file)
            
            with open(log_file, "a") as f:
                if is_new:
                    f.write("timestamp,label,confidence,is_attack,model\n")
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')},{label},{conf},{label.lower() != 'normal'},{type(model).__name__ if MODEL_LOADED else 'Demo'}\n")
        except Exception as log_err:
            print(f"Logging error: {log_err}")

        return jsonify({
            "label": label,
            "confidence": conf,
            "is_attack": label.lower() != "normal",
            "model": type(model).__name__ if MODEL_LOADED else "Demo",
            "status": "ok"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ===================== REAL LIVE CAPTURE (SCAPY) =====================
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
import collections

live_data_queue = []
is_capturing = False

# Stateful tracking for flows
flows = collections.defaultdict(lambda: {
    'start_time': time.time(),
    'bytes': 0,
    'packets': 0,
    'src_ips': set(),
    'dst_ips': set()
})

def packet_callback(pkt):
    global is_capturing, live_data_queue, flows
    if not is_capturing:
        return
    
    try:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_str = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ("ICMP" if ICMP in pkt else "Other"))
            
            src_port = pkt.sport if (TCP in pkt or UDP in pkt) else 0
            dst_port = pkt.dport if (TCP in pkt or UDP in pkt) else 0
            pkt_size = len(pkt)
            payload_len = len(pkt[IP].payload)
            
            # Update flow stats
            flow_key = (src_ip, dst_ip, src_port, dst_port, proto_str)
            flow = flows[flow_key]
            flow['packets'] += 1
            flow['bytes'] += pkt_size
            flow['src_ips'].add(src_ip)
            flow['dst_ips'].add(dst_ip)
            
            duration = (time.time() - flow['start_time']) * 1000 # ms
            
            # Map real packet to model features
            data = {
                "srcPort": src_port,
                "dstPort": dst_port,
                "pktSize": pkt_size,
                "payloadLen": payload_len,
                "flowDur": duration,
                "bytesFlow": flow['bytes'],
                "pktsFlow": flow['packets'],
                "interArrival": 10, # default
                "pktRate": flow['packets'] / (duration/1000) if duration > 0 else 0,
                "uniqueSrc": len(flow['src_ips']),
                "uniqueDst": len(flow['dst_ips']),
                "anomScore": 0.1,
                "attackDur": 0,
                "protocol": proto_str,
                "deviceType": "Smart Speaker", # Baseline for real capture
                "operatingSystem": "Linux",
                "firmwareEncoded": 0
            }
            
            # Use the existing predict logic
            if MODEL_LOADED and scaler and pca:
                X = build_feature_vector(data)
                y_pred = model.predict(X)[0]
                label = le.inverse_transform([y_pred])[0] if le else str(y_pred)
                conf = round(max(model.predict_proba(X)[0]) * 100) if hasattr(model, "predict_proba") else 85
            else:
                label, conf = demo_classify(data)
                
            # ===================== SAVE TO LOGS =====================
            try:
                log_dir = "logs"
                if not os.path.exists(log_dir): os.makedirs(log_dir)
                log_file = os.path.join(log_dir, "prediction_history.csv")
                is_new = not os.path.exists(log_file)
                with open(log_file, "a") as f:
                    if is_new: f.write("timestamp,label,confidence,is_attack,model\n")
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')},{label},{conf},{label.lower() != 'normal'},Real-time\n")
            except: pass

            result = {
                "label": label,
                "confidence": conf,
                "is_attack": label.lower() != "normal",
                "model": "Real-time (Scapy)",
                "timestamp": time.strftime("%H:%M:%S"),
                "details": f"{src_ip} -> {dst_ip} ({proto_str})"
            }
            
            live_data_queue.append(result)
            if len(live_data_queue) > 50:
                live_data_queue.pop(0)
                
    except Exception as e:
        print(f"Packet error: {e}")

def sniffer_thread():
    global is_capturing
    try:
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not is_capturing)
    except Exception as e:
        print(f"Sniffer failed: {e}. (Are you running as Admin?)")
        is_capturing = False

@app.route("/start")
def start_capture():
    global is_capturing, flows, live_data_queue
    if not is_capturing:
        is_capturing = True
        flows.clear()
        live_data_queue.clear()
        thread = threading.Thread(target=sniffer_thread)
        thread.daemon = True
        thread.start()
    return jsonify({"status": "started"})

@app.route("/stop")
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({"status": "stopped"})

@app.route("/live")
def get_live_data():
    return jsonify(live_data_queue)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)