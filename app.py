import os
from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
from nlp_alerts import generate_alert
from chatbot import chatbot_response
import random

app = Flask(__name__)

# Load the trained model
with open('model/intrusion_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Store recent alerts in memory
recent_alerts = []

# Encoding maps
protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
service_map = {'http': 0, 'ftp': 1, 'ssh': 2, 'smtp': 3,
               'dns': 4, 'telnet': 5, 'other': 6}
flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3, 'SH': 4}

def encode_input(data):
    features = [
        data.get('duration', 0),
        protocol_map.get(data.get('protocol_type', 'tcp'), 0),
        service_map.get(data.get('service', 'http'), 0),
        flag_map.get(data.get('flag', 'SF'), 0),
        data.get('src_bytes', 0),
        data.get('dst_bytes', 0),
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        data.get('count', 1),
        data.get('srv_count', 1),
        0, 0, 0, 0, 1, 0, 0,
        data.get('dst_host_count', 1),
        data.get('dst_host_srv_count', 1),
        1, 0, 0, 0, 0, 0, 0, 0
    ]
    return np.array(features).reshape(1, -1)

@app.route('/')
def home():
    return render_template('index.html', alerts=recent_alerts)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    features = encode_input(data)
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    confidence = max(probabilities) * 100
    alert = generate_alert(prediction, confidence, data)
    recent_alerts.insert(0, alert)
    if len(recent_alerts) > 10:
        recent_alerts.pop()
    return jsonify(alert)

@app.route('/simulate')
def simulate():
    scenarios = [
        {'duration': 1, 'protocol_type': 'tcp', 'service': 'ftp',
         'flag': 'SF', 'src_bytes': 15000, 'dst_bytes': 200,
         'count': 500, 'srv_count': 500,
         'dst_host_count': 255, 'dst_host_srv_count': 255},
        {'duration': 0, 'protocol_type': 'icmp', 'service': 'other',
         'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
         'count': 1, 'srv_count': 1,
         'dst_host_count': 1, 'dst_host_srv_count': 1},
        {'duration': 5, 'protocol_type': 'tcp', 'service': 'http',
         'flag': 'SF', 'src_bytes': 1000, 'dst_bytes': 5000,
         'count': 10, 'srv_count': 10,
         'dst_host_count': 50, 'dst_host_srv_count': 50},
    ]
    scenario = random.choice(scenarios)
    features = encode_input(scenario)
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    confidence = max(probabilities) * 100
    alert = generate_alert(prediction, confidence, scenario)
    recent_alerts.insert(0, alert)
    if len(recent_alerts) > 10:
        recent_alerts.pop()
    return jsonify(alert)

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    message = data.get('message', '')
    response = chatbot_response(message, recent_alerts)
    return jsonify({'response': response})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)