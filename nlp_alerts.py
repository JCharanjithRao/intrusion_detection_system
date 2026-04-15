def generate_alert(prediction, confidence, network_data):
    """
    Converts raw AI prediction into human-readable alert messages
    """
    
    protocol = network_data.get('protocol_type', 'Unknown')
    service = network_data.get('service', 'Unknown')
    src_bytes = network_data.get('src_bytes', 0)
    dst_bytes = network_data.get('dst_bytes', 0)
    duration = network_data.get('duration', 0)

    if prediction == 'attack':
        # Determine attack type based on network characteristics
        if src_bytes > 10000 and duration < 2:
            attack_type = "DDoS (Distributed Denial of Service)"
            recommendation = "Block the source IP immediately and rate-limit incoming traffic."
        elif src_bytes == 0 and dst_bytes == 0:
            attack_type = "Port Scanning"
            recommendation = "Enable firewall rules to block suspicious scanning activity."
        elif service in ['ftp', 'ssh', 'telnet']:
            attack_type = "Brute Force Login Attempt"
            recommendation = "Enable multi-factor authentication and block repeated login failures."
        else:
            attack_type = "Suspicious Network Intrusion"
            recommendation = "Investigate the source IP and monitor network traffic closely."

        alert = {
            'status': '🔴 THREAT DETECTED',
            'type': attack_type,
            'confidence': f"{confidence:.1f}%",
            'details': (
                f"Suspicious activity detected over {protocol} protocol "
                f"on {service} service. "
                f"Data transferred: {src_bytes} bytes sent, "
                f"{dst_bytes} bytes received over {duration} seconds."
            ),
            'recommendation': recommendation,
            'severity': get_severity(confidence)
        }

    else:
        alert = {
            'status': '🟢 NETWORK NORMAL',
            'type': 'No Threat Detected',
            'confidence': f"{confidence:.1f}%",
            'details': (
                f"Network traffic over {protocol} protocol "
                f"on {service} service appears normal. "
                f"Data transferred: {src_bytes} bytes sent, "
                f"{dst_bytes} bytes received over {duration} seconds."
            ),
            'recommendation': 'No action needed. Continue monitoring.',
            'severity': 'None'
        }

    return alert


def get_severity(confidence):
    """Returns severity level based on confidence score"""
    if confidence >= 90:
        return '🔴 CRITICAL'
    elif confidence >= 75:
        return '🟠 HIGH'
    elif confidence >= 60:
        return '🟡 MEDIUM'
    else:
        return '🟢 LOW'


def format_alert_message(alert):
    """Formats alert into readable text message"""
    message = f"""
    ╔══════════════════════════════════════╗
           INTRUSION DETECTION ALERT
    ╚══════════════════════════════════════╝

    Status      : {alert['status']}
    Threat Type : {alert['type']}
    Severity    : {alert['severity']}
    Confidence  : {alert['confidence']}

    Details:
    {alert['details']}

    Recommended Action:
    ➡️  {alert['recommendation']}

    ════════════════════════════════════════
    """
    return message