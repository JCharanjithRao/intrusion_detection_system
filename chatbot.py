import re

def chatbot_response(user_message, recent_alerts):
    msg = user_message.lower().strip()

    # Count stats
    total = len(recent_alerts)
    threats = sum(1 for a in recent_alerts if 'THREAT' in a.get('status', ''))
    safe = total - threats

    # Greetings
    if any(w in msg for w in ['hi', 'hello', 'hey', 'sup']):
        return "👋 Hello! I'm CyberBot, your AI security assistant. Ask me about network threats, attack types, or current system status!"

    # Status check
    elif any(w in msg for w in ['status', 'safe', 'secure', 'ok', 'fine']):
        if threats == 0:
            return f"🟢 All clear! No threats detected so far. System is secure and monitoring {total} network events."
        else:
            return f"🔴 Alert! {threats} threat(s) detected out of {total} total scans. Immediate attention recommended!"

    # Threat count
    elif any(w in msg for w in ['how many', 'count', 'number', 'total']):
        return f"📊 Statistics:\n• Total scans: {total}\n• Threats detected: {threats}\n• Safe traffic: {safe}"

    # DDoS explanation
    elif 'ddos' in msg:
        return "💥 DDoS (Distributed Denial of Service) is an attack where hackers flood your network with massive traffic to crash it. Signs: huge src_bytes, very short duration, high connection count."

    # Port scan explanation
    elif 'port scan' in msg or 'scanning' in msg:
        return "🔍 Port Scanning is when attackers probe your network to find open ports and vulnerabilities. Signs: zero bytes transferred, ICMP protocol, many connections."

    # Brute force explanation
    elif 'brute' in msg or 'brute force' in msg or 'login' in msg:
        return "🔑 Brute Force attacks repeatedly try passwords to gain access. Signs: repeated SSH/FTP/Telnet connection attempts with failed logins."

    # Latest alert
    elif any(w in msg for w in ['latest', 'last', 'recent', 'new']):
        if recent_alerts:
            a = recent_alerts[0]
            return f"🕐 Latest Alert:\nStatus: {a.get('status')}\nType: {a.get('type')}\nSeverity: {a.get('severity')}\nAction: {a.get('recommendation')}"
        return "No alerts recorded yet. Try simulating IoT traffic first!"

    # What can you do
    elif any(w in msg for w in ['help', 'what can', 'commands', 'features']):
        return """🤖 I can help you with:
- Network status check → 'is my network safe?'
- Threat statistics → 'how many threats?'
- Attack explanations → 'what is ddos?'
- Latest alerts → 'show latest alert'
- Security tips → 'give me security tips'"""

    # Security tips
    elif any(w in msg for w in ['tip', 'tips', 'advice', 'suggest', 'recommend']):
        return """🛡️ Security Tips:
1. Always use strong passwords on IoT devices
2. Keep firmware updated regularly
3. Segment IoT devices on separate network
4. Monitor unusual traffic spikes
5. Enable 2FA on all critical services"""

    # Protocol questions
    elif 'tcp' in msg:
        return "🌐 TCP (Transmission Control Protocol) is a reliable connection-based protocol. Most attacks use TCP because it establishes persistent connections."
    elif 'udp' in msg:
        return "📡 UDP (User Datagram Protocol) is faster but less reliable. Often used in DNS and streaming, but also in UDP flood attacks."
    elif 'icmp' in msg:
        return "📶 ICMP is used for network diagnostics (like ping). Port scanning often uses ICMP to probe networks silently."

    # Unknown
    else:
        return f"🤔 I'm not sure about '{user_message}'. Try asking about: network status, threats, DDoS, port scanning, brute force, or security tips!"