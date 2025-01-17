from datetime import datetime
from scapy.all import sniff, send, IP, ICMP
from db_setup import TrafficLog, AttackLog, session
from threat_intel import check_threat_intelligence
from email_alert import send_email_alert

def block_packet(ip):
    """Simulates packet blocking by sending an ICMP unreachable."""
    print(f"[BLOCKING] Dropping traffic from {ip}.")
    pkt = IP(src=ip, dst="192.168.0.1") / ICMP(type=3, code=1)  # Destination unreachable
    send(pkt, verbose=False)

def process_packet(packet):
    try:
        src_ip = packet[0][1].src
        dest_ip = packet[0][1].dst
        protocol = packet[0].name
        packet_size = len(packet)
        timestamp = datetime.now()

        print(f"Packet captured: {src_ip} -> {dest_ip} ({protocol}, {packet_size} bytes)")

        # Insert traffic log into the database
        traffic_entry = TrafficLog(
            src_ip=src_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            packet_size=packet_size,
            timestamp=timestamp
        )
        session.add(traffic_entry)
        session.commit()

        # Threat intelligence check
        is_malicious, severity = check_threat_intelligence(src_ip)
        if is_malicious:
            alert_message = f"Malicious traffic detected from {src_ip}!"
            print(f"[ALERT] {alert_message}")
            attack_entry = AttackLog(
                src_ip=src_ip,
                dest_ip=dest_ip,
                alert_message=alert_message,
                severity=severity,
                timestamp=timestamp
            )
            session.add(attack_entry)
            session.commit()

            # Block malicious traffic
            block_packet(src_ip)

            # Send email alert for high-severity threats
            if severity == 'High':
                subject = "High-Severity Malicious Traffic Detected!"
                body = f"Alert: {alert_message}\nSeverity: {severity}\nTime: {timestamp}\nDestination: {dest_ip}"
                send_email_alert(subject, body, "sayeedshirur@gmail.com")  # Replace with recipient's email

    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    print("Starting packet capture...")
    sniff(prn=process_packet, store=False)