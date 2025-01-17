from scapy.all import rdpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import TrafficLog, AttackLog

def load_rules():
    rules = {}
    with open("rules.txt", "r") as file:
        for line in file:
            if line.strip() and not line.startswith("#"):
                key, value = line.strip().split(":")
                rules[key.strip()] = value.strip()
    return rules

def analyze_pcap(file_name):
    rules = load_rules()
    packets = rdpcap(file_name)
    engine = create_engine('sqlite:///nide.db')
    Session = sessionmaker(bind=engine)
    session = Session()

    print(f"Analyzing {len(packets)} packets from {file_name}")
    for packet in packets:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dest_ip = packet["IP"].dst
            packet_size = len(packet)
            protocol = packet["IP"].proto

            # Log traffic
            traffic_log = TrafficLog(src_ip=src_ip, dest_ip=dest_ip, protocol=str(protocol), packet_size=packet_size)
            session.add(traffic_log)
            session.commit()

            # Apply detection rules
            if packet_size > int(rules["large_packet"]):
                alert_message = f"Large packet detected: {packet_size} bytes"
                print(alert_message)
                session.add(AttackLog(alert_message=alert_message, src_ip=src_ip, dest_ip=dest_ip))
                session.commit()

            if str(protocol) == rules["suspicious_protocol"]:
                alert_message = f"Suspicious protocol detected: {protocol}"
                print(alert_message)
                session.add(AttackLog(src_ip=src_ip, dest_ip=dest_ip, alert_message=alert_message))
                session.commit()

if __name__ == "__main__":
    analyze_pcap("./packets.pcap")
