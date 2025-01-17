import subprocess
import re

def capture_and_analyze():
    # Start Tshark to capture packets in real-time
    process = subprocess.Popen(
        ["tshark", "-i", "1", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "frame.len", "-e", "ip.proto"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    print("Capturing packets in real-time... Press Ctrl+C to stop.")
    try:
        for line in iter(process.stdout.readline, b""):
            decoded_line = line.decode().strip()
            if decoded_line:
                analyze_packet(decoded_line)
    except KeyboardInterrupt:
        print("\nStopped packet capture.")
        process.terminate()

def analyze_packet(packet_line):
    # Parse packet details (source IP, destination IP, length, protocol)
    packet_data = packet_line.split("\t")
    if len(packet_data) >= 4:
        src_ip, dest_ip, length, protocol = packet_data
        print(f"Packet Captured: {src_ip} -> {dest_ip}, Length: {length}, Protocol: {protocol}")
        
        # Example: Detect abnormally large packets
        if int(length) > 1500:
            print("[ALERT] Large Packet Detected!")
        
        # Example: Flag specific protocols (6 = TCP, 17 = UDP)
        if protocol == "6":
            print("[INFO] TCP traffic observed.")

if __name__ == "__main__":
    capture_and_analyze()
