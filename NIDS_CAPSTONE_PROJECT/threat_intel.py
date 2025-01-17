import random

def check_threat_intelligence(ip):
    """
    Simulates checking an IP address against a threat intelligence database.
    Returns whether the IP is malicious and its severity.
    """
    print(f"[Mock ThreatIntel] Simulating threat check for IP: {ip}")
    
    # Simulated logic: Randomly determine if the IP is malicious
    is_malicious = random.choice([True, False])
    severity = random.choice(['Low', 'Medium', 'High']) if is_malicious else None

    return is_malicious, severity
