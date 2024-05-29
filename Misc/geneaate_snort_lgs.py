import random
from datetime import datetime, timedelta

# Sample alerts and classifications
alerts = [
    ("SQL Injection Attempt", "Web Application Attack"),
    ("Possible DDoS Attack", "Attempted Denial of Service"),
    ("SSH Brute Force Attempt", "Attempted Information Leak"),
    ("Potential Malware Download", "Malware Traffic"),
    ("Port Scan Detected", "Attempted Information Leak"),
    ("Unauthorized Access Attempt", "Attempted Admin Privilege Gain")
]

# Function to generate a random IP address
def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

# Function to generate a random port
def generate_port():
    return random.randint(1, 65535)

# Generate a timestamp starting from now and increasing
start_time = datetime.now()

# Open a file to write
with open('snort_alerts_generated.txt', 'w') as file:
    for i in range(30):
        # Choose a random alert
        alert, classification = random.choice(alerts)

        # Generate source and destination IP and ports
        src_ip = generate_ip()
        dst_ip = generate_ip()
        src_port = generate_port()
        dst_port = generate_port()

        # Timestamp
        timestamp = (start_time + timedelta(minutes=i)).strftime("%m/%d-%H:%M:%S.%f")[:-3]

        # Write entry
        file.write(f"[**] [1:{1000000+i}:1] \"{alert}\" [**]\n")
        file.write(f"[Classification: {classification}] [Priority: {random.randint(1, 3)}]\n")
        file.write(f"{timestamp} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
        file.write("TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:1500 DF\n")
        file.write("***AP*** Seq: 0x1A2B3C4D Ack: 0x1A2B3C4D Win: 0x2000 TcpLen: 32\n")
        file.write(f"[Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-{random.randint(1000, 9999)}]\n")
        file.write("\n")
