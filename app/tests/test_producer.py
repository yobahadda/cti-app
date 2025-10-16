# from kafka import Consumer
from confluent_kafka import Consumer
import json
import time
from datetime import datetime
import random

# Configuration
KAFKA_BOOTSTRAP_SERVERS = ['localhost:9092']
TOPIC = 'security-logs'

# Sample log templates
SAMPLE_LOGS = [
    # Phishing attempt
    {
        "timestamp": None,
        "event_type": "email_received",
        "src_ip": "203.0.113.42",
        "dest_ip": "192.168.1.10",
        "action": "blocked",
        "message": "Suspicious email with malicious attachment detected from phishing campaign",
        "attachment": "invoice_malware.exe",
        "sender": "attacker@malicious-domain.com"
    },
    # Command execution
    {
        "timestamp": None,
        "event_type": "process_execution",
        "src_ip": "192.168.1.50",
        "process": "powershell.exe",
        "command_line": "powershell -encodedCommand Base64EncodedMaliciousScript",
        "action": "detected",
        "message": "Suspicious powershell command line execution detected"
    },
    # Ransomware activity
    {
        "timestamp": None,
        "event_type": "file_modification",
        "src_ip": "192.168.1.100",
        "action": "detected",
        "message": "Multiple files encrypted with ransomware, .locked extension added",
        "file_count": 1500,
        "extension": ".locked"
    },
    # C2 Communication
    {
        "timestamp": None,
        "event_type": "network_connection",
        "src_ip": "192.168.1.75",
        "dest_ip": "198.51.100.50",
        "dest_port": 443,
        "protocol": "https",
        "action": "allowed",
        "message": "Suspicious outbound connection to known C2 server detected"
    },
    # Brute force attack
    {
        "timestamp": None,
        "event_type": "authentication_attempt",
        "src_ip": "203.0.113.100",
        "dest_ip": "192.168.1.20",
        "service": "ssh",
        "action": "failed",
        "attempts": 50,
        "message": "Multiple failed SSH authentication attempts from external IP"
    },
    # File hash detection
    {
        "timestamp": None,
        "event_type": "file_scan",
        "src_ip": "192.168.1.30",
        "file_path": "C:\\Users\\victim\\Downloads\\malware.exe",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "action": "quarantined",
        "message": "Malicious file hash detected and quarantined"
    },
    # DNS query to malicious domain
    {
        "timestamp": None,
        "event_type": "dns_query",
        "src_ip": "192.168.1.45",
        "query": "evil-command-control.com",
        "action": "blocked",
        "message": "DNS query to known malicious domain blocked"
    },
    # Lateral movement via RDP
    {
        "timestamp": None,
        "event_type": "rdp_connection",
        "src_ip": "192.168.1.60",
        "dest_ip": "192.168.1.70",
        "username": "compromised_user",
        "action": "detected",
        "message": "Suspicious RDP connection for lateral movement detected"
    }
]

def create_producer():
    """Create Kafka producer"""
    return Consumer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )

def generate_log():
    """Generate a random security log"""
    log = random.choice(SAMPLE_LOGS).copy()
    log['timestamp'] = datetime.utcnow().isoformat()
    log['log_id'] = f"LOG-{int(time.time())}-{random.randint(1000, 9999)}"
    return log

def send_continuous_logs(producer, interval=5):
    """Send logs continuously"""
    print(f"Starting to send logs to topic '{TOPIC}' every {interval} seconds...")
    print("Press Ctrl+C to stop\n")
    
    count = 0
    try:
        while True:
            log = generate_log()
            producer.send(TOPIC, value=log)
            producer.flush()
            
            count += 1
            print(f"[{count}] Sent: {log['event_type']} - {log.get('message', 'N/A')[:60]}...")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print(f"\n\nStopped. Total logs sent: {count}")
    finally:
        producer.close()

def send_batch_logs(producer, num_logs=10):
    """Send a batch of logs"""
    print(f"Sending {num_logs} logs to topic '{TOPIC}'...\n")
    
    for i in range(num_logs):
        log = generate_log()
        producer.send(TOPIC, value=log)
        print(f"[{i+1}/{num_logs}] Sent: {log['event_type']}")
        time.sleep(0.5)
    
    producer.flush()
    print(f"\n✅ Successfully sent {num_logs} logs")
    producer.close()

def send_attack_scenario(producer):
    """Simulate a complete attack scenario"""
    print("Simulating APT attack scenario...\n")
    
    scenarios = [
        ("1. Initial Access - Phishing", {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "email_received",
            "src_ip": "203.0.113.50",
            "dest_ip": "192.168.1.100",
            "action": "delivered",
            "message": "Spearphishing email with malicious attachment delivered",
            "sender": "ceo@fake-company-domain.com",
            "attachment": "Q4_Financial_Report.docx.exe"
        }),
        ("2. Execution - Malware runs", {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "process_execution",
            "src_ip": "192.168.1.100",
            "process": "Q4_Financial_Report.docx.exe",
            "parent_process": "outlook.exe",
            "action": "detected",
            "message": "Suspicious process execution from email attachment"
        }),
        ("3. Command & Control - C2 Beacon", {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "network_connection",
            "src_ip": "192.168.1.100",
            "dest_ip": "198.51.100.25",
            "dest_port": 443,
            "protocol": "https",
            "action": "allowed",
            "message": "Outbound HTTPS connection to suspicious domain c2-server.evil.com"
        }),
        ("4. Credential Access - Mimikatz", {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "credential_dumping",
            "src_ip": "192.168.1.100",
            "process": "mimikatz.exe",
            "action": "detected",
            "message": "Credential dumping tool mimikatz detected accessing LSASS"
        }),
        ("5. Lateral Movement - SMB", {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "smb_connection",
            "src_ip": "192.168.1.100",
            "dest_ip": "192.168.1.50",
            "username": "admin",
            "action": "success",
            "message": "Lateral movement via SMB using compromised admin credentials"
        }),
        ("6. Exfiltration - Large Data Transfer", {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "data_transfer",
            "src_ip": "192.168.1.50",
            "dest_ip": "198.51.100.30",
            "bytes_transferred": 5368709120,
            "protocol": "https",
            "action": "detected",
            "message": "Large volume data exfiltration to external IP detected"
        })
    ]
    
    for step, log in scenarios:
        print(f"{step}")
        producer.send(TOPIC, value=log)
        producer.flush()
        time.sleep(3)
    
    print("\n✅ Attack scenario complete!")
    producer.close()

if __name__ == "__main__":
    import sys
    
    print("="*60)
    print("CTI Kafka Log Producer")
    print("="*60)
    print("\nOptions:")
    print("1. Send continuous logs (Ctrl+C to stop)")
    print("2. Send batch of logs")
    print("3. Simulate attack scenario")
    print()
    
    choice = input("Select option (1-3): ").strip()
    
    try:
        producer = create_producer()
        print("\n✅ Connected to Kafka\n")
        
        if choice == "1":
            interval = input("Enter interval in seconds (default 5): ").strip()
            interval = int(interval) if interval else 5
            send_continuous_logs(producer, interval)
        
        elif choice == "2":
            num = input("Enter number of logs (default 10): ").strip()
            num = int(num) if num else 10
            send_batch_logs(producer, num)
        
        elif choice == "3":
            send_attack_scenario(producer)
        
        else:
            print("Invalid option")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure Kafka is running:")
        print("  docker run -d -p 9092:9092 apache/kafka:latest")
        sys.exit(1)