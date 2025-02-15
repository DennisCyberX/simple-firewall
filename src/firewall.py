import json
import logging
from scapy.all import sniff, IP, TCP

# Configure logging
logging.basicConfig(filename='logs/firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Load firewall rules
def load_rules():
    with open('src/rules.json', 'r') as file:
        return json.load(file)

# Apply firewall rules
def apply_firewall_rules(packet):
    rules = load_rules()
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        for rule in rules:
            if dst_port == rule['port']:
                action = rule['action']
                if action == "block":
                    logging.warning(f"Blocked traffic from {src_ip} to {dst_ip}:{dst_port}")
                    print(f"🚫 Blocked traffic from {src_ip} to {dst_ip}:{dst_port}")
                elif action == "allow":
                    logging.info(f"Allowed traffic from {src_ip} to {dst_ip}:{dst_port}")
                    print(f"✅ Allowed traffic from {src_ip} to {dst_ip}:{dst_port}")

# Start firewall
def start_firewall(interface="eth0"):
    print(f"🔥 Starting Firewall on interface {interface}...")
    sniff(iface=interface, prn=apply_firewall_rules, store=False)

if __name__ == "__main__":
    start_firewall()
