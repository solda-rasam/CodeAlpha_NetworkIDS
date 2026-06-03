import sys
import os
from scapy.all import sniff, IP, TCP

def load_snort_rules(rule_file):
    rules = []
    if not os.path.exists(rule_file):
        with open(rule_file, 'w', encoding='utf-8') as f:
            f.write('alert tcp any any -> any any (msg:"Snort ALERT: Potential Port Scanning Detected"; flags:S; sid:1000001;)\n')
            
    with open(rule_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith("alert"):
                msg = line.split('msg:')[1].split(';')[0].replace('"', '')
                flag = line.split('flags:')[1].split(';')[0] if 'flags:' in line else None
                rules.append({"msg": msg, "flag": flag})
    return rules

SNORT_RULES = load_snort_rules("snort.rules")

def analyze_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        
        for rule in SNORT_RULES:
            if rule["flag"] == "S" and packet[TCP].flags == "S":
                print("\n" + "="*60)
                print(f"[!!!] {rule['msg']}")
                print(f"    [Snort Match] Attacker IP: {src_ip} -> Destination: {dst_ip}:{dst_port}")
                print("="*60 + "\n")

def main():
    print("[*] Network Intrusion Detection System (NIDS) Powered by Snort Rules...")
    print("[*] Successfully loaded rules from 'snort.rules'.")
    print("[*] Continuously monitoring live network traffic... (Press Ctrl+C to stop)")
    
    try:
        sniff(prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping Snort NIDS Engine. System Secured.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Error: Access Denied. Administrator privileges required.")
        sys.exit(1)

if __name__ == "__main__":
    main()