from scapy.all import sniff
from scapy.layers.inet import IP

print("=" * 60)
print("NetScope - Basic Network Sniffer")
print("=" * 60)

def packet_callback(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\nPacket Captured")
        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")
        print(f"Protocol       : {protocol}")

print("\nCapturing 10 packets...\n")

sniff(prn=packet_callback, count=10)

print("\nCapture Complete")