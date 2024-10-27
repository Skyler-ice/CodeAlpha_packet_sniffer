from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    # Check if packet has IP layer
    if packet.haslayer(IP):
        # Get IP details
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\nPacket: {src_ip} --> {dst_ip}")
        
        # Check if it's a TCP packet
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Protocol: TCP | Source Port: {src_port} | Destination Port: {dst_port}")
        
        # Check if it's a UDP packet
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Protocol: UDP | Source Port: {src_port} | Destination Port: {dst_port}")
        else:
            print(f"Protocol: Other (Protocol Number: {protocol})")

def start_sniffing():
    print("Starting network sniffing... Press Ctrl+C to stop.")
    # Start sniffing on the default network interface
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
