from scapy.all import *

def packet_callback(packet):
    print(f"[*] Packet: {packet.summary()}")

def start_sniffer(interface, timeout=30):
    print(f"Starting packet sniffer on {interface} for {timeout} seconds...")
    sniff(iface=interface, prn=packet_callback, store=0, filter="ip", timeout=timeout)
    print("Finished packet sniffing.")
if __name__ == "__main__":
    network_interface = 'Wi-Fi'  
    start_sniffer(network_interface, timeout=30)  
