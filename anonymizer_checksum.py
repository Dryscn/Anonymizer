import argparse
import random
import ipaddress
from scapy.all import rdpcap, wrpcap, Ether, IP, TCP, UDP, Raw
from scapy.packet import Packet

def read_pcap(file_path):
    return list(rdpcap(file_path))

def write_pcap(packets, output_file):
    wrpcap(output_file, packets)

def generate_realistic_ip(original_ip):
    try:
        ip_obj = ipaddress.ip_address(original_ip)
    except ValueError:
        return original_ip
    
    random.seed(original_ip)  
    if ip_obj.is_private:
        if original_ip.startswith("10."):
            return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        elif original_ip.startswith("172.16."):
            return f"172.16.{random.randint(1,254)}.{random.randint(1,254)}"
        else:  # 192.168.0.0/16
            return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    else:
        first_octet = original_ip.split('.')[0]
        return f"{first_octet}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def rebuild_packet(original_packet, new_src, new_dst):
    new_pkt = original_packet.copy()
    

    if IP in new_pkt:
        del new_pkt[IP].chksum
        new_pkt[IP].src = new_src
        new_pkt[IP].dst = new_dst
        

        if TCP in new_pkt:
            del new_pkt[TCP].chksum
        elif UDP in new_pkt:
            del new_pkt[UDP].chksum
    

    return new_pkt.__class__(bytes(new_pkt))

def anonymize_ips(packets, mode):
    ip_map = {}
    new_packets = []  
    
    for pkt in packets:
        if IP not in pkt:
            new_packets.append(pkt)
            continue
        
        original_src = pkt[IP].src
        original_dst = pkt[IP].dst
        

        new_src = original_src
        if mode in ["src", "both"]:
            if original_src not in ip_map:
                ip_map[original_src] = generate_realistic_ip(original_src)
            new_src = ip_map[original_src]
            
        new_dst = original_dst
        if mode in ["dst", "both"]:
            if original_dst not in ip_map:
                ip_map[original_dst] = generate_realistic_ip(original_dst)
            new_dst = ip_map[original_dst]
        

        rebuilt_pkt = rebuild_packet(pkt, new_src, new_dst)
        new_packets.append(rebuilt_pkt)
    
    return new_packets

def main():
    parser = argparse.ArgumentParser(description="PCAP IP Anonymizer")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-m", "--mode", choices=["src", "dst", "both"], default="both")
    
    args = parser.parse_args()
    

    packets = read_pcap(args.input)
    anonymized = anonymize_ips(packets, args.mode)
    write_pcap(anonymized, args.output)

if __name__ == "__main__":
    main()