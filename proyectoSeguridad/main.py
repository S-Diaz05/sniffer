import scapy.all as scapy
from scapy.layers import http
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.utils import wrpcap, rdpcap
import hashlib


def sniff(interface):
    packets = scapy.sniff(iface=interface, prn=sniffed_packet)
    wrpcap("./Test.pcap", packets)

    d = rdpcap("./Test.pcap")


def sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()

        print(f"\n[+] {ip} Requested {url} with {method}")
        if packet.haslayer(Raw) and method == "POST":
            write_file_data(packet[Raw].load)
            encryption(str(packet[Raw].load))

        write_file(packet, "no_encriptado.txt")

    else:
        write_file(packet, "encriptado.txt")


def encryption(data):
    my_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
    write_file_data(my_hash)


def write_file_data(data):
    f = open('data.txt', 'a')
    f.write(str(data))
    f.close()


def write_file(packet, file):
    f = open(file, 'a')
    f.write(str(packet))
    f.close()


def main():
    sniff("eth0")


if __name__ == '__main__':
    main()
