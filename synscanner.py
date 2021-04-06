#!/usr/bin/python
# Author: Owen Ireland
# Date: 31-Mar-2021
# Purpose: TCP SYN port scanner for IP range, assignment work for MSc Information Security, RHUL
# Credits: Based on tutorial code from The Defalt at the following URL
# https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/
from optparse import OptionParser
from netaddr import IPNetwork
from logging import getLogger, ERROR 
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import * 
import sys 
from datetime import datetime 
from time import strftime


def checkhost(f_ip):  # Function to check if target is up
    conf.verb = 0  # Hide verbose output (comment out if needed)
    # print "Pinging %s" % f_ip
    try:
        ping = sr1(IP(dst=f_ip) / ICMP(), timeout=1)  # Ping the target with ICMP packet

        if ping is None:
            return False
        else:
            print "Target is Up, Beginning Scan..."
            return True
    except Exception:  # If ping fails
        print "Unexpected error occurred. Check raw socket privileges etc."
        print "Exiting..."
        sys.exit(1)


def scanport(f_port):  # Function to scan a given port
    try:
        srcport = RandShort()  # Generate random source Port Number
        conf.verb = 0  # Hide output
        synack_pkt = sr1(IP(dst=ip_addr) / TCP(sport=srcport, dport=f_port, flags="S"), timeout=1)
        # Send SYN and recieve RST-ACK or SYN-ACK
        pktflags = synack_pkt.getlayer(TCP).flags  # Extract flags of received packet
        if pktflags == SYNACK:  # Cross reference Flags
            rst_pkt = IP(dst=ip_addr) / TCP(sport=srcport, dport=f_port, flags="R")  # Construct RST packet
            send(rst_pkt)  # Send RST packet
            return True # If open, return false
        else:
            return False # If closed, return false
    except AttributeError:
        return False  # Port not responding (filtered?)
    except KeyboardInterrupt:  # In case the user needs to quit
        rst_pkt = IP(dst=ip_addr) / TCP(sport=srcport, dport=f_port, flags="R")  # Built RST packet
        send(rst_pkt)  # Send RST packet to whatever port is currently being scanned
        print "\n[*] User Requested Shutdown..."
        print "[*] Exiting..."
        sys.exit(1)


if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option("-r", "--iprange", dest="iprange")
    parser.add_option("-s", "--startport", dest="startport")
    parser.add_option("-e", "--endport", dest="endport")
    (options, args) = parser.parse_args()

    if not options.iprange:
        print "Usage: please specify --iprange parameter"
        exit(1)
    if not options.startport:
        print "Usage: please specify --startport parameter"
        exit(1)
    if not options.endport:
        print "Usage: please specify --endport parameter"
        exit(1)

    print "IP Range=%s" % options.iprange

    ports = range(int(options.startport), int(options.endport)+1)  # Build range from given port numbers
    start_clock = datetime.now()  # Start clock for scan time
    SYNACK = 0x12  # Set flag values for later reference
    RSTACK = 0x14

    print "Starting SYNscanner at " + strftime("%d/%m/%Y, %H:%M:%S")
    print "Please be patient."
    for ip in IPNetwork(options.iprange):
        ip_addr = str(ip)  # Note scapy sr1 function needs string input otherwise hangs

        if checkhost(ip_addr):  # Host is up so continue to port scan
            print "SYN scan report for %s" % ip_addr
            port_total_cnt = 0
            port_open_cnt = 0

            for port in ports:  # Iterate through range of ports
                port_total_cnt += 1
                if scanport(port) :  # Pass each port to scanport function
                    port_open_cnt += 1
                    print "Port " + str(port) + ": Open"  # Print status
            print "Total of %d ports scanned of which %d are open" % (port_total_cnt, port_open_cnt)
            print ""
    stop_clock = datetime.now()  # Stop clock for scan time
    total_time = stop_clock - start_clock  # Calculate scan time
    print "Scanning Finished"  # Confirm scan stop
    print "Total Scan Duration: " + str(total_time)  # Print scan time
