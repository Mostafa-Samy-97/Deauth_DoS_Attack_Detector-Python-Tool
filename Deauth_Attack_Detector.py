#!/usr/bin/env python

# Deauth_Attack Detector Python Tool Version 1.0
# Developed By Mostafa_Samy
# Github Link ==>> https://github.com/Mostafa-Samy-97

'''
this tool will help you to detect any Deauth attacks 
By analyzing the output packet count, you can detect whether it falls under the DoS attack
or normal behavior

'''

from scapy.all import *
from scapy.layers import Dot11

# get Network Interface from user
interface = raw_input('Enter your Network Interface > ')

# set Packet Counter 
Packet_Counter = 1

# extract info of the packet 
def info(packet):
    if packet.haslayer(Dot11):
        # The packet.subtype==12 statement indicates the deauth frame
        if ((packet.type == 0) & (packet.subtype==12)):
            global Packet_Counter
            print ("[+] Deauthentication Packet detected ! ", Packet_Counter)
            Packet_Counter = Packet_Counter + 1

# Start Sniffing and Detecting Deauth Packets
sniff(iface=interface,prn=info)
