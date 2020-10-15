
import os
import sys
import pyfiglet
from scapy.all import *

os.system("clear")

print (chr(27)+"[36m") 
banner = pyfiglet.figlet_format("Fake Ap Gen")
print (banner)
print ("     Author : Rahat Khan Tusar(RKT)")
print ("     Github : https://github.com/r3k4t")

interface = input("Enter interface(wlp2s0): ")

os.system("sudo airmon-ng start {}".format(interface))

# interface to use to send beacon frames, must be in monitor mode
iface = "wlp2s0mon"
# generate a random MAC address (built-in in scapy)
sender_mac = RandMAC()
# SSID (name of access point)
ssid = input("Enter Wifi Essid Name:")
# 802.11 frame
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
# beacon layer
beacon = Dot11Beacon()
# putting ssid in the frame
essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
# stack all the layers and add a RadioTap
frame = RadioTap()/dot11/beacon/essid
# send the frame in layer 2 every 100 milliseconds forever
# using the `iface` interface
sendp(frame, inter=0.1, iface=iface, loop=1)
