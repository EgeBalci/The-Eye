# The-Eye
Simple security surveillance script for ubuntu.
The Eye can detect possible ARP poisoning, DNS spoofing and suspicous connections(meterpreter/reverse shell/bind shell) on tcp.


# ARP Poisoning detector 
Checks the arp chache and default gateway continiosly.
# DNS Spoof Detector
Checks the /etc/hosts file for unwanted changes.
# Suspicous Connection Detector
Monitors the netstat table for suspicous outgoing tcp connections.
