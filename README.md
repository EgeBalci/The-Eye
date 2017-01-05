# The-Eye [![License](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://raw.githubusercontent.com/EgeBalci/Cminer/master/LICENSE)  [![Donate](https://img.shields.io/badge/Donate-Patreon-green.svg)](http://patreon.com/user?u=3556027)
Simple security surveillance script for linux distributions.
The Eye can detect possible ARP poisoning, DNS spoofing and suspicous connections(meterpreter/reverse shell/bind shell) on tcp.


<table>
    <tr>
        <th>Operative system</th>
        <th> Version </th>
    </tr>
    <tr>
        <td>Ubuntu</td>
        <td>* </td>
    </tr>
    <tr>
        <td>Kali linux</td>
        <td>* </td>
    </tr>
    <tr>
        <td>Debian</td>
        <td>* </td>
    </tr>
    <tr>
        <td>Mint</td>
        <td>* </td>
    </tr>
     <tr>
        <td>Arch Linux</td>
        <td>* </td>
    </tr>
    <tr>
        <td>Black Arch</td>
        <td>* </td>
    </tr>
</table>

# Dependencies
	sudo apt-get install espeak

# ARP Poisoning detector 
Checks the arp chache and default gateway continiosly.
# DNS Spoof Detector
Checks the /etc/hosts file for unwanted changes.
# Suspicous Connection Detector
Monitors the netstat table for suspicous outgoing tcp connections.
