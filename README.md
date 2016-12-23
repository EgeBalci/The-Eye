# The-Eye
Simple security surveillance script for ubuntu.
The Eye can detect possible ARP poisoning, DNS spoofing and suspicous connections(meterpreter/reverse shell/bind shell) on tcp.


<table>
    <tr>
        <th>Operative system</th>
        <th> Version </th>
    </tr>
    <tr>
        <td>Ubuntu</td>
        <td> 16.04  / 15.10 </td>
    </tr>
    <tr>
        <td>Kali linux</td>
        <td> Rolling / Sana</td>
    </tr>
    <tr>
        <td>Debian</td>
        <td>* </td>
    </tr>
    <tr>
        <td>Mint</td>
        <td>* </td>
    </tr>
</table>

# ARP Poisoning detector 
Checks the arp chache and default gateway continiosly.
# DNS Spoof Detector
Checks the /etc/hosts file for unwanted changes.
# Suspicous Connection Detector
Monitors the netstat table for suspicous outgoing tcp connections.
