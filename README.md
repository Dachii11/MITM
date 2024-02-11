![python](https://img.shields.io/badge/Python-3.10.12-blue)
![os](https://img.shields.io/badge/OS-Linux-Yellow)
# MITM

Simple MITM (man in the middle) tool written in python.
Sniff others traffic in the network with just one command. (It displays only **DNS** packets to see what websites they visit but saving all traffic in .pcap files).
**Use this tool for educationally purposes only and see how MITM attack works**

# How to run
```
  python3 mitm.py -R <YOUR_NETWORK_RANGE>
```
for example: 192.168.0.0/24
# Sniff DHCP packets to capture victim's device hostname
```
python3 mitm.py -R <YOUR_NETWORK_RANGE> -D <TARGET_IP>
```
sniffing DHCP **requires wlan interface**, so if you using **VM** you will need wlan adapter that supports Monitor Mode **&** Packet Injection.

# How DHCP sniffing works
attacker deauthing target device from the network, it waits until target connects again and captures DHCP packets containing device hostname.
