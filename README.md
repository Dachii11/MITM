![python](https://img.shields.io/badge/Python-3.10.12-blue)
![os](https://img.shields.io/badge/OS-Linux-Yellow)
# MITM

Simple MITM (man in the middle) tool written in python.
Sniff others traffic in the network with just one command. (It only displays **DNS** packets to see which websites the target is visiting, but stores all traffic in .pcap files).
**Use this tool for educationally purposes only and see how MITM attack works**

This Tool will have more functionality in the future.
# Install requirements
```
 pip install -r requirements.txt
```

# How to run
```
  python3 mitm.py -R <YOUR_NETWORK_RANGE>
```
for example: 192.168.0.0/24
# Sniff DHCP packets to capture target device hostname
```
python3 mitm.py -R <YOUR_NETWORK_RANGE> -D <TARGET_IP>
```
sniffing DHCP **requires wlan interface**, so if you are using **VM** you will need wlan adapter that supports Monitor Mode **&** Packet Injection.
**Put your wlan interface on Monitor Mode**

# How DHCP sniffing works
attacker deauthing target device from the network, it waits until target connects again and captures DHCP packets containing device hostname.
