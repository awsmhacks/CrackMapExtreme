#!/usr/bin/env python3

from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
import netaddr
import socket
# edit /etc/resolv.conf to include 
#   search domain.com   
# if you want internal network resolution, else you need to use fqdn 

def parse_targets(target):
    if netaddr.ip.nmap.valid_nmap_range(target):
        return list(netaddr.ip.nmap.iter_nmap_range(target))
    else:
        try:
            t = socket.gethostbyname(target.strip())
        except:
            print("Error getting IP Info for {}".format(target.strip()))
            return list()
        return [t]

