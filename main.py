"""
Author: Jorden Hadas
Date: 5/3/2024
Description: check which of the ports from 20 to 1024 are open
"""

from scapy.all import *
from scapy.layers.inet import TCP, IP

TIMEOUT = 3
SYN = 0x02
ACK = 0x10
FLAGS = 'S'


def check_syn_ack_flags(packet_data):
    """
    :param packet_data: the packet the server returns
    :return: whether the SUN+ACK flags are turned on or not
    """
    f = packet_data['TCP'].flags
    return f & SYN and f & ACK


def main():
    ip = input("enter your computer ip")
    print("the ports that are open: ")
    for port in range(20, 1024):
        syn_segment = TCP(dport=port, flags=FLAGS)
        try:
            syn_packet = IP(dst=ip) / syn_segment
            syn_ack_packet = sr1(syn_packet, timeout=TIMEOUT, verbose=0)
            if syn_ack_packet is not None:
                if check_syn_ack_flags(syn_ack_packet):
                    print(port)
            else:
                print(".")
        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
