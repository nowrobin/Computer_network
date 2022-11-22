# 1개씩은 되는데, 여러개 한번에 하는 방법 찾으면 될듯?
    #packet = sniff(prn=handler, filter="tcp and port 22", store=0)
    #packet.nsummary()

from scapy.all import *

def handler(packet):
    #간단한 요약정보로 출력
    print(packet.summary())
    #자세한 정보 출력
    #print(packet.show())

def sniffing():

    #SSH -> TCP port:22
    #sniff(prn=handler, filter="tcp and port 22", store=0)

    #DNS -> UDP/TCP port:53
    #sniff(prn=handler, filter="udp and port 53", store=0)

    #HTTP -> TCP port:80
    #sniff(prn=handler, filter="tcp and port 80", store=0)

    #ICMP port:1
    #sniff(prn=handler, filter="icmp", store=0)


def main():
    sniffing()

main()