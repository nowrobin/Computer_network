from scapy.all import *

def handler(packet):
    #간단한 요약정보로 출력
    #print(packet.summary())
    print(packet.show())

def sniffSSH():
    sniff(iface='eth0', prn=handler, filter="tcp and port 22", store=0)

def main():
    #패킷 덤프
    #sniff(iface="eth0", prn=handler, store=0)
    sniffSSH()

main()