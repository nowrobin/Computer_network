from scapy.all import *
from scapy.layers.http import *
from bs4 import BeautifulSoup


def inspect(a):
    if HTTPRequest in a:
    
        print(a[IP].src)
        print(a[IP].dst)
        print(a[IP].dport)
        print(a[TCP].payload)
       # print("\n{} ----HTTPRequest----> {}:{}:\n{}".format(a[IP].src, a[IP].dst, a[IP].dport, str(bytes(a[TCP].payload))))
    if HTTPResponse in a:
        response = str(bytes(a[TCP].payload))
        soup = BeautifulSoup(response, "html.parser")
        print("\n{} ----HTTPResponse----> {}:{}:\n{}".format(a[IP].src, a[IP].dst, a[IP].dport, soup))

sniff(prn=inspect, session=TCPSession)