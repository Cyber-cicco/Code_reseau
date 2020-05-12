import scapy.all as scapy
import threading


def scan_dat_guy(c):
    ans, unans = scapy.sr(scapy.IP(dst=c)/scapy.TCP(dport=(1,1000), flags='S'), timeout=1, verbose=False)
    with lock:
        for msg in ans:
            if msg[1][scapy.TCP].flags == 'SA':
                print(c, msg[1].sport, msg[1][scapy.TCP].flags)

b = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst='192.168.1.1/24'), timeout=2)[0]
print("Adresses du reseau : ")
for c in b:
    print(c[1].psrc)
    lock = threading.RLock()
    tdr_scan = threading.Thread(target=lambda:scan_dat_guy(c[1].psrc))
    tdr_scan.start()
