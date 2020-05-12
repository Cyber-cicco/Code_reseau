#!/usr/bin/env python3

import scapy.all as scapy
import optparse
import subprocess
import time
import datetime

lst_entrees = []
fst_scan = True


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip_range", dest="ip_range", help="Précise la plage d'adresse IP visée par le scan")
    options = parser.parse_args()[0]
    if not options.ip_range:
        parser.error("Veuillez entrer une adresse IP. --help pour obtenir de l'aide")
    return options


def interface(title1, title2):
    print("\n----------------------------------------\n" + title1 + "                 " + title2 +
          "\n----------------------------------------\n")


def append_scan(ip_to_append, file, in_or_out):
    subprocess.call("echo '-------------------------------------" + file, shell=True)
    subprocess.call("echo '" + ip_to_append + in_or_out + str(datetime.datetime.now()) +
                    file, shell=True)


def scan_arp_answer_only(ip):
    return scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=ip), timeout=1,  verbose=False)[0]


def print_answers(answer, fst_scan):
    lst_sorties = []
    subprocess.call(["clear"])
    file = "' >> /root/.scan_logs.txt"
    interface("Adresse IP", "Adresse MAC")
    if fst_scan:
        subprocess.call("echo 'debut du scan : " + str(datetime.datetime.now()) + file, shell=True)
        subprocess.call("echo 'scan initial : " + file, shell=True)
    for a in answer:
        ip_mac = a[1].psrc + "\t:\t" + a[1].hwsrc
        print(ip_mac)
        lst_sorties.append(ip_mac)
        if not fst_scan:
            if not ip_mac in lst_entrees:
                append_scan(ip_mac, file, " entrée le : ")
                lst_entrees.append(ip_mac)
        else:
            subprocess.call("echo '" + ip_mac + file, shell=True)
            lst_entrees.append(ip_mac)
    for b in lst_entrees:
        if b not in lst_sorties:
            append_scan(b, file, "sortie le : ")
            del lst_entrees[lst_entrees.index(b)]
    lst_sorties[:] = []
    print("\n \n")


IP = get_args()
print("Initialisation du scan........")
try:
    while True:
        lst_answered = scan_arp_answer_only(IP.ip_range)
        print_answers(lst_answered, fst_scan)
        fst_scan = False
        time.sleep(30)
except KeyboardInterrupt:
    interface("         Au revoir", "")