import struct
import socket
from scapy.all import *
import os

ip_array = list()
ip_count = list()

ip_types = list()
eth_types = list()
lsap_types = list()
tcp_types = list()
udp_types = list()

class DatalinkLayerProtocols:
    def __init__(self, value, name):
        self.value = int(value,0)
        self.name = name.lower()

class IPProtocol:
    def __init__(self, value, type, name):
        self.value = int(value,0)
        self.IPtype = type
        self.name = name

class TcpUdpProtocols:
    def __init__(self, value,port, name):
        self.value = int(value,0)
        self.port = port
        self.name = name
        

def add_ip(ipInc):
    i=0
    for ip in ip_array:
        if(ip == ipInc):
            ip_count[i]+=1
            #print('Zvacsujem ip {} na {}'.format(format_ip(ip),ip_count[i]))
            return
        i+=1

    ip_array.append(ipInc)
    ip_count.append(1)
    #print('Pridavam ip {} s hodnotou {}'.format(format_ip(ip_array[i]),ip_count[i]))

def print_ip():
    max = 0
    tmp = 0
    i=0
    print('IP adresy vysielajúcich uzlov:')
    for ip in ip_array:
        print(format_ip(ip))
        if ip_count[i] > max:
            max = ip_count[i]
            tmp = i
        i+=1
    
    print('\nAdresa uzla s najväčším počtom odoslaných paketov:')
    print('{}\t{} paketov'.format(format_ip(ip_array[tmp]),ip_count[tmp]))
        

def get_eth_header(data):
    d_mac,s_mac,protocol = struct.unpack('! 6s 6s H', data[:14])
    return create_mac(d_mac), create_mac(s_mac), protocol, data[14:]

def create_mac(b_array):
    b_array = map('{:02x}'.format, b_array)
    b_array = ':'.join(b_array).upper()
    return b_array

def format_ip(ip):
    return '.'.join(map(str,ip))

def unpack_icmp(raw_data):
    print('ICMP')
    #os.system("pause")

def unpack_igmp(raw_data):
    print('IGMP')
    #os.system("pause")

def unpack_tcp(raw_data):
    print('TCP')
    #os.system("pause")

def unpack_igrp(raw_data):
    print('IGRP')
    #os.system("pause")

def unpack_udp(raw_data):
    print('UDP')
    #os.system("pause")

def unpack_gre(raw_data):
    print('GRE')
    #os.system("pause")

def unpack_esp(raw_data):
    print('ESP')
    #os.system("pause")

def unpack_ah(raw_data):
    print('AH')
    #os.system("pause")

def unpack_skip(raw_data):
    print('SKIP')
    #os.system("pause")

def unpack_eigrp(raw_data):
    print('EIGRP')
    #os.system("pause")

def unpack_ospf(raw_data):
    print('OSPF')
    #os.system("pause")

def unpack_l2tp(raw_data):
    print('L2TP')
    #os.system("pause")

def unpack_ipv4(raw_data):
    print('IPV4')
    a=raw_data[0];
    mask = 0b00001111
    length = mask & a
    length*=4
    protokol,src_ip,target_ip = struct.unpack('! 9x B 2x 4s 4s',raw_data[:20])
    #print('\tProtokol: {} Src IP: {} Destination IP: {}'.format(protokol,format_ip(src_ip),format_ip(target_ip)))
    print('zdrojová IP adresa: {}'.format(format_ip(src_ip)))
    print('cieľová IP adresa: {}'.format(format_ip(target_ip)))
    add_ip(src_ip)
    option = {
        1:unpack_icmp,
        2:unpack_igmp,
        6:unpack_tcp,
        9:unpack_igrp,
        17:unpack_udp,
        47:unpack_gre,
        50:unpack_esp,
        51:unpack_ah,
        57:unpack_skip,
        88:unpack_eigrp,
        89:unpack_ospf,
        112:unpack_l2tp,
        }
    option[protokol](data[length:])

def unpack_arp(raw_data):
    print('ARP')
    #os.system("pause")

def unpack_x75(raw_data):
    printf('X75')
    #os.system("pause")

def unpack_x25(raw_data):
    printf('X25')
    #os.system("pause")

def unpack_rarp(raw_data):
    printf("REVERSE ARP")
    #os.system("pause")

def unpack_atalk(raw_data):
    print('ATALK')
    #os.system("pause")

def unpack_atalka(raw_data):
    print('ATALK A')
    #os.system("pause")

def unpack_etIEEE(raw_data):
    print('etherhet IEEE')
    #os.system("pause")

def unpack_novell(raw_data):
    print('NOVELL')
    #os.system("pause")

def unpack_ipv6(raw_data):
    print('IPV6')
    #os.system("pause")

def unpack_ppp(raw_data):
    print('PPP')
    #os.system("pause")

def unpack_mpls(raw_data):
    print('MPLS')
    #os.system("pause")

def unpack_mpls2(raw_data):
    print('MPLS2')
    #os.system("pause")

def unpack_pppoe(raw_data):
    print('PPPOE')
    #os.system("pause")

def unpack_pppoe2(raw_data):
    printf("PPPOE 2")
    #os.system("pause")

def unpack_ethernet(raw_data):
    print('dĺžka rámca poskytnutá pcap API - {} B'.format(len(raw_data)))

    if len(raw_data) <= 60:
        print('dĺžka rámca prenášaného po médiu – 64 B')
    else:
        print('dĺžka rámca prenášaného po médiu – {} B'.format(len(raw_data)+4))

    d_mac,s_mac,etType,new_raw_data = get_eth_header(raw_data)
    #print('{} {} {}'.format(len(raw_data),d_mac,s_mac))
    if etType>=1536:
        print('Ethernet II')
        print('Zdrojová MAC adresa: {}'.format(d_mac))
        print('Cieľová MAC adresa:  {}'.format(s_mac))
        '''
        option = {
            2048: unpack_ipv4,
            2049: unpack_x75,
            2053: unpack_x25,
            2054: unpack_arp,
            32821: unpack_rarp,
            32923: unpack_atalk,
            33011: unpack_atalka,
            33024: unpack_etIEEE,
            33079: unpack_novell,
            34525: unpack_ipv6,
            34827: unpack_ppp,
            34887: unpack_mpls,
            34888: unpack_mpls2,
            34915: unpack_pppoe,
            34916: unpack_pppoe2,
        }
        option[int(etType)](new_raw_data)
        '''
    elif etType<=1500:
        etType2 = struct.unpack('! 2s',new_raw_data[:2])
        if etType2 == 0xFFFF:
            print('IEEE 802.3 – Raw')
            print('Zdrojová MAC adresa: {}'.format(d_mac))
            print('Cieľová MAC adresa: {}'.format(s_mac))
        elif etType2 == 0xAAAA:
            print('IEEE 802.3 LLC + SNAP')
            print('Zdrojová MAC adresa: {}'.format(d_mac))
            print('Cieľová MAC adresa: {}'.format(s_mac))
        else:
            print('IEEE 802.3 LLC')
            print('Zdrojová MAC adresa: {}'.format(d_mac))
            print('Cieľová MAC adresa: {}'.format(s_mac))


def print_frame(raw_data):
    length = len(raw_data)
    i=0
    while length >0:
        tmp = struct.unpack('! 1s',raw_data[:1])
        print('{} '.format(tmp[0].hex()),end='')
        raw_data = raw_data[1:]
        length-=1
        i+=1
        if i%16 == 0:
            print('')
            i=0
        elif i%8 == 0:
            print(' ',end='')

    print('\n')
                  

data = rdpcap('test.pcap')
difTypes = open('types.txt','r')

ip,eth,lsap,udp,tcp = False,False,False,False,False

for number,text in enumerate(difTypes):
    #print("i: "+str(i));
    editedText = text.replace("\n","")
    words = editedText.split()
    if '#Eth' in words[0]:
        print('ETHERNET')
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        eth = True;
        continue;
    if '#IP' in words[0]:
        print('IP')
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        ip = True;
        continue;
    if '#TCP' in words[0]:
        print('TCP')
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        tcp = True;
        continue;
    if '#UDP' in words[0]:
        print('UDP')
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        udp = True;
        continue;
    if '#LSAP' in words[0]:
        print('LSAP')
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        lsap = True;
        continue;
    m=0

    #nahodenie do class

    if eth:
        addedClass = DatalinkLayerProtocols(words[0],words[1])
        eth_types.append(addedClass)
        print('{} {}'.format(addedClass.value, addedClass.name))
    elif tcp:
        addedClass = TcpUdpProtocols(words[0],words[1],words[2])
        tcp_types.append(addedClass)
        print('{} {} {}'.format(addedClass.value, addedClass.name,addedClass.port))
    elif udp:
        addedClass = TcpUdpProtocols(words[0],words[1],words[2])
        udp_types.append(addedClass)
        print('{} {} {}'.format(addedClass.value, addedClass.name,addedClass.port))
    elif ip:
        addedClass = IPProtocol(words[0],words[1],words[2])
        ip_types.append(addedClass)
        print('{} {} {}'.format(addedClass.value,addedClass.IPtype ,addedClass.name))
    elif lsap:
        addedClass = DatalinkLayerProtocols(words[0],words[1])
        lsap_types.append(addedClass)
        print('{} {}'.format(addedClass.value, addedClass.name))


'''
    #print(' ')
    for k in words:
        #print(str(m) + ': '+k);
        if eth:
            eth_types.append(k)
        elif tcp:
            tcp_types.append(k)
        elif udp:
            udp_types.append(k)
        elif ip:
            ip_types.append(k)
        elif lsap:
            lsap_types.append(k)
        m+=1
    #print('\n')
print('\n')

for item in eth_types:
    print(item)
print(' ')
for item in lsap_types:
    print(item)
print(' ')
for item in ip_types:
    print(item)
print(' ')
for item in tcp_types:
    print(item)
print(' ')
for item in udp_types:
    print(item)
print(' ')
'''




iterator=0
for packet in data:
    raw_data = raw(data[iterator])
    iterator+=1
    print('rámec {} '.format(iterator))
    unpack_ethernet(raw_data)
    #print_frame(raw_data)  #ZAPNUT POTOM!
    print('')

#print_ip()

