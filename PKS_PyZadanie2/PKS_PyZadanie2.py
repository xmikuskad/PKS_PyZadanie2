import struct
import socket
from scapy.all import *
import os
import sys

ip_array = list()
ip_count = list()

ip_types = list()
eth_types = list()
lsap_types = list()
tcp_types = list()
udp_types = list()

arp_list = []

class DatalinkLayerProtocols:
    def __init__(self, value, name):
        self.value = int(value,0)
        self.name = name.lower()

class IPProtocol:
    def __init__(self, value, type, name):
        self.value = int(value,0)
        self.IPtype = type
        self.name = name.lower()

class TcpUdpProtocols:
    def __init__(self, value,port, name):
        self.value = value
        self.port = int(port)
        self.name = name

class ArpInfo:
    def __init__(self,srcIp,dstIp,srcMac,dstMac,order):
        self.srcIp = srcIp
        self.dstIp = dstIp
        self.srcMac = srcMac
        self.dstMac = dstMac
        self.order = order

class ArpCommunication:
    def __init__(self,ip):
        self.ip = ip
        self.completed = False
        self.ARPrequests = list()
        self.ARPreplies = list()

def add_ip(ipInc):
    i=0
    for ip in ip_array:
        if(ip == ipInc):
            ip_count[i]+=1
            return
        i+=1

    ip_array.append(ipInc)
    ip_count.append(1)

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

def unpack_icmp(raw_data,iterator):
    print('ICMP')

def unpack_igmp(raw_data,iterator):
    print('IGMP')

def unpack_tcp(raw_data,iterator):
    print('TCP')
    srcPort,dstPort = struct.unpack('! H H',raw_data[:4])

    foundSrc = False
    foundDst = False

    for port in tcp_types:
        if srcPort == port.port:
            foundSrc = True
            print('Zdrojový port je {} - {}'.format(srcPort,port.name))

    for port in tcp_types:
        if dstPort == port.port:
            foundDst = True
            print('Cieľový port je {} - {}'.format(dstPort,port.name))

    if not foundSrc:
        print('Zdrojový port je {}'.format(srcPort))

    if not foundDst:
        print('Cieľový port je {}'.format(dstPort))

def unpack_igrp(raw_data,iterator):
    print('IGRP')

def unpack_udp(raw_data,iterator):
    print('UDP')
    srcPort,dstPort = struct.unpack('! H H',raw_data[:4])

    foundSrc = False
    foundDst = False


    for port in udp_types:
        if srcPort == port.port:
            foundSrc = True
            print('Zdrojový port je {} - {}'.format(srcPort,port.name))

    for port in udp_types:
        if dstPort == port.port:
            foundDst = True
            print('Cieľový port je {} - {}'.format(dstPort,port.name))

    if not foundSrc:
        print('Zdrojový port je {}'.format(srcPort))

    if not foundDst:
        print('Cieľový port je {}'.format(dstPort))

def unpack_gre(raw_data,iterator):
    print('GRE')

def unpack_esp(raw_data,iterator):
    print('ESP')

def unpack_ah(raw_data,iterator):
    print('AH')

def unpack_skip(raw_data,iterator):
    print('SKIP')

def unpack_eigrp(raw_data,iterator):
    print('EIGRP')

def unpack_ospf(raw_data,iterator):
    print('OSPF')

def unpack_l2tp(raw_data,iterator):
    print('L2TP')

def unpack_ipv4(raw_data,iterator):
    print('IPV4')
    a=raw_data[0];
    mask = 0b00001111
    length = mask & a
    length*=4
    protokol_num,src_ip,target_ip = struct.unpack('! 9x B 2x 4s 4s',raw_data[:20])
    print('zdrojová IP adresa: {}'.format(format_ip(src_ip)))
    print('cieľová IP adresa: {}'.format(format_ip(target_ip)))
    add_ip(src_ip)

    for protocol in ip_types:
        if protokol_num == protocol.value:
            func_name = 'unpack_'+protocol.name

            functions = globals().copy()
            functions.update(locals())
            call_func = functions.get(func_name)

            if not call_func:
                print('Nepoznam funkciu v ipv4 '+func_name)
                raise Exception('Missing method')
            #Overit, ci sa length dobre pocita!
            call_func(raw_data[length:],iterator)
            return

    print('Nenasiel som prislusny protokol {} v zozname'.format(protokol_num))

def unpack_xerox(raw_data,iterator):
    print('XEROX PUP')

def unpack_pup(raw_data,iterator):
    print('PUP Addr Trans')

def unpack_arp(raw_data,iterator):
    print('ARP')
    tmp,operation,srcMac,srcIp,dstMac,dstIp = struct.unpack('! 6s H 6s 4s 6s 4s',raw_data[:28])
    #print('operation {}, srcMac {}, srcIP {}, dstMac {}, dstIp {}'.format(operation,create_mac(srcMac),format_ip(srcIp),create_mac(dstMac),format_ip(dstIp)))

    index = 0
    while index<len(arp_list):
        if operation == 1 and arp_list[index].completed == False and arp_list[index].ip == format_ip(dstIp):
            info = ArpInfo(format_ip(srcIp),format_ip(dstIp),create_mac(srcMac),create_mac(dstMac),iterator)
            arp_list[index].ARPrequests.append(info)
            if len(arp_list[index].ARPreplies) > 0:
                arp_list[index].completed = True
            return

        elif operation == 2 and arp_list[index].completed == False and arp_list[index].ip == format_ip(srcIp):
            info = ArpInfo(format_ip(srcIp),format_ip(dstIp),create_mac(srcMac),create_mac(dstMac),iterator)
            arp_list[index].ARPreplies.append(info)
            if len(arp_list[index].ARPrequests) > 0:
                arp_list[index].completed = True
            return
        index+=1


    if operation == 1:
        newArp = ArpCommunication(format_ip(dstIp))
        newArp.ARPrequests.append(ArpInfo(format_ip(srcIp),format_ip(dstIp),create_mac(srcMac),create_mac(dstMac),iterator))
        arp_list.append(newArp)
    elif operation == 2:
        newArp = ArpCommunication(format_ip(srcIp))
        newArp.ARPreplies.append(ArpInfo(format_ip(srcIp),format_ip(dstIp),create_mac(srcMac),create_mac(dstMac),iterator))
        arp_list.append(newArp)


def unpack_x75internet(raw_data,iterator):
    print('X.75 Internet')

def unpack_x25internet(raw_data,iterator):
    print('X.25 Internet')

def unpack_rarp(raw_data,iterator):
    print("Reverse ARP")

def unpack_appletalk(raw_data,iterator):
    print('AppleTalk')

def unpack_appletalkaarp(raw_data,iterator):
    print('AppleTalk AARP')

def unpack_ieee(raw_data,iterator):
    print('IEEE 802.1Q')

def unpack_novellipx(raw_data,iterator):
    print('NOVELL IPX')

def unpack_ipv6(raw_data,iterator):
    print('IPv6')

def unpack_ppp(raw_data,iterator):
    print('PPP')

def unpack_mpls(raw_data,iterator):
    print('MPLS')

def unpack_mpls2(raw_data,iterator):
    print('MPLS with upstream-assigned label')

def unpack_pppoed(raw_data,iterator):
    print('PPPOE Discovery Stage')

def unpack_pppoeS(raw_data,iterator):
    print("PPPOE Session Stage")

def unpack_nullsap(raw_data,iterator):
    print('Null Sap')

def unpack_llcsmi(raw_data,iterator):
    print('LLC Sublayer Management / Individual')

def unpack_llcsmg(raw_data,iterator):
    print('LLC Sublayer Management / Group')

def unpack_ip(raw_data,iterator):
    print('IP (DOD Internet Protocol)')

def unpack_prowaynmmi(raw_data,iterator):
    print('PROWAY Network management, Maintenance and Installation')

def unpack_stp(raw_data,iterator):
    print('Spanning tree')

def unpack_mms(raw_data,iterator):
    print('MMS EIA-RS 511')

def unpack_isiip(raw_data,iterator):
    print('ISI IP')

def unpack_x25plp(raw_data,iterator):
    print('X.25 PLP')

def unpack_prowayaslm(raw_data,iterator):
    print('PROWAY Active Station List Maintenance')

def unpack_ipx(raw_data,iterator):
    print('IPX')

def unpack_lan(raw_data,iterator):
    print('LAN Management')

def unpack_iso(raw_data,iterator):
    print('ISO Network Layer Protocols')

def unpack_dsap(raw_data,iterator):
    print('Global DSAP')


def unpack_ethernet(raw_data,iterator):
    print('dĺžka rámca poskytnutá pcap API - {} B'.format(len(raw_data)))

    if len(raw_data) <= 60:
        print('dĺžka rámca prenášaného po médiu – 64 B')
    else:
        print('dĺžka rámca prenášaného po médiu – {} B'.format(len(raw_data)+4))

    d_mac,s_mac,etType,new_raw_data = get_eth_header(raw_data)
    if etType>=1536:
        print('Ethernet II')
        print('Zdrojová MAC adresa: {}'.format(d_mac))
        print('Cieľová MAC adresa:  {}'.format(s_mac))

        for protocol in eth_types:
            if int(etType) == protocol.value:
                func_name = 'unpack_'+protocol.name

                functions = globals().copy()
                functions.update(locals())
                call_func = functions.get(func_name)

                if not call_func:
                    print("Nenasiel som funkciu v ethernete "+func_name)
                    raise Exception('Missing method')
                call_func(new_raw_data,iterator)
                return

        print('Nenasiel som prislusny protokol {} v zozname'.format(etType))

    elif etType<=1500:
        etType2,ehm = struct.unpack('! 2s 2s',new_raw_data[:4])
        if etType2.hex().upper() == 'FFFF':
            print('IEEE 802.3 – Raw')
            print('Zdrojová MAC adresa: {}'.format(d_mac))
            print('Cieľová MAC adresa: {}'.format(s_mac))
        elif etType2.hex().upper() == 'AAAA':
            print('IEEE 802.3 LLC + SNAP')
            print('Zdrojová MAC adresa: {}'.format(d_mac))
            print('Cieľová MAC adresa: {}'.format(s_mac))

            tmp,snapType = struct.unpack('! 6s H',new_raw_data[:8]);

            for protocol in eth_types:
                if int(snapType) == protocol.value:
                    func_name = 'unpack_'+protocol.name

                    functions = globals().copy()
                    functions.update(locals())
                    call_func = functions.get(func_name)

                    if not call_func:
                        print("Nenasiel som funkciu v IEEE 802.3 LLC + SNAP "+func_name)
                        raise Exception('Missing method')
                    call_func(new_raw_data[8:],iterator)
                    return

            print('Nenasiel som prislusny protokol {} v zozname'.format(snapType))

        else:
            print('IEEE 802.3 LLC')
            print('Zdrojová MAC adresa: {}'.format(d_mac))
            print('Cieľová MAC adresa: {}'.format(s_mac))

            tmp,llcType = struct.unpack('! B B',new_raw_data[:2]);

            for protocol in lsap_types:
                if int(llcType) == protocol.value:
                    func_name = 'unpack_'+protocol.name

                    functions = globals().copy()
                    functions.update(locals())
                    call_func = functions.get(func_name)

                    if not call_func:
                        print("Nenasiel som funkciu v IEEE 802.3 LLC "+func_name)
                        raise Exception('Missing method')
                    call_func(new_raw_data[3:],iterator)
                    return

            print('Nenasiel som prislusny protokol {} v zozname'.format(llcType))


def check_arp(skipper):
    counter = 1
    info_shown = False

    for item in arp_list:

        if item.completed == skipper:
            continue

        if info_shown == False:
            info_shown = True
            if skipper == True:
                print("Neuplne ARP komunikacie\n")
            else:
                print('Uplne ARP komunikacie\n')

        if item.completed == True:
            print('Komunikacia {}'.format(counter))
            counter+=1

        if len(item.ARPrequests) > 0:
            print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
            for request in item.ARPrequests:
                print('{} Zdrojova IP: {}, Cielova IP: {}'.format(request.order,request.srcIp,request.dstIp))

        print('')

        if len(item.ARPreplies) > 0:
            print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
            for reply in item.ARPreplies:
                print('{} Zdrojova IP: {}, Cielova IP: {}'.format(reply.order,reply.srcIp,reply.dstIp))

    print('\n')

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
                  

loader = True
while loader == True:
    fileName = input('Zadaj meno pcap suboru na otvorenie: ')
    try:
        data = rdpcap(fileName)
        loader = False
    except IOError:
        print('Nenasiel som subor, skus znova')

#presmerovanie vystupu do suboru
outputFile = open('output.txt','w',encoding='utf-8')
sys.stdout = outputFile


try:
    difTypes = open('types.txt','r')
except IOError:
    print('Subor types.txt nebol najdeny.')
    input()
    os._exit(0)
    


ip,eth,lsap,udp,tcp = False,False,False,False,False

for number,text in enumerate(difTypes):
    editedText = text.replace("\n","")
    words = editedText.split()
    if '#Eth' in words[0]:
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        eth = True;
        continue;
    if '#IP' in words[0]:
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        ip = True;
        continue;
    if '#TCP' in words[0]:
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        tcp = True;
        continue;
    if '#UDP' in words[0]:
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        udp = True;
        continue;
    if '#LSAP' in words[0]:
        ip,eth,lsap, udp,tcp = False,False,False,False,False
        lsap = True;
        continue;
    m=0

    #nahodenie do class

    if eth:
        addedClass = DatalinkLayerProtocols(words[0],words[1])
        eth_types.append(addedClass)
    elif tcp:
        addedClass = TcpUdpProtocols(words[0],words[1],words[2])
        tcp_types.append(addedClass)
    elif udp:
        addedClass = TcpUdpProtocols(words[0],words[1],words[2])
        udp_types.append(addedClass)
    elif ip:
        addedClass = IPProtocol(words[0],words[1],words[2])
        ip_types.append(addedClass)
    elif lsap:
        addedClass = DatalinkLayerProtocols(words[0],words[1])
        lsap_types.append(addedClass)


iterator=0
for packet in data:
    raw_data = raw(data[iterator])
    iterator+=1
    print('rámec {} '.format(iterator))
    unpack_ethernet(raw_data,iterator)
    #print_frame(raw_data)  #ZAPNUT POTOM!
    print('')

print_ip()

#testovanie ARP
print('')
check_arp(False)
check_arp(True)

outputFile.close()

