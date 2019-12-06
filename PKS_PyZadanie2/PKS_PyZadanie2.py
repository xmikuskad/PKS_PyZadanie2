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
icmp_list = []
icmp_fail_list = []
tftp_list = []

tftp_port = -1

http_list = []

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

class IcmpInfo:
    def __init__(self,type,order):
        self.type = type
        self.order = order

class IcmpCommunication:
    def __init__(self,ID):
        self.ID = ID
        self.ICMPCommunication = list()

class TftpCommunication:
    def __init__(self,port):
        self.port = port
        self.TFTPCommunication = list()
        self.completed = False

class TftpInfo:
    def __init__(self,opcode,order):
        self.opcode = opcode
        self.order = order

class HttpCommunication:
    def __init__(self,port):
        self.port = port
        self.completed = False
        self.fin1 = False
        self.fin2 = False
        self.ack1 = False
        self.ack2 = False
        self.rst = False
        self.First10Comm = list()
        self.Last10Comm = list()

class TcpInfo:
    def __init__(self,order):
        self.order = order

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

def unpack_icmp(raw_data,iterator,repeating):
    print('ICMP')

    if repeating == True:
        return

    msg_type, tmp = struct.unpack('! B B',raw_data[:2])

    if int(msg_type) == 0 or int(msg_type) == 8 or int(msg_type) ==13 or int(msg_type) ==14 or int(msg_type) ==15 or int(msg_type) ==16 or int(msg_type) ==17 or int(msg_type) ==18:
        tmp,id = struct.unpack('! 4s H',raw_data[:6])
        for leaf in icmp_list:
            if leaf.ID == id:
                leaf.ICMPCommunication.append(IcmpInfo(int(msg_type),iterator))
                return

        new_communication = IcmpCommunication(id)
        new_communication.ICMPCommunication.append(IcmpInfo(int(msg_type),iterator))
        icmp_list.append(new_communication)
    else:
        icmp_fail_list.append(IcmpInfo(int(msg_type),iterator))
    


def unpack_igmp(raw_data,iterator,repeating):
    print('IGMP')

def unpack_http(flags,iterator,repeating,port):
    print('HTTP')

    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    print('ack {} fin {} syn {} rst {}'.format(ack,fin,syn,rst))

    if syn and not ack:
        #if len(http_list) >=2:
            #test1 = http_list
        #else:
        http_list.append(HttpCommunication(port))

    if len(http_list) <= 0:
        return

    for leaf in http_list:
        if leaf.port == port and leaf.completed == False:
            if len(leaf.First10Comm) <10:
                leaf.First10Comm.append(TcpInfo(iterator))
            elif len(leaf.Last10Comm) <10:
                leaf.Last10Comm.append(TcpInfo(iterator))
            else:
                leaf.Last10Comm.append(TcpInfo(iterator))
                leaf.Last10Comm.pop(0)

            if rst:
                leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

        return


def unpack_tcp(raw_data,iterator,repeating):
    print('TCP')
    srcPort,dstPort,tmp,flags = struct.unpack('! H H 9s B ',raw_data[:14])

    foundSrc = False
    foundDst = False

    for port in tcp_types:
        if srcPort == port.port:
            foundSrc = True
            print('Zdrojový port je {} - {}'.format(srcPort,port.name))
            if str.lower(port.name) == 'http':
                unpack_http(int(flags),iterator,repeating,dstPort)

    for port in tcp_types:
        if dstPort == port.port:
            foundDst = True
            print('Cieľový port je {} - {}'.format(dstPort,port.name))
            if str.lower(port.name) == 'http':
                unpack_http(int(flags),iterator,repeating,srcPort)

    if not foundSrc:
        print('Zdrojový port je {}'.format(srcPort))

    if not foundDst:
        print('Cieľový port je {}'.format(dstPort))

    #dorobit komunikacie

def unpack_igrp(raw_data,iterator,repeating):
    print('IGRP')

def unpack_tftp(raw_data,iterator,repeating):
    print("TFPT")

    if repeating == True:
        return

    global tftp_port
    opcode,tmp = struct.unpack('! H B',raw_data[:3])

    for leaf in tftp_list:
        if tftp_port == leaf.port and leaf.completed == False:
            leaf.TFTPCommunication.append(TftpInfo(int(opcode),iterator))
            return

    new_tftp = TftpCommunication(tftp_port)
    new_tftp.TFTPCommunication.append(TftpInfo(int(opcode),iterator))
    tftp_list.append(new_tftp)


def unpack_udp(raw_data,iterator,repeating):
    print('UDP')
    srcPort,dstPort = struct.unpack('! H H',raw_data[:4])

    foundSrc = False
    foundDst = False
    global tftp_port

    for port in udp_types:
        if srcPort == port.port:
            foundSrc = True
            print('Zdrojový port je {} - {}'.format(srcPort,port.name))

    if not foundSrc:
        print('Zdrojový port je {}'.format(srcPort))

    for port in udp_types:
        if dstPort == port.port:
            foundDst = True
            print('Cieľový port je {} - {}'.format(dstPort,port.name))
            if str.lower(port.name) == 'tftp':
                tftp_port = srcPort
                if len(tftp_list) > 0:
                    tftp_list[len(tftp_list)-1].completed = True

    if not foundDst:
        print('Cieľový port je {}'.format(dstPort))

    if dstPort == tftp_port or srcPort == tftp_port:
        unpack_tftp(raw_data[8:],iterator,repeating)

def unpack_gre(raw_data,iterator,repeating):
    print('GRE')

def unpack_esp(raw_data,iterator,repeating):
    print('ESP')

def unpack_ah(raw_data,iterator,repeating):
    print('AH')

def unpack_skip(raw_data,iterator,repeating):
    print('SKIP')

def unpack_eigrp(raw_data,iterator,repeating):
    print('EIGRP')

def unpack_ospf(raw_data,iterator,repeating):
    print('OSPF')

def unpack_l2tp(raw_data,iterator,repeating):
    print('L2TP')

def unpack_ipv4(raw_data,iterator,repeating):
    print('IPV4')
    a=raw_data[0];
    mask = 0b00001111
    length = mask & a
    length*=4
    protokol_num,src_ip,target_ip = struct.unpack('! 9x B 2x 4s 4s',raw_data[:20])
    print('zdrojová IP adresa: {}'.format(format_ip(src_ip)))
    print('cieľová IP adresa: {}'.format(format_ip(target_ip)))

    if repeating == False:
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
            call_func(raw_data[length:],iterator,repeating)
            return

    print('Nenasiel som prislusny protokol {} v zozname'.format(protokol_num))

def unpack_xerox(raw_data,iterator,repeating):
    print('XEROX PUP')

def unpack_pup(raw_data,iterator,repeating):
    print('PUP Addr Trans')

def unpack_arp(raw_data,iterator,repeating):
    print('ARP')
    tmp,operation,srcMac,srcIp,dstMac,dstIp = struct.unpack('! 6s H 6s 4s 6s 4s',raw_data[:28])
    #print('operation {}, srcMac {}, srcIP {}, dstMac {}, dstIp {}'.format(operation,create_mac(srcMac),format_ip(srcIp),create_mac(dstMac),format_ip(dstIp)))

    if repeating == True:
        return

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


def unpack_x75internet(raw_data,iterator,repeating):
    print('X.75 Internet')

def unpack_x25internet(raw_data,iterator,repeating):
    print('X.25 Internet')

def unpack_rarp(raw_data,iterator,repeating):
    print("Reverse ARP")

def unpack_appletalk(raw_data,iterator,repeating):
    print('AppleTalk')

def unpack_appletalkaarp(raw_data,iterator,repeating):
    print('AppleTalk AARP')

def unpack_ieee(raw_data,iterator,repeating):
    print('IEEE 802.1Q')

def unpack_novellipx(raw_data,iterator,repeating):
    print('NOVELL IPX')

def unpack_ipv6(raw_data,iterator,repeating):
    print('IPv6')

def unpack_ppp(raw_data,iterator,repeating):
    print('PPP')

def unpack_mpls(raw_data,iterator,repeating):
    print('MPLS')

def unpack_mpls2(raw_data,iterator,repeating):
    print('MPLS with upstream-assigned label')

def unpack_pppoed(raw_data,iterator,repeating):
    print('PPPOE Discovery Stage')

def unpack_pppoeS(raw_data,iterator,repeating):
    print("PPPOE Session Stage")

def unpack_nullsap(raw_data,iterator,repeating):
    print('Null Sap')

def unpack_llcsmi(raw_data,iterator,repeating):
    print('LLC Sublayer Management / Individual')

def unpack_llcsmg(raw_data,iterator,repeating):
    print('LLC Sublayer Management / Group')

def unpack_ip(raw_data,iterator,repeating):
    print('IP (DOD Internet Protocol)')

def unpack_prowaynmmi(raw_data,iterator,repeating):
    print('PROWAY Network management, Maintenance and Installation')

def unpack_stp(raw_data,iterator,repeating):
    print('Spanning tree')

def unpack_mms(raw_data,iterator,repeating):
    print('MMS EIA-RS 511')

def unpack_isiip(raw_data,iterator,repeating):
    print('ISI IP')

def unpack_x25plp(raw_data,iterator,repeating):
    print('X.25 PLP')

def unpack_prowayaslm(raw_data,iterator,repeating):
    print('PROWAY Active Station List Maintenance')

def unpack_ipx(raw_data,iterator,repeating):
    print('IPX')

def unpack_lan(raw_data,iterator,repeating):
    print('LAN Management')

def unpack_iso(raw_data,iterator,repeating):
    print('ISO Network Layer Protocols')

def unpack_dsap(raw_data,iterator,repeating):
    print('Global DSAP')


def unpack_ethernet(raw_data,iterator,repeating):
    print('dĺžka rámca poskytnutá pcap API - {} B'.format(len(raw_data)))

    if len(raw_data) <= 60:
        print('dĺžka rámca prenášaného po médiu – 64 B')
    else:
        print('dĺžka rámca prenášaného po médiu – {} B'.format(len(raw_data)+4))

    d_mac,s_mac,etType,new_raw_data = get_eth_header(raw_data)
    if etType>=1536:
        print('Ethernet II')
        print('Zdrojová MAC adresa: {}'.format(s_mac))
        print('Cieľová MAC adresa:  {}'.format(d_mac))


        for protocol in eth_types:
            if int(etType) == protocol.value:
                func_name = 'unpack_'+protocol.name

                functions = globals().copy()
                functions.update(locals())
                call_func = functions.get(func_name)

                if not call_func:
                    print("Nenasiel som funkciu v ethernete "+func_name)
                    raise Exception('Missing method')
                call_func(new_raw_data,iterator,repeating)
                return

        print('Nenasiel som prislusny protokol {} v zozname'.format(etType))

    elif etType<=1500:
        etType2,ehm = struct.unpack('! 2s 2s',new_raw_data[:4])
        if etType2.hex().upper() == 'FFFF':
            print('IEEE 802.3 – Raw')
            print('Zdrojová MAC adresa: {}'.format(s_mac))
            print('Cieľová MAC adresa: {}'.format(d_mac))
        elif etType2.hex().upper() == 'AAAA':
            print('IEEE 802.3 LLC + SNAP')
            print('Zdrojová MAC adresa: {}'.format(s_mac))
            print('Cieľová MAC adresa: {}'.format(d_mac))


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
                    call_func(new_raw_data[8:],iterator,repeating)
                    return

            print('Nenasiel som prislusny protokol {} v zozname'.format(snapType))

        else:
            print('IEEE 802.3 LLC')
            print('Zdrojová MAC adresa: {}'.format(s_mac))
            print('Cieľová MAC adresa: {}'.format(d_mac))


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
                    call_func(new_raw_data[3:],iterator,repeating)
                    return

            print('Nenasiel som prislusny protokol {} v zozname'.format(llcType))


def check_http(skipper):

    for leaf in http_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:
            if skipper == True:
                print('Prva kompletna HTTP komunikacia\n')
            else:
                print('Prva nekompletna HTTP komunikacia\n')    
            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for http in leaf.First10Comm:
                print('rámec {} '.format(http.order))
                unpack_ethernet(raw(data[http.order-1]),http.order,True)
                #print_frame(raw(data[http.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('Poslednych 10 ramcov')
            for http in leaf.Last10Comm:
                print('rámec {} '.format(http.order))
                unpack_ethernet(raw(data[http.order-1]),http.order,True)
                #print_frame(raw(data[http.order-1]))  #ZAPNUT POTOM!
            break    


def check_tftp():
    if len(tftp_list) > 0:
        print('TFTP Komunikacie\n')

    count =0
    for leaf in tftp_list:
        count+=1
        print('\nKomunikacia {}\n'.format(count))
        for tftp in leaf.TFTPCommunication:
                print('Poradie {} opcode {}'.format(tftp.order,tftp.opcode))

                if tftp.opcode == 1:
                    print('Read request')
                elif tftp.opcode == 2:
                    print('Write request')
                elif tftp.opcode == 3:
                    print('Read or write the next block of data')
                elif tftp.opcode == 4:
                    print('Acknowledgment')
                elif tftp.opcode == 5:
                    print('Error message')
                elif tftp.opcode == 6:
                    print('Option acknowledgment')

                print('rámec {} '.format(tftp.order))
                unpack_ethernet(raw(data[tftp.order-1]),tftp.order,True)
                #print_frame(raw(data[tftp.order-1]))  #ZAPNUT POTOM!

def check_icmp():
    if len(icmp_list) > 0:
        print('Reply + request ICMP\n')

    for leaf in icmp_list:
        print('\nICMP identifier {}\n'.format(leaf.ID))
        for icmp in leaf.ICMPCommunication:
            if icmp.type == 0:
                print('ICMP - Echo reply')
            elif icmp.type == 8:
                print('ICMP - Echo request')
            elif leaf.type == 13:
                print('Timestamp')
            elif leaf.type == 14:
                print('Timestamp reply')
            elif leaf.type == 15:
                print('Information request')
            elif leaf.type == 16:
                print('Information reply')
            elif leaf.type == 17:
                print('Address Mask request')
            elif leaf.type == 18:
                print('Address Mask reply')
            print('rámec {} '.format(icmp.order))
            unpack_ethernet(raw(data[icmp.order-1]),icmp.order,True)
            #print_frame(raw(data[icmp.order-1]))  #ZAPNUT POTOM!

    if len(icmp_fail_list) > 0:
        print('\n\nOstatne ICMP\n')

    for leaf in icmp_fail_list:
        if leaf.type == 3:
            print('ICMP - Destination unreachable')
        elif leaf.type == 4:
            print('ICMP - Source quench')
        elif leaf.type == 5:
            print('ICMP - Redirection')
        elif leaf.type == 9:
            print('ICMP - Router Ad')
        elif leaf.type == 10:
            print('ICMP - Router Selection')
        elif leaf.type == 11:
            print('Time exceeded')
        elif leaf.type == 12:
            print('Parameter problem')
        elif leaf.type == 30:
            print('Traceroute')

        print('rámec {} '.format(leaf.order))
        unpack_ethernet(raw(data[leaf.order-1]),leaf.order,True)
        #print_frame(raw(data[leaf.order-1]))  #ZAPNUT POTOM!

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
            for request in item.ARPrequests:
                print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
                print('Zdrojova IP: {}, Cielova IP: {}'.format(request.srcIp,request.dstIp))
                print('rámec {} '.format(request.order))
                unpack_ethernet(raw(data[request.order-1]),request.order,True)
                #print_frame(raw(data[request.order-1]))  #ZAPNUT POTOM!

        print('')

        if len(item.ARPreplies) > 0:
            for reply in item.ARPreplies:
                print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
                print('Zdrojova IP: {}, Cielova IP: {}'.format(reply.srcIp,reply.dstIp))
                print('rámec {} '.format(reply.order))
                unpack_ethernet(raw(data[reply.order-1]),reply.order,True)
                #print_frame(raw(data[reply.order-1]))  #ZAPNUT POTOM!


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
    unpack_ethernet(raw_data,iterator,False)
    #print_frame(raw_data)  #ZAPNUT POTOM!
    print('')

print('--------------------------------------------------------\n')
#vypisanie top IP adries
print_ip()
print('\n--------------------------------------------------------\n')

#vypisovanie ARP
check_arp(False)
check_arp(True)
print('--------------------------------------------------------\n')

#vypisovanie ICMP
check_icmp()
print('--------------------------------------------------------\n')

#vypisovanie TFTP
check_tftp()
print('--------------------------------------------------------\n')

#vypisovanie HTTP
check_http(True)
check_http(False)
print('--------------------------------------------------------\n')

outputFile.close()

