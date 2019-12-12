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
ssh_list = []
https_list = []
telnet_list = []
ftp_data_list = []
ftp_control_list = []

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

class TcpCommunication:
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
            if int(leaf.ID) == int(id):
                leaf.ICMPCommunication.append(IcmpInfo(int(msg_type),iterator))
                return

        new_communication = IcmpCommunication(id)
        new_communication.ICMPCommunication.append(IcmpInfo(int(msg_type),iterator))
        icmp_list.append(new_communication)
    else:
        icmp_fail_list.append(IcmpInfo(int(msg_type),iterator))    

def unpack_http(flags,iterator,repeating,port):
    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    if syn and not ack:
        http_list.append(TcpCommunication(port))

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

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True
        return


def unpack_https(flags,iterator,repeating,port):
    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    if syn and not ack:
        https_list.append(TcpCommunication(port))

    if len(https_list) <= 0:
        return

    for leaf in https_list:
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

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True
        return

def unpack_ssh(flags,iterator,repeating,port):
    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    if syn and not ack:
        ssh_list.append(TcpCommunication(port))

    if len(ssh_list) <= 0:
        return

    for leaf in ssh_list:
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

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True
        return

def unpack_telnet(flags,iterator,repeating,port):
    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    if syn and not ack:
        telnet_list.append(TcpCommunication(port))

    if len(telnet_list) <= 0:
        return

    for leaf in telnet_list:
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

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True
        return

def unpack_ftp_control(flags,iterator,repeating,port):
    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    if syn and not ack:
        ftp_control_list.append(TcpCommunication(port))

    if len(ftp_control_list) <= 0:
        return

    for leaf in ftp_control_list:
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

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True
        return

def unpack_ftp_data(flags,iterator,repeating,port):
    if repeating == True:
        return

    ack = (flags & (1<<4)) >> 4
    fin = flags & 1
    syn = (flags & (1<<1)) >> 1
    rst = (flags & (1<<2)) >> 2

    if syn and not ack:
        ftp_data_list.append(TcpCommunication(port))

    if len(ftp_data_list) <= 0:
        return

    for leaf in ftp_data_list:
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

            if ack:
                if leaf.fin1 and leaf.fin2:
                    leaf.completed = True

            if fin:
                if not leaf.fin1:
                    leaf.fin1 = True
                else:
                    leaf.fin2 = True
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
            if str.lower(port.name) == 'ssh':
                unpack_ssh(int(flags),iterator,repeating,dstPort)
            if str.lower(port.name) == 'ftp_control':
                unpack_ftp_control(int(flags),iterator,repeating,dstPort)
            if str.lower(port.name) == 'telnet':
                unpack_telnet(int(flags),iterator,repeating,dstPort)
            if str.lower(port.name) == 'ftp_data':
                unpack_ftp_data(int(flags),iterator,repeating,dstPort)
            if str.lower(port.name) == 'https':
                unpack_https(int(flags),iterator,repeating,dstPort)

    for port in tcp_types:
        if dstPort == port.port:
            foundDst = True
            print('Cieľový port je {} - {}'.format(dstPort,port.name))
            if str.lower(port.name) == 'http':
                unpack_http(int(flags),iterator,repeating,srcPort)
            if str.lower(port.name) == 'ssh':
                unpack_ssh(int(flags),iterator,repeating,srcPort)
            if str.lower(port.name) == 'ftp_control':
                unpack_ftp_control(int(flags),iterator,repeating,srcPort)
            if str.lower(port.name) == 'telnet':
                unpack_telnet(int(flags),iterator,repeating,srcPort)
            if str.lower(port.name) == 'ftp_data':
                unpack_ftp_data(int(flags),iterator,repeating,srcPort)
            if str.lower(port.name) == 'https':
                unpack_https(int(flags),iterator,repeating,srcPort)

    if not foundSrc:
        print('Zdrojový port je {}'.format(srcPort))

    if not foundDst:
        print('Cieľový port je {}'.format(dstPort))

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
            name = protocol.name
            func_name = 'unpack_'+protocol.name

            functions = globals().copy()
            functions.update(locals())
            call_func = functions.get(func_name)

            if call_func:
                call_func(raw_data[length:],iterator,repeating)
                return

    try:
        name
    except NameError:
        print('Nepoznam protokol {}'.format(protokol_num))
    else:
        print(name.upper())

def unpack_arp(raw_data,iterator,repeating):
    print('ARP')
    tmp,operation,srcMac,srcIp,dstMac,dstIp = struct.unpack('! 6s H 6s 4s 6s 4s',raw_data[:28])

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
                name = protocol.name
                func_name = 'unpack_'+protocol.name

                functions = globals().copy()
                functions.update(locals())
                call_func = functions.get(func_name)

                if call_func:
                    call_func(new_raw_data,iterator,repeating)
                    return

        try:
            name
        except NameError:
            print('Nepoznam protokol {}'.format(etType))
        else:
            print(name.upper())

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
                    name = protocol.name
                    func_name = 'unpack_'+protocol.name

                    functions = globals().copy()
                    functions.update(locals())
                    call_func = functions.get(func_name)

                    if call_func:
                        call_func(new_raw_data[8:],iterator,repeating)
                        return

            try:
                name
            except NameError:
                print('Nepoznam protokol {}'.format(snapType))
            else:
                print(name.upper())

        else:
            print('IEEE 802.3 LLC')
            print('Zdrojová MAC adresa: {}'.format(s_mac))
            print('Cieľová MAC adresa: {}'.format(d_mac))


            tmp,llcType = struct.unpack('! B B',new_raw_data[:2]);

            for protocol in lsap_types:
                if int(llcType) == protocol.value:
                    name = protocol.name
                    func_name = 'unpack_'+protocol.name

                    functions = globals().copy()
                    functions.update(locals())
                    call_func = functions.get(func_name)

                    if call_func:
                        call_func(new_raw_data[3:],iterator,repeating)
                        return

            try:
                name
            except NameError:
                print('Nepoznam protokol {}'.format(llcType))
            else:
                print(name.upper())


def check_http(skipper):

    if skipper == True:
        print('Prva kompletna HTTP komunikacia\n')
    else:
        print('\nPrva nekompletna HTTP komunikacia\n')    

    for leaf in http_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for http in leaf.First10Comm:
                print('rámec {} '.format(http.order))
                unpack_ethernet(raw(data[http.order-1]),http.order,True)
                print_frame(raw(data[http.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('\nPoslednych 10 ramcov')
            for http in leaf.Last10Comm:
                print('rámec {} '.format(http.order))
                unpack_ethernet(raw(data[http.order-1]),http.order,True)
                print_frame(raw(data[http.order-1]))  #ZAPNUT POTOM!
            break    

def check_https(skipper):

    if skipper == True:
        print('Prva kompletna HTTPS komunikacia\n')
    else:
        print('\nPrva nekompletna HTTPS komunikacia\n')    

    for leaf in https_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for https in leaf.First10Comm:
                print('rámec {} '.format(https.order))
                unpack_ethernet(raw(data[https.order-1]),https.order,True)
                print_frame(raw(data[https.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('\nPoslednych 10 ramcov')
            for https in leaf.Last10Comm:
                print('rámec {} '.format(https.order))
                unpack_ethernet(raw(data[https.order-1]),https.order,True)
                print_frame(raw(data[https.order-1]))  #ZAPNUT POTOM!
            break    

def check_ssh(skipper):

    if skipper == True:
        print('Prva kompletna SSH komunikacia\n')
    else:
        print('\nPrva nekompletna SSH komunikacia\n')    

    for leaf in ssh_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for ssh in leaf.First10Comm:
                print('rámec {} '.format(ssh.order))
                unpack_ethernet(raw(data[ssh.order-1]),ssh.order,True)
                print_frame(raw(data[ssh.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('\nPoslednych 10 ramcov')
            for ssh in leaf.Last10Comm:
                print('rámec {} '.format(ssh.order))
                unpack_ethernet(raw(data[ssh.order-1]),ssh.order,True)
                print_frame(raw(data[ssh.order-1]))  #ZAPNUT POTOM!
            break    


def check_telnet(skipper):

    if skipper == True:
        print('Prva kompletna TELNET komunikacia\n')
    else:
        print('\nPrva nekompletna TELNET komunikacia\n')    

    for leaf in telnet_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for telnet in leaf.First10Comm:
                print('rámec {} '.format(telnet.order))
                unpack_ethernet(raw(data[telnet.order-1]),telnet.order,True)
                print_frame(raw(data[telnet.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('\nPoslednych 10 ramcov')
            for ssh in leaf.Last10Comm:
                print('rámec {} '.format(telnet.order))
                unpack_ethernet(raw(data[telnet.order-1]),telnet.order,True)
                print_frame(raw(data[telnet.order-1]))  #ZAPNUT POTOM!
            break    

def check_ftp_control(skipper):

    if skipper == True:
        print('Prva kompletna riadiaca FTP komunikacia\n')
    else:
        print('\nPrva nekompletna riadiaca FTP komunikacia\n')    

    for leaf in ftp_control_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for ftp_control in leaf.First10Comm:
                print('rámec {} '.format(ftp_control.order))
                unpack_ethernet(raw(data[ftp_control.order-1]),ftp_control.order,True)
                print_frame(raw(data[ftp_control.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('\nPoslednych 10 ramcov')
            for ftp_control in leaf.Last10Comm:
                print('rámec {} '.format(ftp_control.order))
                unpack_ethernet(raw(data[ftp_control.order-1]),ftp_control.order,True)
                print_frame(raw(data[ftp_control.order-1]))  #ZAPNUT POTOM!
            break    

def check_ftp_data(skipper):

    if skipper == True:
        print('Prva kompletna datova FTP komunikacia\n')
    else:
        print('\nPrva nekompletna datova FTP komunikacia\n')    

    for leaf in ftp_data_list:
        if leaf.completed == skipper and len(leaf.First10Comm) > 3:            
            if len(leaf.Last10Comm) > 0:
                print('Prvych 10 ramcov')
            for ftp_data in leaf.First10Comm:
                print('rámec {} '.format(ftp_data.order))
                unpack_ethernet(raw(data[ftp_data.order-1]),ftp_data.order,True)
                print_frame(raw(data[ftp_data.order-1]))  #ZAPNUT POTOM!

            if len(leaf.Last10Comm) > 0:        
                print('\nPoslednych 10 ramcov')
            for ftp_data in leaf.Last10Comm:
                print('rámec {} '.format(ftp_data.order))
                unpack_ethernet(raw(data[ftp_data.order-1]),ftp_data.order,True)
                print_frame(raw(data[ftp_data.order-1]))  #ZAPNUT POTOM!
            break    

def check_tftp():
    print('TFTP Komunikacie\n')

    count =0
    for leaf in tftp_list:
        count+=1
        print('\nKomunikacia {}\n'.format(count))
        if len(leaf.TFTPCommunication) > 10:
            print('Prvych 10 ramcov')

        index = 0
        show = False
        while index < len(leaf.TFTPCommunication):

            if index > 9 and index <= len(leaf.TFTPCommunication) -11:
                index +=1
                continue

            if index > 9 and index > len(leaf.TFTPCommunication) -11 and show == False:
                print('\nPoslednych 10 ramcov')
                show = True

            tftp = leaf.TFTPCommunication[index]
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
            print_frame(raw(data[tftp.order-1]))  #ZAPNUT POTOM!

            index+=1

def check_icmp():
    print('Reply + request ICMP\n')


    for leaf in icmp_list:
        print('\nICMP identifier {}\n'.format(leaf.ID))

        if len(leaf.ICMPCommunication) > 10:
            print('Prvych 10 ramcov')

        index = 0
        show = False
        while index < len(leaf.ICMPCommunication):

            if index > 9 and index <= len(leaf.ICMPCommunication) -11:
                index +=1
                continue

            if index > 9 and index > len(leaf.ICMPCommunication) -11 and show == False:
                print('\nPoslednych 10 ramcov')
                show = True

            icmp = leaf.ICMPCommunication[index]
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
            print_frame(raw(data[icmp.order-1]))  #ZAPNUT POTOM!

            index+=1



    print('\nOstatne ICMP\n')

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
        print_frame(raw(data[leaf.order-1]))  #ZAPNUT POTOM!

def check_arp(skipper):
    counter = 1

    if skipper == True:
        print("\nNeuplne ARP komunikacie\n")
    else:
        print('Uplne ARP komunikacie\n')

    for item in arp_list:

        if item.completed == skipper:
            continue

        if item.completed == True:
            print('Komunikacia {}'.format(counter))
            counter+=1
        else:
            print('Nova neuplna komunikacia\n')

        max_length = len(item.ARPrequests) + len(item.ARPreplies)

        if(max_length < 10):
            if len(item.ARPrequests) > 0:
                for request in item.ARPrequests:
                    print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
                    print('Zdrojova IP: {}, Cielova IP: {}'.format(request.srcIp,request.dstIp))
                    print('rámec {} '.format(request.order))
                    unpack_ethernet(raw(data[request.order-1]),request.order,True)
                    print_frame(raw(data[request.order-1]))  #ZAPNUT POTOM!

            print('')

            if len(item.ARPreplies) > 0:
                for reply in item.ARPreplies:
                    print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
                    print('Zdrojova IP: {}, Cielova IP: {}'.format(reply.srcIp,reply.dstIp))
                    print('rámec {} '.format(reply.order))
                    unpack_ethernet(raw(data[reply.order-1]),reply.order,True)
                    print_frame(raw(data[reply.order-1]))  #ZAPNUT POTOM!
        else:
            tmpIt = 1
            index1 = 0
            index2 =0
            print('Prvych 10 ramcov')
            while tmpIt <= 10:

                if index1 > len(item.ARPrequests) -1:
                    print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
                    leaf = item.ARPreplies[index2]
                    index2+=1
                elif index2 > len(item.ARPreplies) -1:
                    print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
                    leaf = item.ARPrequests[index1]
                    index1+=1
                else:
                    if item.ARPrequests[index1].order < item.ARPreplies[index2].order:
                        print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
                        leaf = item.ARPrequests[index1]
                        index1+=1
                    else:
                        leaf = item.ARPreplies[index2]
                        print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
                        index2+=1

                print('Zdrojova IP: {}, Cielova IP: {}'.format(leaf.srcIp,leaf.dstIp))
                print('rámec {} '.format(leaf.order))
                unpack_ethernet(raw(data[leaf.order-1]),leaf.order,True)
                print_frame(raw(data[leaf.order-1]))  #ZAPNUT POTOM!

                tmpIt+=1

            tmpIt = 0

            if max_length-10 < 10:
                max_it = max_length-10
            else:
                max_it = 10

            index1 = len(item.ARPrequests) -1
            index2 = len(item.ARPreplies) -1

            while tmpIt<max_it:
                if index1 <0:
                    index2-=1
                elif index2 <0:
                    index1-=1
                else:
                    if item.ARPrequests[index1].order > item.ARPreplies[index2].order:
                        index1-=1
                    else:
                        index2-=1

                tmpIt+=1

            tmpIt = 0
            if index1 != len(item.ARPrequests) -1 or index1 <0:
                index1+=1
            if index2 != len(item.ARPreplies) -1 or index2 <0:
                index2+=1
            print('Poslednych 10 ramcov')
            while tmpIt <max_it:

                if index1 > len(item.ARPrequests) -1:
                    print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
                    leaf = item.ARPreplies[index2]
                    index2+=1
                elif index2 > len(item.ARPreplies) -1:
                    print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
                    leaf = item.ARPrequests[index1]
                    index1+=1
                else:
                    if item.ARPrequests[index1].order < item.ARPreplies[index2].order:
                        print('ARP-Request, IP adresa {}, MAC adresa: ???'.format(item.ip))
                        leaf = item.ARPrequests[index1]
                        index1+=1
                    else:
                        leaf = item.ARPreplies[index2]
                        print('ARP-Reply, IP adresa {}, MAC adresa: {}'.format(item.ip,item.ARPreplies[0].srcMac))
                        index2+=1

                print('Zdrojova IP: {}, Cielova IP: {}'.format(leaf.srcIp,leaf.dstIp))
                print('rámec {} '.format(leaf.order))
                unpack_ethernet(raw(data[leaf.order-1]),leaf.order,True)
                print_frame(raw(data[leaf.order-1]))  #ZAPNUT POTOM!

                tmpIt+=1
    

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
    sys.stdout = sys.__stdout__
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
    print_frame(raw_data)  #ZAPNUT POTOM!
    print('')

outputFile.close()
outputFile = open('outputOther.txt','w',encoding='utf-8')
sys.stdout = outputFile


print('--------------------------------------------------------\n')
#vypisanie top IP adries
print_ip()
print('\n--------------------------------------------------------\n')

#vypisovanie HTTP
check_http(True)
check_http(False)
print('--------------------------------------------------------\n')

#vypisovanie HTTPS
check_https(True)
check_https(False)
print('--------------------------------------------------------\n')

#vypisovanie TELNET
check_telnet(True)
check_telnet(False)
print('--------------------------------------------------------\n')

#vypisovanie SSH
check_ssh(True)
check_ssh(False)
print('--------------------------------------------------------\n')

#vypisovanie FTP CONTROL
check_ftp_control(True)
check_ftp_control(False)
print('--------------------------------------------------------\n')

#vypisovanie FTP DATA
check_ftp_data(True)
check_ftp_data(False)
print('--------------------------------------------------------\n')

#vypisovanie TFTP
check_tftp()
print('--------------------------------------------------------\n')

#vypisovanie ICMP
check_icmp()
print('--------------------------------------------------------\n')

#vypisovanie ARP
check_arp(False)
check_arp(True)
print('--------------------------------------------------------\n')


outputFile.close()