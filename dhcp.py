# -*- coding: utf-8 -*-
import struct

from os_ken.lib import addrconv
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import udp
from os_ken.lib.packet import dhcp
from os_ken.ofproto import ether
from os_ken.ofproto import inet


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99' # 不要修改，用于填充 MAC 字段的虚拟地址
    dns = '8.8.8.8' # 不要修改，用于 DHCP 的 DNS 选项
    start_ip = '192.168.1.2' # 可修改，地址池起始地址
    end_ip = '192.168.1.100' # 可修改，地址池结束边界
    netmask = '255.255.255.0' # 可修改，子网掩码

    # 可以使用以上属性配置 DHCP 服务器。
    # 也可以添加 lease_time 等属性来支持 bonus 功能。


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = '192.168.1.1'
    lease_time = 86400
    allocated_ip = {}
    next_ip = addrconv.ipv4.text_to_bin(start_ip)

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        client_ip = cls._get_client_ip(dhcp_pkt)
        if client_ip is None:
            client_ip = cls._allocate_ip(eth_pkt.src)
        else:
            cls._remember_ip(eth_pkt.src, client_ip)

        ack_pkt = cls._assemble_reply(pkt, client_ip, dhcp.DHCP_ACK)
        return ack_pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        client_ip = cls._allocate_ip(eth_pkt.src)
        return cls._assemble_reply(pkt, client_ip, dhcp.DHCP_OFFER)

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        msg_type = cls._get_message_type(dhcp_pkt)

        if msg_type == dhcp.DHCP_DISCOVER:
            cls._send_packet(datapath, port, cls.assemble_offer(pkt, datapath))
        elif msg_type == dhcp.DHCP_REQUEST:
            cls._send_packet(datapath, port, cls.assemble_ack(pkt, datapath, port))

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @classmethod
    def _assemble_reply(cls, pkt, client_ip, msg_type):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',
            src=cls.hardware_addr,
            ethertype=ether.ETH_TYPE_IP))
        reply_pkt.add_protocol(ipv4.ipv4(
            src=cls.server_ip,
            dst='255.255.255.255',
            proto=inet.IPPROTO_UDP))
        reply_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        reply_pkt.add_protocol(dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            htype=dhcp_pkt.htype,
            hlen=dhcp_pkt.hlen,
            hops=dhcp_pkt.hops,
            xid=dhcp_pkt.xid,
            secs=dhcp_pkt.secs,
            flags=dhcp_pkt.flags,
            ciaddr='0.0.0.0',
            yiaddr=client_ip,
            siaddr=cls.server_ip,
            giaddr=dhcp_pkt.giaddr,
            chaddr=dhcp_pkt.chaddr,
            options=dhcp.options(option_list=[
                dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT, struct.pack('!B', msg_type)),
                dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                            addrconv.ipv4.text_to_bin(cls.server_ip)),
                dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT,
                            addrconv.ipv4.text_to_bin(cls.netmask)),
                dhcp.option(dhcp.DHCP_GATEWAY_ADDR_OPT,
                            addrconv.ipv4.text_to_bin(cls.server_ip)),
                dhcp.option(dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                            addrconv.ipv4.text_to_bin(cls.dns)),
                dhcp.option(dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                            struct.pack('!I', cls.lease_time)),
            ])))
        return reply_pkt

    @classmethod
    def _get_message_type(cls, dhcp_pkt):
        for opt in dhcp_pkt.options.option_list:
            if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                return cls._option_value_to_int(opt.value)
        return None

    @classmethod
    def _get_client_ip(cls, dhcp_pkt):
        for opt in dhcp_pkt.options.option_list:
            if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:
                return addrconv.ipv4.bin_to_text(opt.value)
        return None

    @classmethod
    def _allocate_ip(cls, mac_addr):
        if mac_addr in cls.allocated_ip:
            return cls.allocated_ip[mac_addr]

        current = cls._ip_to_int(cls.next_ip)
        end = cls._ip_to_int(addrconv.ipv4.text_to_bin(cls.end_ip))
        if current >= end:
            raise RuntimeError('No available DHCP address')

        client_ip = addrconv.ipv4.bin_to_text(cls._int_to_ip(current))
        cls.allocated_ip[mac_addr] = client_ip
        cls.next_ip = cls._int_to_ip(current + 1)
        return client_ip

    @classmethod
    def _remember_ip(cls, mac_addr, client_ip):
        cls.allocated_ip[mac_addr] = client_ip
        current = cls._ip_to_int(cls.next_ip)
        requested = cls._ip_to_int(addrconv.ipv4.text_to_bin(client_ip))
        if requested >= current:
            cls.next_ip = cls._int_to_ip(requested + 1)

    @classmethod
    def _option_value_to_int(cls, value):
        if isinstance(value, int):
            return value
        return struct.unpack('!B', value[0:1])[0]

    @classmethod
    def _ip_to_int(cls, ip_bytes):
        return struct.unpack('!I', ip_bytes)[0]

    @classmethod
    def _int_to_ip(cls, ip_int):
        return struct.pack('!I', ip_int)
