# -*- coding: utf-8 -*-
import struct
import time

from os_ken.lib import addrconv
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import udp
from os_ken.lib.packet import dhcp
from os_ken.ofproto import ether
from os_ken.ofproto import inet


class Config():
    # DHCP 服务器基础配置。地址池采用左闭右开的范围：[start_ip, end_ip)。
    controller_macAddr = '7e:49:b3:f0:f9:99' # 不要修改，用于填充 MAC 字段的虚拟地址
    dns = '8.8.8.8' # 不要修改，用于 DHCP 的 DNS 选项
    start_ip = '192.168.1.2' # 可修改，地址池起始地址
    end_ip = '192.168.1.100' # 可修改，地址池结束边界
    netmask = '255.255.255.0' # 可修改，子网掩码
    lease_time = 86400 # 可修改，DHCP 租约时间，单位为秒

    # 可以使用以上属性配置 DHCP 服务器。
    # 也可以添加 lease_time 等属性来支持 bonus 功能。


class DHCPServer():
    # 从 Config 读取 DHCP 服务端参数，后续组装报文和分配地址都会用到。
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = '192.168.1.1'
    lease_time = Config.lease_time

    # 记录 DHCP 地址分配状态：
    # allocated_ip: MAC -> IP，便于同一主机续租时拿回原地址。
    # ip_to_mac: IP -> MAC，便于判断某个 IP 是否已经被占用。
    # lease_expiration: MAC -> 过期时间戳，用于清理超时租约。
    allocated_ip = {}
    ip_to_mac = {}
    lease_expiration = {}

    # 下一次自动分配时优先检查的地址，实现地址池内的循环分配。
    next_ip = addrconv.ipv4.text_to_bin(start_ip)

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # 收到 DHCP REQUEST 后，确认客户端请求的地址，并返回 ACK。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        requested_ip = cls._get_client_ip(dhcp_pkt)
        client_ip = cls._allocate_ip(eth_pkt.src, requested_ip)

        ack_pkt = cls._assemble_reply(pkt, client_ip, dhcp.DHCP_ACK)
        return ack_pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # 收到 DHCP DISCOVER 后，先为客户端挑选一个地址并返回 OFFER。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        client_ip = cls._allocate_ip(eth_pkt.src)
        return cls._assemble_reply(pkt, client_ip, dhcp.DHCP_OFFER)

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # 根据 DHCP 消息类型选择处理流程：DISCOVER -> OFFER，REQUEST -> ACK。
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        msg_type = cls._get_message_type(dhcp_pkt)

        if msg_type == dhcp.DHCP_DISCOVER:
            cls._send_packet(datapath, port, cls.assemble_offer(pkt, datapath))
        elif msg_type == dhcp.DHCP_REQUEST:
            cls._send_packet(datapath, port, cls.assemble_ack(pkt, datapath, port))

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        # 将构造好的 DHCP 回复报文封装成 OpenFlow PacketOut，从入端口发回客户端。
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
        # 复用客户端原始 DHCP 报文中的事务 ID、硬件地址等字段，确保客户端能匹配回复。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',
            src=cls.hardware_addr,
            ethertype=ether.ETH_TYPE_IP))
        # DHCP 回复通常广播给客户端，因为客户端此时可能还没有配置 IP。
        reply_pkt.add_protocol(ipv4.ipv4(
            src=cls.server_ip,
            dst='255.255.255.255',
            proto=inet.IPPROTO_UDP))
        reply_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        # yiaddr 是分配给客户端的 IP；options 中携带消息类型、网关、DNS、租约时间等参数。
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
        # 从 DHCP options 中解析消息类型，例如 DISCOVER、REQUEST。
        for opt in dhcp_pkt.options.option_list:
            if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                return cls._option_value_to_int(opt.value)
        return None

    @classmethod
    def _get_client_ip(cls, dhcp_pkt):
        # REQUEST 报文可能通过 Requested IP Address 选项指定希望使用的地址。
        for opt in dhcp_pkt.options.option_list:
            if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:
                return addrconv.ipv4.bin_to_text(opt.value)
        return None

    @classmethod
    def _allocate_ip(cls, mac_addr, requested_ip=None):
        # 分配新地址前先清理过期租约，避免地址池被过期记录占住。
        cls._expire_leases()

        # 如果该 MAC 已经有租约，则直接续租并返回原 IP。
        if mac_addr in cls.allocated_ip:
            client_ip = cls.allocated_ip[mac_addr]
            cls._renew_lease(mac_addr, client_ip)
            return client_ip

        # 如果客户端请求了可用地址，优先满足客户端请求。
        if requested_ip and cls._ip_available_for_mac(requested_ip, mac_addr):
            cls._remember_ip(mac_addr, requested_ip)
            return requested_ip

        # 客户端没有指定可用地址时，从地址池中按 next_ip 开始循环查找空闲 IP。
        start = cls._ip_to_int(addrconv.ipv4.text_to_bin(cls.start_ip))
        end = cls._ip_to_int(addrconv.ipv4.text_to_bin(cls.end_ip))
        current = cls._ip_to_int(cls.next_ip)
        if current < start or current >= end:
            current = start

        pool_size = end - start
        for offset in range(pool_size):
            candidate = start + ((current - start + offset) % pool_size)
            candidate_ip = addrconv.ipv4.bin_to_text(cls._int_to_ip(candidate))
            if candidate_ip not in cls.ip_to_mac:
                cls._remember_ip(mac_addr, candidate_ip)
                # 记录下一个查找起点，避免每次都从地址池开头扫描。
                next_offset = (candidate - start + 1) % pool_size
                cls.next_ip = cls._int_to_ip(start + next_offset)
                return candidate_ip

        raise RuntimeError('No available DHCP address')

    @classmethod
    def _remember_ip(cls, mac_addr, client_ip):
        # 记录一条 MAC 与 IP 的绑定，并同时刷新租约时间。
        if not cls._ip_in_pool(client_ip):
            raise RuntimeError('Requested DHCP address is outside the address pool')

        # 如果同一 MAC 更换了 IP，需要移除旧 IP 的反向映射。
        old_ip = cls.allocated_ip.get(mac_addr)
        if old_ip and old_ip != client_ip:
            cls.ip_to_mac.pop(old_ip, None)

        # 防止不同 MAC 同时占用同一个 IP。
        owner = cls.ip_to_mac.get(client_ip)
        if owner and owner != mac_addr:
            raise RuntimeError('Requested DHCP address is already allocated')

        cls.allocated_ip[mac_addr] = client_ip
        cls.ip_to_mac[client_ip] = mac_addr
        cls._renew_lease(mac_addr, client_ip)

    @classmethod
    def _renew_lease(cls, mac_addr, client_ip):
        # 租约过期时间用当前时间加 lease_time 表示。
        cls.lease_expiration[mac_addr] = time.time() + cls.lease_time

    @classmethod
    def _expire_leases(cls):
        # 找出已经到期的 MAC，并释放它们占用的地址。
        now = time.time()
        expired_macs = [
            mac for mac, expires_at in cls.lease_expiration.items()
            if expires_at <= now
        ]
        for mac in expired_macs:
            client_ip = cls.allocated_ip.pop(mac, None)
            cls.lease_expiration.pop(mac, None)
            if client_ip and cls.ip_to_mac.get(client_ip) == mac:
                cls.ip_to_mac.pop(client_ip, None)

    @classmethod
    def _ip_available_for_mac(cls, ip_addr, mac_addr):
        # 请求的 IP 必须在地址池内，且没有被其他 MAC 占用。
        if not cls._ip_in_pool(ip_addr):
            return False
        owner = cls.ip_to_mac.get(ip_addr)
        return owner is None or owner == mac_addr

    @classmethod
    def _ip_in_pool(cls, ip_addr):
        # 判断地址是否落在 DHCP 地址池范围内，end_ip 作为结束边界不参与分配。
        ip_int = cls._ip_to_int(addrconv.ipv4.text_to_bin(ip_addr))
        start = cls._ip_to_int(addrconv.ipv4.text_to_bin(cls.start_ip))
        end = cls._ip_to_int(addrconv.ipv4.text_to_bin(cls.end_ip))
        return start <= ip_int < end

    @classmethod
    def _option_value_to_int(cls, value):
        # os_ken 中 DHCP option 的值可能已经是 int，也可能是 bytes，需要统一转成整数。
        if isinstance(value, int):
            return value
        return struct.unpack('!B', value[0:1])[0]

    @classmethod
    def _ip_to_int(cls, ip_bytes):
        # IPv4 的 4 字节网络序表示转成整数，便于比较和加减。
        return struct.unpack('!I', ip_bytes)[0]

    @classmethod
    def _int_to_ip(cls, ip_int):
        # 整数转回 4 字节网络序 IPv4，供 addrconv 或 DHCP option 使用。
        return struct.pack('!I', ip_int)
