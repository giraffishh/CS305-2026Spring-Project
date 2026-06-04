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
    # DHCP 服务器的基础配置。测试脚本中主机初始没有 IP，
    # 因此需要控制器在这个地址池中为它们分配地址。
    controller_macAddr = '7e:49:b3:f0:f9:99'
    dns = '8.8.8.8'
    start_ip = '192.168.1.2'
    end_ip = '192.168.1.100'
    netmask = '255.255.255.0'
    lease_time = 86400


class DHCPServer():
    """一个运行在 SDN 控制器中的简化 DHCP 服务器。

    controller.py 在收到 DHCP PacketIn 后会调用 handle_dhcp。
    本类负责识别 DHCP 消息类型、维护租约状态、构造 DHCP 回复包，
    并通过 OpenFlow PacketOut 将回复发送回对应主机。
    """

    # DHCP 回复包中使用的服务器参数。
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = '192.168.1.1'

    # 地址池采用左闭右开区间 [start_ip, end_ip)，
    # 因此默认可分配范围是 192.168.1.2 到 192.168.1.99。
    lease_time = Config.lease_time

    # OFFER 只是临时承诺，还没有正式绑定给客户端。
    # 如果客户端没有继续发送 REQUEST，该临时保留会在 60 秒后过期。
    offer_hold_time = 60

    # 如果客户端发送 DECLINE 表示该 IP 冲突，则暂时屏蔽该 IP，
    # 避免马上再次分配给其它客户端。
    declined_hold_time = 600

    # OFFERED 表示已经发出 OFFER 但还没 ACK；BOUND 表示正式租约。
    STATE_OFFERED = 'offered'
    STATE_BOUND = 'bound'

    # 核心租约表：
    # leases_by_mac 用于按客户端 MAC 查找它当前的租约；
    # leases_by_ip 用于按 IP 查找该地址是否已经被占用。
    # 两张表互相配合，保证同一 IP 不会分配给两个 MAC。
    leases_by_mac = {}
    leases_by_ip = {}

    # 记录被 DECLINE 的 IP 以及它们的屏蔽到期时间。
    declined_ip_until = {}

    # 兼容报告中的变量名。这三张表由 _sync_compatibility_maps 同步维护，
    # 方便答辩时说明 MAC->IP、IP->MAC 和租约过期时间。
    allocated_ip = {}
    ip_to_mac = {}
    lease_expiration = {}

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # REQUEST 阶段需要确认客户端请求的 IP 是否仍然合法可用。
        # 如果不可用，返回 None，外层会发送 DHCP NAK。
        client_ip = cls._confirm_requested_ip(pkt)
        if client_ip is None:
            return None
        return cls._assemble_reply(pkt, client_ip, dhcp.DHCP_ACK)

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # DISCOVER 阶段选择一个可用 IP，并以 OFFERED 状态临时保留。
        client_ip = cls._offer_ip(pkt)
        if client_ip is None:
            return None
        return cls._assemble_reply(pkt, client_ip, dhcp.DHCP_OFFER)

    @classmethod
    def assemble_nak(cls, pkt):
        # DHCP NAK 用于拒绝非法或冲突的 REQUEST。
        # os-ken 版本差异下可能没有 DHCP_NAK 常量，因此使用 6 作为兜底值。
        return cls._assemble_reply(pkt, '0.0.0.0',
                                   getattr(dhcp, 'DHCP_NAK', 6))

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # 每次处理 DHCP 包前先清理过期租约，确保过期 IP 可以重新使用。
        cls._purge_expired_leases()

        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        msg_type = cls._get_message_type(dhcp_pkt)

        if msg_type == dhcp.DHCP_DISCOVER:
            # 客户端广播 DISCOVER，服务器返回 OFFER。
            cls._send_packet(datapath, port, cls.assemble_offer(pkt, datapath))
        elif msg_type == dhcp.DHCP_REQUEST:
            # 客户端确认想使用某个 IP。合法则 ACK，否则 NAK。
            ack_pkt = cls.assemble_ack(pkt, datapath, port)
            if ack_pkt is None:
                ack_pkt = cls.assemble_nak(pkt)
            cls._send_packet(datapath, port, ack_pkt)
        elif msg_type == getattr(dhcp, 'DHCP_RELEASE', 7):
            # 客户端主动释放租约，服务器立即删除对应记录。
            cls._release_client(pkt)
        elif msg_type == getattr(dhcp, 'DHCP_DECLINE', 4):
            # 客户端认为该 IP 冲突，服务器删除租约并暂时屏蔽该 IP。
            cls._decline_requested_ip(pkt)

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        # DHCP 回复通过 OpenFlow PacketOut 直接从收到请求的端口发回去。
        if pkt is None:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)

    @classmethod
    def _assemble_reply(cls, pkt, client_ip, msg_type):
        # 根据收到的 DHCP 请求构造回复包。这里保留 xid、chaddr 等字段，
        # 让客户端能够把回复和自己的请求对应起来。
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        # 所有 DHCP 回复都需要携带消息类型和服务器标识。
        options = [
            dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT,
                        struct.pack('!B', msg_type)),
            dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                        addrconv.ipv4.text_to_bin(cls.server_ip)),
        ]

        # OFFER/ACK 需要携带网络配置；NAK 不分配地址，所以只保留必要选项。
        if msg_type in (dhcp.DHCP_OFFER, dhcp.DHCP_ACK):
            options.extend([
                dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT,
                            addrconv.ipv4.text_to_bin(cls.netmask)),
                dhcp.option(dhcp.DHCP_GATEWAY_ADDR_OPT,
                            addrconv.ipv4.text_to_bin(cls.server_ip)),
                dhcp.option(dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                            addrconv.ipv4.text_to_bin(cls.dns)),
                dhcp.option(dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                            struct.pack('!I', cls.lease_time)),
            ])

        reply_pkt = packet.Packet()
        # DHCP 初始阶段客户端可能还没有 IP，因此使用广播 MAC/IP 返回。
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
            options=dhcp.options(option_list=options)))
        return reply_pkt

    @classmethod
    def _offer_ip(cls, pkt):
        # 为 DISCOVER 选择 OFFER 地址。优先返回客户端已有的有效租约，
        # 其次尝试客户端请求的 IP，最后从地址池中找第一个可用 IP。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        mac_addr = cls._normalize_mac(eth_pkt.src)

        existing_lease = cls._active_lease_for_mac(mac_addr)
        if existing_lease:
            # 如果已经有 BOUND 租约，不要把它降级成短期 OFFER；
            # 如果只是 OFFERED，则刷新 OFFER 保留时间。
            if existing_lease['state'] == cls.STATE_OFFERED:
                cls._reserve_offer(mac_addr, existing_lease['ip'], dhcp_pkt.xid)
            return existing_lease['ip']

        requested_ip = cls._get_requested_ip(dhcp_pkt)
        if requested_ip and cls._ip_is_available_for_mac(requested_ip, mac_addr):
            cls._reserve_offer(mac_addr, requested_ip, dhcp_pkt.xid)
            return requested_ip

        client_ip = cls._find_free_ip(mac_addr)
        if client_ip:
            cls._reserve_offer(mac_addr, client_ip, dhcp_pkt.xid)
        return client_ip

    @classmethod
    def _confirm_requested_ip(cls, pkt):
        # 为 REQUEST 确认最终地址。REQUEST 中可能通过 option 50 指定 IP；
        # 续租时也可能放在 ciaddr 字段中。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        mac_addr = cls._normalize_mac(eth_pkt.src)

        requested_ip = cls._get_requested_ip(dhcp_pkt)
        if requested_ip is None and dhcp_pkt.ciaddr != '0.0.0.0':
            requested_ip = dhcp_pkt.ciaddr
        if requested_ip is None:
            requested_ip = cls._active_ip_for_mac(mac_addr)
        if requested_ip is None:
            requested_ip = cls._find_free_ip(mac_addr)

        if not cls._ip_is_available_for_mac(requested_ip, mac_addr):
            # 请求的地址不存在、超出地址池、被 DECLINE 屏蔽、
            # 或已经属于其它 MAC 时，拒绝该 REQUEST。
            return None

        # REQUEST 合法后，租约从 OFFERED 转为 BOUND。
        cls._bind_lease(mac_addr, requested_ip, dhcp_pkt.xid)
        return requested_ip

    @classmethod
    def _reserve_offer(cls, mac_addr, client_ip, xid=None):
        # 临时保留 OFFER 地址，防止同一 IP 同时 OFFER 给多个客户端。
        cls._remove_mac_lease(mac_addr)
        lease = cls._build_lease(mac_addr, client_ip, cls.STATE_OFFERED,
                                 cls.offer_hold_time, xid)
        cls.leases_by_mac[mac_addr] = lease
        cls.leases_by_ip[client_ip] = lease
        cls._sync_compatibility_maps()

    @classmethod
    def _bind_lease(cls, mac_addr, client_ip, xid=None):
        # 正式绑定租约。如果同一 MAC 之前绑定了不同 IP，
        # 先释放旧 IP，再绑定新 IP。
        current = cls.leases_by_mac.get(mac_addr)
        if current and current['ip'] != client_ip:
            cls.leases_by_ip.pop(current['ip'], None)

        lease = cls._build_lease(mac_addr, client_ip, cls.STATE_BOUND,
                                 cls.lease_time, xid)
        cls.leases_by_mac[mac_addr] = lease
        cls.leases_by_ip[client_ip] = lease
        cls._sync_compatibility_maps()

    @classmethod
    def _build_lease(cls, mac_addr, client_ip, state, lease_time, xid=None):
        # 统一构造租约对象，expires_at 是绝对过期时间。
        return {
            'mac': mac_addr,
            'ip': client_ip,
            'state': state,
            'xid': xid,
            'expires_at': cls._now() + lease_time,
            'lease_time': lease_time,
        }

    @classmethod
    def _release_client(cls, pkt):
        # DHCP RELEASE 不需要回复，只要删除该 MAC 的租约即可。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        cls._remove_mac_lease(cls._normalize_mac(eth_pkt.src))

    @classmethod
    def _decline_requested_ip(cls, pkt):
        # DHCP DECLINE 表示客户端检测到地址冲突。
        # 删除该客户端租约，并把被拒绝的 IP 临时加入黑名单。
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        mac_addr = cls._normalize_mac(eth_pkt.src)
        declined_ip = cls._get_requested_ip(dhcp_pkt)
        cls._remove_mac_lease(mac_addr)
        if declined_ip and cls._ip_in_pool(declined_ip):
            cls.declined_ip_until[declined_ip] = (
                cls._now() + cls.declined_hold_time
            )

    @classmethod
    def _remove_mac_lease(cls, mac_addr):
        # 同时从 MAC->lease 和 IP->lease 两张表中删除租约。
        lease = cls.leases_by_mac.pop(mac_addr, None)
        if lease:
            cls.leases_by_ip.pop(lease['ip'], None)
        cls._sync_compatibility_maps()

    @classmethod
    def _purge_expired_leases(cls):
        # 清理 OFFER 超时、正式租约过期，以及 DECLINE 屏蔽到期的地址。
        now = cls._now()

        for mac_addr, lease in list(cls.leases_by_mac.items()):
            if lease['expires_at'] <= now:
                cls.leases_by_mac.pop(mac_addr, None)
                cls.leases_by_ip.pop(lease['ip'], None)

        for ip_addr, expires_at in list(cls.declined_ip_until.items()):
            if expires_at <= now:
                cls.declined_ip_until.pop(ip_addr, None)

        cls._sync_compatibility_maps()

    @classmethod
    def _ip_is_available_for_mac(cls, ip_addr, mac_addr):
        # IP 可用需要满足三个条件：
        # 1. 不为空且在地址池内；
        # 2. 没有处于 DECLINE 屏蔽期；
        # 3. 没有被其它 MAC 的有效租约占用。
        if not ip_addr or not cls._ip_in_pool(ip_addr):
            return False
        if cls._ip_is_declined(ip_addr):
            return False

        lease = cls.leases_by_ip.get(ip_addr)
        if lease is None:
            return True
        return lease['mac'] == mac_addr

    @classmethod
    def _active_ip_for_mac(cls, mac_addr):
        lease = cls._active_lease_for_mac(mac_addr)
        return lease['ip'] if lease else None

    @classmethod
    def _active_lease_for_mac(cls, mac_addr):
        lease = cls.leases_by_mac.get(mac_addr)
        if lease and lease['expires_at'] > cls._now():
            return lease
        return None

    @classmethod
    def _find_free_ip(cls, mac_addr):
        # 顺序扫描地址池，找到第一个对该 MAC 可用的 IP。
        for ip_int in range(cls._pool_start_int(), cls._pool_end_int()):
            ip_addr = cls._int_to_ip_text(ip_int)
            if cls._ip_is_available_for_mac(ip_addr, mac_addr):
                return ip_addr
        return None

    @classmethod
    def _sync_compatibility_maps(cls):
        # 将核心租约表同步为报告中更直观的三张表。
        # 这些表不是额外状态来源，只是 leases_by_mac 的派生视图。
        active_leases = {
            mac: lease for mac, lease in cls.leases_by_mac.items()
            if lease['expires_at'] > cls._now()
        }
        cls.allocated_ip = {
            mac: lease['ip'] for mac, lease in active_leases.items()
        }
        cls.ip_to_mac = {
            lease['ip']: mac for mac, lease in active_leases.items()
        }
        cls.lease_expiration = {
            mac: lease['expires_at'] for mac, lease in active_leases.items()
        }

    @classmethod
    def _get_message_type(cls, dhcp_pkt):
        for opt in dhcp_pkt.options.option_list:
            if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                return cls._option_value_to_int(opt.value)
        return None

    @classmethod
    def _get_requested_ip(cls, dhcp_pkt):
        for opt in dhcp_pkt.options.option_list:
            if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:
                return cls._option_value_to_ip(opt.value)
        return None

    @classmethod
    def _option_value_to_int(cls, value):
        if isinstance(value, int):
            return value
        return struct.unpack('!B', value[0:1])[0]

    @classmethod
    def _option_value_to_ip(cls, value):
        if isinstance(value, str):
            return value
        return addrconv.ipv4.bin_to_text(value)

    @classmethod
    def _normalize_mac(cls, mac_addr):
        return mac_addr.lower()

    @classmethod
    def _ip_in_pool(cls, ip_addr):
        ip_int = cls._ip_text_to_int(ip_addr)
        return cls._pool_start_int() <= ip_int < cls._pool_end_int()

    @classmethod
    def _ip_is_declined(cls, ip_addr):
        return cls.declined_ip_until.get(ip_addr, 0) > cls._now()

    @classmethod
    def _pool_start_int(cls):
        return cls._ip_text_to_int(cls.start_ip)

    @classmethod
    def _pool_end_int(cls):
        return cls._ip_text_to_int(cls.end_ip)

    @classmethod
    def _ip_text_to_int(cls, ip_addr):
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_addr))[0]

    @classmethod
    def _int_to_ip_text(cls, ip_int):
        return addrconv.ipv4.bin_to_text(struct.pack('!I', ip_int))

    @classmethod
    def _now(cls):
        return time.time()
