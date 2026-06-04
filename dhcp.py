# -*- coding: utf-8 -*-
import logging
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
    controller_macAddr = '7e:49:b3:f0:f9:99'
    dns = '8.8.8.8'
    start_ip = '192.168.1.2'
    end_ip = '192.168.1.100'
    netmask = '255.255.255.0'
    lease_time = 86400


class DHCPServer():
    logger = logging.getLogger('DHCPServer')
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = '192.168.1.1'

    # The address pool uses [start_ip, end_ip), so the default range is
    # 192.168.1.2 through 192.168.1.99.
    lease_time = Config.lease_time
    offer_hold_time = 60
    declined_hold_time = 600

    STATE_OFFERED = 'offered'
    STATE_BOUND = 'bound'

    leases_by_mac = {}
    leases_by_ip = {}
    declined_ip_until = {}

    # Compatibility aliases for the bonus report wording.
    allocated_ip = {}
    ip_to_mac = {}
    lease_expiration = {}

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        client_ip = cls._confirm_requested_ip(pkt)
        if client_ip is None:
            return None
        return cls._assemble_reply(pkt, client_ip, dhcp.DHCP_ACK)

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        client_ip = cls._offer_ip(pkt)
        if client_ip is None:
            return None
        return cls._assemble_reply(pkt, client_ip, dhcp.DHCP_OFFER)

    @classmethod
    def assemble_nak(cls, pkt):
        return cls._assemble_reply(pkt, '0.0.0.0',
                                   getattr(dhcp, 'DHCP_NAK', 6))

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        cls._purge_expired_leases()

        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        msg_type = cls._get_message_type(dhcp_pkt)

        if msg_type == dhcp.DHCP_DISCOVER:
            offer_pkt = cls.assemble_offer(pkt, datapath)
            if offer_pkt is None:
                cls._log_pool_exhausted(pkt)
                offer_pkt = cls.assemble_nak(pkt)
            cls._send_packet(datapath, port, offer_pkt)
        elif msg_type == dhcp.DHCP_REQUEST:
            ack_pkt = cls.assemble_ack(pkt, datapath, port)
            if ack_pkt is None:
                cls._log_pool_exhausted(pkt)
                ack_pkt = cls.assemble_nak(pkt)
            cls._send_packet(datapath, port, ack_pkt)
        elif msg_type == getattr(dhcp, 'DHCP_RELEASE', 7):
            cls._release_client(pkt)
        elif msg_type == getattr(dhcp, 'DHCP_DECLINE', 4):
            cls._decline_requested_ip(pkt)

    @classmethod
    def _log_pool_exhausted(cls, pkt):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        mac_addr = cls._normalize_mac(eth_pkt.src) if eth_pkt else 'unknown'
        message = (
            'DHCP address pool exhausted: no available IP for %s '
            'in [%s, %s)' % (mac_addr, cls.start_ip, cls.end_ip)
        )
        cls.logger.warning(message)
        print(message, flush=True)

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
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
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        options = [
            dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT,
                        struct.pack('!B', msg_type)),
            dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                        addrconv.ipv4.text_to_bin(cls.server_ip)),
        ]

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
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        mac_addr = cls._normalize_mac(eth_pkt.src)

        existing_lease = cls._active_lease_for_mac(mac_addr)
        if existing_lease:
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
            return None

        cls._bind_lease(mac_addr, requested_ip, dhcp_pkt.xid)
        return requested_ip

    @classmethod
    def _reserve_offer(cls, mac_addr, client_ip, xid=None):
        cls._remove_mac_lease(mac_addr)
        lease = cls._build_lease(mac_addr, client_ip, cls.STATE_OFFERED,
                                 cls.offer_hold_time, xid)
        cls.leases_by_mac[mac_addr] = lease
        cls.leases_by_ip[client_ip] = lease
        cls._sync_compatibility_maps()

    @classmethod
    def _bind_lease(cls, mac_addr, client_ip, xid=None):
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
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        cls._remove_mac_lease(cls._normalize_mac(eth_pkt.src))

    @classmethod
    def _decline_requested_ip(cls, pkt):
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
        lease = cls.leases_by_mac.pop(mac_addr, None)
        if lease:
            cls.leases_by_ip.pop(lease['ip'], None)
        cls._sync_compatibility_maps()

    @classmethod
    def _purge_expired_leases(cls):
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
        for ip_int in range(cls._pool_start_int(), cls._pool_end_int()):
            ip_addr = cls._int_to_ip_text(ip_int)
            if cls._ip_is_available_for_mac(ip_addr, mac_addr):
                return ip_addr
        return None

    @classmethod
    def _sync_compatibility_maps(cls):
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
