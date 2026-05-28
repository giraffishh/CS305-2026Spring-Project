from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.topology import event
from os_ken.topology.switches import Switch, Host, HostState, Port, PortState, PortData, PortDataState, Link, LinkState
from os_ken.topology.switches import Switches
from os_ken.ofproto import ofproto_v1_0, ether, inet
from os_ken.lib.packet import packet, ethernet, ether_types, arp
from os_ken.lib.packet import dhcp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from dhcp import DHCPServer
from collections import defaultdict
import os
import time
from ofctl_utilis import OfCtl,OfCtl_v1_0,OfCtl_after_v1_2,VLANID_NONE
import logging
import copy
import heapq
from firewall import Firewall


class ControllerApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    SWITCHING_COOKIE = 0x3055
    SWITCHING_PRIORITY = 100
    DEFAULT_ROUTING_ALGORITHM = "dijkstra"
    ROUTING_ALGORITHMS = ("dijkstra", "bellman_ford")

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.ofctls = {}
        self.switches = set()
        self.links = defaultdict(dict)
        self.hosts_by_mac = {}
        self.mac_by_ip = {}
        self.installed_mac_flows = {}
        self.firewall = Firewall()
        self.last_logged_paths = None
        self.routing_algorithm = self._select_routing_algorithm()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.ofctls[datapath.id] = OfCtl.factory(datapath, self.logger)
        self.switches.add(datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            priority=0,
            flags=0,
            actions=actions)
        datapath.send_msg(mod)
        self.firewall.install_rules(self.ofctls)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """
        datapath = ev.switch.dp
        self.datapaths[datapath.id] = datapath
        self.ofctls[datapath.id] = OfCtl.factory(datapath, self.logger)
        self.switches.add(datapath.id)
        self.firewall.install_rules(self.ofctls)
        self._recompute_paths()

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """
        dpid = ev.switch.dp.id
        self.switches.discard(dpid)
        self.datapaths.pop(dpid, None)
        self.ofctls.pop(dpid, None)
        self.links.pop(dpid, None)
        for neighbors in self.links.values():
            neighbors.pop(dpid, None)
        self.hosts_by_mac = {
            mac: host for mac, host in self.hosts_by_mac.items()
            if host["dpid"] != dpid
        }
        self.mac_by_ip = {
            ip: mac for ip, mac in self.mac_by_ip.items()
            if mac in self.hosts_by_mac
        }
        self._recompute_paths()


    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """ 
        host = ev.host
        if not host.port:
            return
        self._learn_host(host.mac, host.port.dpid, host.port.port_no,
                         host.ipv4[0] if host.ipv4 else None)
        self._recompute_paths()

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        link = ev.link
        self._add_link(link.src.dpid, link.dst.dpid,
                       link.src.port_no, link.dst.port_no)
        self._recompute_paths()

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        link = ev.link
        self._remove_link(link.src.dpid, link.dst.dpid)
        self._recompute_paths()
   
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        self._recompute_paths()



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            inPort = msg.in_port
            if not pkt_dhcp:
                self._handle_non_dhcp_packet(datapath, inPort, pkt, msg.data)
            else:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)      
            return 
        except Exception as e:
            self.logger.error(e)

    def _handle_non_dhcp_packet(self, datapath, in_port, pkt, msg_data):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if pkt_arp and pkt_eth:
            self._handle_arp(datapath, in_port, pkt_arp, pkt_eth)

    def _handle_arp(self, datapath, in_port, pkt_arp, pkt_eth):
        self._learn_host(pkt_arp.src_mac, datapath.id, in_port, pkt_arp.src_ip)

        if pkt_arp.opcode == arp.ARP_REPLY:
            self._recompute_paths()
            return

        if pkt_arp.opcode != arp.ARP_REQUEST:
            return

        dst_mac = self.mac_by_ip.get(pkt_arp.dst_ip)
        if not dst_mac:
            self.logger.info("Unknown ARP target %s from %s",
                             pkt_arp.dst_ip, pkt_arp.src_ip)
            return

        ofctl = self._get_ofctl(datapath)
        ofctl.send_arp(
            arp.ARP_REPLY,
            VLANID_NONE,
            pkt_arp.src_mac,
            dst_mac,
            pkt_arp.dst_ip,
            pkt_arp.src_ip,
            pkt_arp.src_mac,
            datapath.ofproto.OFPP_CONTROLLER,
            in_port
        )
        self.logger.info("ARP reply: %s is at %s", pkt_arp.dst_ip, dst_mac)
        self._recompute_paths()

    def _get_ofctl(self, datapath):
        if datapath.id not in self.ofctls:
            self.datapaths[datapath.id] = datapath
            self.ofctls[datapath.id] = OfCtl.factory(datapath, self.logger)
        self.switches.add(datapath.id)
        return self.ofctls[datapath.id]

    def _learn_host(self, mac, dpid, port_no, ip_addr=None):
        if not mac:
            return
        self.switches.add(dpid)
        self.hosts_by_mac[mac] = {
            "dpid": dpid,
            "port": port_no,
            "ip": ip_addr
        }
        if ip_addr:
            self.mac_by_ip[ip_addr] = mac

    def _add_link(self, src_dpid, dst_dpid, src_port, dst_port):
        self.switches.add(src_dpid)
        self.switches.add(dst_dpid)
        self.links[src_dpid][dst_dpid] = src_port
        self.links[dst_dpid][src_dpid] = dst_port

    def _remove_link(self, src_dpid, dst_dpid):
        self.links[src_dpid].pop(dst_dpid, None)
        self.links[dst_dpid].pop(src_dpid, None)

    def _select_routing_algorithm(self):
        algorithm = os.environ.get(
            "CS305_ROUTING_ALGORITHM",
            self.DEFAULT_ROUTING_ALGORITHM
        ).lower()
        if algorithm not in self.ROUTING_ALGORITHMS:
            self.logger.warning(
                "Unknown routing algorithm %s, fallback to %s",
                algorithm,
                self.DEFAULT_ROUTING_ALGORITHM
            )
            return self.DEFAULT_ROUTING_ALGORITHM
        return algorithm

    def _shortest_switch_path(self, src_dpid, dst_dpid):
        if self.routing_algorithm == "bellman_ford":
            return self._bellman_ford_switch_path(src_dpid, dst_dpid)
        return self._dijkstra_switch_path(src_dpid, dst_dpid)

    def _dijkstra_switch_path(self, src_dpid, dst_dpid):
        if src_dpid == dst_dpid:
            return [src_dpid]
        queue = [(0, src_dpid, [src_dpid])]
        visited = set()

        while queue:
            distance, dpid, path = heapq.heappop(queue)
            if dpid in visited:
                continue
            visited.add(dpid)
            if dpid == dst_dpid:
                return path
            for neighbor in sorted(self.links.get(dpid, {})):
                if neighbor not in visited:
                    heapq.heappush(queue, (distance + 1, neighbor,
                                           path + [neighbor]))
        return None

    def _bellman_ford_switch_path(self, src_dpid, dst_dpid):
        if src_dpid == dst_dpid:
            return [src_dpid]

        nodes = set(self.switches)
        for src, neighbors in self.links.items():
            nodes.add(src)
            nodes.update(neighbors.keys())

        if src_dpid not in nodes or dst_dpid not in nodes:
            return None

        distance = {dpid: float("inf") for dpid in nodes}
        previous = {}
        distance[src_dpid] = 0

        edges = []
        for src in sorted(self.links):
            for dst in sorted(self.links[src]):
                edges.append((src, dst))

        for _ in range(max(len(nodes) - 1, 0)):
            updated = False
            for src, dst in edges:
                if distance[src] + 1 < distance[dst]:
                    distance[dst] = distance[src] + 1
                    previous[dst] = src
                    updated = True
            if not updated:
                break

        if distance[dst_dpid] == float("inf"):
            return None

        path = [dst_dpid]
        while path[-1] != src_dpid:
            parent = previous.get(path[-1])
            if parent is None:
                return None
            path.append(parent)
        path.reverse()
        return path

    def _recompute_paths(self):
        desired_flows = {}
        for dst_mac, dst_host in list(self.hosts_by_mac.items()):
            for src_dpid in list(self.switches):
                datapath = self.datapaths.get(src_dpid)
                if not datapath:
                    continue
                out_port = self._output_port_to_host(src_dpid, dst_host)
                if out_port is None:
                    continue
                desired_flows[(src_dpid, dst_mac)] = out_port

        for key, old_port in list(self.installed_mac_flows.items()):
            dpid, dst_mac = key
            if key in desired_flows:
                continue
            datapath = self.datapaths.get(dpid)
            if datapath:
                self._delete_mac_flow(datapath, dst_mac)
            self.installed_mac_flows.pop(key, None)

        for (dpid, dst_mac), out_port in desired_flows.items():
            datapath = self.datapaths.get(dpid)
            if datapath:
                self._install_mac_flow(datapath, dst_mac, out_port)

        self._log_host_paths()

    def _output_port_to_host(self, src_dpid, dst_host):
        dst_dpid = dst_host["dpid"]
        if src_dpid == dst_dpid:
            return dst_host["port"]

        path = self._shortest_switch_path(src_dpid, dst_dpid)
        if not path or len(path) < 2:
            return None
        return self.links[src_dpid].get(path[1])

    def _install_mac_flow(self, datapath, dst_mac, out_port):
        key = (datapath.id, dst_mac)
        if self.installed_mac_flows.get(key) == out_port:
            return

        if key in self.installed_mac_flows:
            self._delete_mac_flow(datapath, dst_mac)

        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port, 0)]
        self._get_ofctl(datapath).set_flow(
            self.SWITCHING_COOKIE,
            self.SWITCHING_PRIORITY,
            dl_dst=dst_mac,
            actions=actions
        )
        self.installed_mac_flows[key] = out_port

    def _delete_mac_flow(self, datapath, dst_mac):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            ofp.OFPFW_ALL & ~ofp.OFPFW_DL_DST,
            0,
            0,
            dst_mac,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        )
        mod = parser.OFPFlowMod(
            datapath,
            match,
            self.SWITCHING_COOKIE,
            ofp.OFPFC_DELETE,
            idle_timeout=0,
            hard_timeout=0,
            priority=self.SWITCHING_PRIORITY,
            actions=[]
        )
        datapath.send_msg(mod)

    def _log_host_paths(self):
        hosts = sorted(
            (host["ip"], mac, host)
            for mac, host in self.hosts_by_mac.items()
            if host.get("ip")
        )
        path_logs = []
        for src_ip, src_mac, src_host in hosts:
            for dst_ip, dst_mac, dst_host in hosts:
                if src_mac == dst_mac:
                    continue
                path = self._shortest_switch_path(src_host["dpid"],
                                                  dst_host["dpid"])
                if not path:
                    continue
                full_path = (
                    ["host_%s" % src_mac] +
                    ["switch_%s" % dpid for dpid in path] +
                    ["host_%s" % dst_mac]
                )
                path_logs.append((
                    src_mac,
                    dst_mac,
                    len(path) + 1,
                    " -> ".join(full_path)
                ))

        snapshot = (self.routing_algorithm, tuple(path_logs))
        if snapshot == self.last_logged_paths:
            return
        self.last_logged_paths = snapshot

        if path_logs:
            self.logger.info("Routing algorithm: %s", self.routing_algorithm)

        for src_mac, dst_mac, distance, path_text in path_logs:
            self.logger.info("The distance from host_%s to host_%s : %s",
                             src_mac, dst_mac, distance)
            self.logger.info("Path: %s", path_text)
    
