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
    # 指定当前控制器支持的 OpenFlow 版本。
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    # 下发二层转发流表时使用的 cookie，用于后续区分和删除。
    SWITCHING_COOKIE = 0x3055
    # 二层转发规则的优先级，高于默认 table-miss。
    SWITCHING_PRIORITY = 100
    # 默认最短路算法，可通过环境变量覆盖。
    DEFAULT_ROUTING_ALGORITHM = "dijkstra"
    ROUTING_ALGORITHMS = ("dijkstra", "bellman_ford")

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        # 维护当前在线交换机 datapath 对象，key 为交换机 dpid。
        self.datapaths = {}
        # 为每台交换机缓存对应的 OfCtl 封装，便于统一下发流表或报文。
        self.ofctls = {}
        # 记录当前拓扑中已知的交换机集合。
        self.switches = set()
        # 邻接表形式的链路视图：links[src_dpid][dst_dpid] = src_port。
        self.links = defaultdict(dict)
        # 主机学习表：MAC -> {dpid, port, ip}。
        self.hosts_by_mac = {}
        # ARP 学到的 IP/MAC 映射，用于快速响应 ARP 请求。
        self.mac_by_ip = {}
        # 已安装的目的 MAC 转发表项，避免重复下发。
        self.installed_mac_flows = {}
        self.firewall = Firewall()
        # 保存上一次打印的路径快照，避免日志重复刷屏。
        self.last_logged_paths = None
        # 根据环境变量选择路径算法。
        self.routing_algorithm = self._select_routing_algorithm()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # 交换机刚连接控制器时，下发 table-miss，将未知报文送到控制器。
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
        # 在交换机初始化完成后同步安装防火墙规则。
        self.firewall.install_rules(self.ofctls)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """
        # 新交换机加入时更新本地拓扑缓存，并重新计算转发路径。
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
        # 交换机离线后清理相关状态，避免保留失效链路和主机信息。
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
        # 主机接入后记录其接入交换机、端口和 IP，并刷新全网转发表。
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
        # 链路加入后更新双向邻接关系。
        link = ev.link
        self._add_link(link.src.dpid, link.dst.dpid,
                       link.src.port_no, link.dst.port_no)
        self._recompute_paths()

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # 链路删除后从邻接表中移除，并重新下发可达路径。
        link = ev.link
        self._remove_link(link.src.dpid, link.dst.dpid)
        self._recompute_paths()
   
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # 端口状态变化可能影响主机连通性或链路状态，因此统一触发重算。
        self._recompute_paths()



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            # table-miss 上送的报文在这里统一处理，目前主要区分 DHCP 与非 DHCP。
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
        # 当前仅对 ARP 报文进行额外处理，其余报文依赖预装流表转发。
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if pkt_arp and pkt_eth:
            self._handle_arp(datapath, in_port, pkt_arp, pkt_eth)

    def _handle_arp(self, datapath, in_port, pkt_arp, pkt_eth):
        # 无论请求还是响应，先借助 ARP 源信息学习主机位置。
        self._learn_host(pkt_arp.src_mac, datapath.id, in_port, pkt_arp.src_ip)

        if pkt_arp.opcode == arp.ARP_REPLY:
            # 收到 ARP 响应说明主机已经活跃，可据此重算路径。
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
        # 若已知目标 IP 对应的 MAC，则由控制器直接代答 ARP。
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
        # 延迟初始化 OfCtl，确保任意已知 datapath 都能被统一操作。
        if datapath.id not in self.ofctls:
            self.datapaths[datapath.id] = datapath
            self.ofctls[datapath.id] = OfCtl.factory(datapath, self.logger)
        self.switches.add(datapath.id)
        return self.ofctls[datapath.id]

    def _learn_host(self, mac, dpid, port_no, ip_addr=None):
        # 更新主机位置；如果主机迁移到新端口，这里会直接覆盖旧记录。
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
        # 控制器内部使用无向图表示交换机之间链路，因此双向写入。
        self.switches.add(src_dpid)
        self.switches.add(dst_dpid)
        self.links[src_dpid][dst_dpid] = src_port
        self.links[dst_dpid][src_dpid] = dst_port

    def _remove_link(self, src_dpid, dst_dpid):
        # 删除链路时同样要清除双向邻接信息。
        self.links[src_dpid].pop(dst_dpid, None)
        self.links[dst_dpid].pop(src_dpid, None)

    def _select_routing_algorithm(self):
        # 允许通过环境变量切换最短路算法，便于实验对比。
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
        # 根据配置分派到对应的最短路径算法实现。
        if self.routing_algorithm == "bellman_ford":
            return self._bellman_ford_switch_path(src_dpid, dst_dpid)
        return self._dijkstra_switch_path(src_dpid, dst_dpid)

    def _dijkstra_switch_path(self, src_dpid, dst_dpid):
        # 在无权图中使用 Dijkstra，等价于按跳数寻找最短路径。
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
        # Bellman-Ford 版本同样按单位边权计算，便于和 Dijkstra 做实验对照。
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
        # 根据当前拓扑和主机学习结果，重新整理每台交换机的目的 MAC 转发规则。
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
            # 如果某条旧规则已经不再需要，则主动删除，避免错误转发。
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
        # 计算从源交换机前往目标主机时，第一跳应该走哪个端口。
        dst_dpid = dst_host["dpid"]
        if src_dpid == dst_dpid:
            return dst_host["port"]

        path = self._shortest_switch_path(src_dpid, dst_dpid)
        if not path or len(path) < 2:
            return None
        return self.links[src_dpid].get(path[1])

    def _install_mac_flow(self, datapath, dst_mac, out_port):
        # 为“目的 MAC -> 输出端口”安装二层转发表项。
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
        # 删除指定交换机上匹配目标 MAC 的旧流表项。
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
        # 打印主机对之间的路径和距离，便于观察当前算法下的转发结果。
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
    
