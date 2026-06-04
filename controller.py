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
        # ---------------- 全局拓扑状态 ----------------
        # 这个控制器不依赖交换机自己做 MAC learning，而是在控制器里保存
        # 一份全局网络视图。后面的 switch/link/host 事件处理函数都会更新
        # 这些表，最短路计算和流表下发也都基于这些表完成。

        # dpid -> datapath。datapath 是 os-ken 表示某台交换机 OpenFlow
        # 连接的对象，控制器需要通过它向交换机发送 FlowMod、PacketOut 等消息。
        self.datapaths = {}
        # dpid -> OfCtl。OfCtl 是本项目封装的 OpenFlow 工具类，缓存起来后
        # 安装流表、发送 ARP 包时不用反复创建。它依赖 datapath，但接口更方便。
        self.ofctls = {}
        # 当前控制器已经知道的交换机 dpid 集合。最短路算法会把这里的 dpid
        # 当作图中的点；有些 dpid 可能先从拓扑事件学到，真正下发流表时仍会
        # 检查 datapaths 中是否存在可用连接。
        self.switches = set()
        # 交换机之间的邻接表：links[src_dpid][dst_dpid] = src_port。
        # 含义是：如果数据包在 src_dpid 上，下一跳要去 dst_dpid，就应该从
        # src_port 这个端口发出。由于 Mininet 中交换机链路按无向边理解，
        # _add_link 会同时写入两个方向。
        self.links = defaultdict(dict)
        # 主机位置表：MAC -> {dpid, port, ip}。dpid/port 表示该主机接在哪台
        # 交换机的哪个端口，ip 用于 ARP 代答。这个表是“主机是图的叶子节点”
        # 的关键来源。
        self.hosts_by_mac = {}
        # IP -> MAC。控制器收到 ARP request 时，用目标 IP 查这个表；如果能
        # 找到 MAC，就直接构造 ARP reply 返回给源主机，避免在全网广播 ARP。
        self.mac_by_ip = {}
        # (dpid, dst_mac) -> out_port。记录已经安装过的目的 MAC 转发表项，
        # 用来避免重复下发同一条规则，也方便拓扑变化后删除旧规则。
        self.installed_mac_flows = {}
        self.firewall = Firewall()
        # 保存上一次打印的路径快照，避免日志重复刷屏。
        self.last_logged_paths = None
        # 根据环境变量选择路径算法。
        self.routing_algorithm = self._select_routing_algorithm()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # EventOFPSwitchFeatures 是 OpenFlow 握手阶段的事件，说明交换机已经
        # 和控制器建立连接。这里先把 datapath/OfCtl 放进全局状态表，这样
        # 后续拓扑事件或 PacketIn 到来时，控制器能找到对应交换机并下发消息。
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.ofctls[datapath.id] = OfCtl.factory(datapath, self.logger)
        self.switches.add(datapath.id)

        # 安装 table-miss 流表项：没有命中更高优先级规则的报文会被送到
        # 控制器。DHCP、ARP 以及尚未安装路径规则的首批报文都依赖这条规则
        # 触发 PacketIn。
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
        # os-ken 拓扑模块发现新交换机后会触发 EventSwitchEnter。这里做的
        # 事情和 SwitchFeatures 类似：把交换机加入全局交换机集合，并缓存
        # 控制通道对象。拓扑图多了一个点，所有主机对的最短路径都有可能
        # 发生变化，所以最后调用 _recompute_paths。
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
        # 交换机离线时，它对应的图节点、控制连接、相邻边、挂载在它上面的
        # 主机都不再可信。这里按依赖关系逐项清理，避免最短路算法继续经过
        # 一个不存在的交换机。
        dpid = ev.switch.dp.id
        # 1. 从交换机集合和控制通道缓存中删除该 dpid。
        self.switches.discard(dpid)
        self.datapaths.pop(dpid, None)
        self.ofctls.pop(dpid, None)
        # 2. 删除以该交换机为起点的所有边。
        self.links.pop(dpid, None)
        # 3. 删除其他交换机邻接表中指向该交换机的边。
        for neighbors in self.links.values():
            neighbors.pop(dpid, None)
        # 4. 删除接在该交换机上的主机位置记录。
        self.hosts_by_mac = {
            mac: host for mac, host in self.hosts_by_mac.items()
            if host["dpid"] != dpid
        }
        # 5. 同步清理 IP->MAC 表，只保留仍然有位置记录的主机。
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
        # 主机在最短路图中不是中间节点，而是挂在某台交换机某个端口上的
        # 叶子节点。os-ken 通过 gratuitous ARP 发现主机后，会给出 host.mac、
        # host.port.dpid、host.port.port_no 和可能的 host.ipv4。控制器把这些
        # 信息写入 hosts_by_mac/mac_by_ip，之后才能计算“去某个目的 MAC”时
        # 每台交换机应该把包从哪个端口发出去。
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
        # EventLinkAdd 表示 LLDP 拓扑发现模块发现了两台交换机之间的连接。
        # link.src.port_no 是从 src 走向 dst 时应该使用的输出端口，
        # link.dst.port_no 是反方向应该使用的输出端口。_add_link 会把这条
        # 物理链路写成邻接表里的两个有向项，供最短路后的“下一跳端口”查询。
        link = ev.link
        self._add_link(link.src.dpid, link.dst.dpid,
                       link.src.port_no, link.dst.port_no)
        self._recompute_paths()

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # 链路删除后，邻接表中的两个方向都必须移除。否则最短路算法可能
        # 继续选择已经断开的边，导致控制器下发错误的输出端口。
        link = ev.link
        self._remove_link(link.src.dpid, link.dst.dpid)
        self._recompute_paths()
   
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # 端口 up/down 可能意味着主机断开、交换机间链路不可用，或端口号对应
        # 的连通关系发生变化。这里不直接改拓扑表，因为真正的链路增删会由
        # EventLinkAdd/EventLinkDelete 更新；此处触发一次重算，保证已有状态
        # 被尽快反映到流表。
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
        # ARP 报文天然携带源主机的 src_mac/src_ip，而且 PacketIn 告诉我们
        # 它是从哪台交换机的哪个端口进来的。因此无论这是 ARP request 还是
        # ARP reply，都可以用来刷新主机位置表。测试脚本启动时发送的
        # gratuitous ARP 也会走到这里。
        self._learn_host(pkt_arp.src_mac, datapath.id, in_port, pkt_arp.src_ip)

        if pkt_arp.opcode == arp.ARP_REPLY:
            # ARP reply 只用于学习主机信息；它本身不需要控制器再代答。学习后
            # 立刻重算路径，使新主机对应的目的 MAC 流表尽快被安装。
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
        # 有些路径会先拿到 datapath，却还没有在 switch_features_handler 或
        # handle_switch_add 中创建 OfCtl。这里做懒加载，保证只要有 datapath，
        # 就可以获得可用的 OpenFlow 操作封装。同时把 dpid 加入 switches，
        # 让全局拓扑视图不会漏掉这台交换机。
        if datapath.id not in self.ofctls:
            self.datapaths[datapath.id] = datapath
            self.ofctls[datapath.id] = OfCtl.factory(datapath, self.logger)
        self.switches.add(datapath.id)
        return self.ofctls[datapath.id]

    def _learn_host(self, mac, dpid, port_no, ip_addr=None):
        # 把一个主机绑定到“接入交换机 dpid + 接入端口 port_no”。
        # 如果同一个 MAC 后续从另一个端口出现，直接覆盖旧记录，相当于支持
        # 主机迁移或重复学习。最短路转发只关心目的主机当前位置，所以保留
        # 最新位置是合理的。
        if not mac:
            return
        # 主机接入的交换机也一定是拓扑中的交换机节点。这里补充 add 一次，
        # 可以容忍事件到达顺序不同：即使 HostAdd/ARP 先于 SwitchEnter 到达，
        # 后续计算也能看到这个 dpid。
        self.switches.add(dpid)
        self.hosts_by_mac[mac] = {
            "dpid": dpid,
            "port": port_no,
            "ip": ip_addr
        }
        # 只有拿到有效 IP 时才更新 ARP 查询表。ARP 代答依赖 IP->MAC，
        # 而路径流表下发依赖 MAC->位置，两张表的用途不同。
        if ip_addr:
            self.mac_by_ip[ip_addr] = mac

    def _add_link(self, src_dpid, dst_dpid, src_port, dst_port):
        # 把交换机链路加入控制器内部的图。图的节点是交换机 dpid，边是
        # 交换机之间的连接；边上保存的是“从当前交换机去邻居交换机应该
        # 使用哪个输出端口”。这个端口信息会在 _output_port_to_host 中用于
        # 把最短路的下一跳转换成 OpenFlow action output。
        self.switches.add(src_dpid)
        self.switches.add(dst_dpid)
        self.links[src_dpid][dst_dpid] = src_port
        self.links[dst_dpid][src_dpid] = dst_port

    def _remove_link(self, src_dpid, dst_dpid):
        # 删除链路时同时删除两个方向。使用 pop(..., None) 是为了容忍事件
        # 重复到达或只记录了一侧方向的情况，不因为缺少 key 让控制器崩溃。
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
        desired_flows = {} # 流表格式： (dpid, dst_mac) -> out_port
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
        # 日志使用 IP/MAC/接入端口组合标识主机，这样在 Mininet CLI 中执行
        # link up/down 后，可以直接看出路径是否绕开了故障链路。
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

                src_label = self._format_host_label(src_ip, src_mac, src_host)
                dst_label = self._format_host_label(dst_ip, dst_mac, dst_host)
                path = self._shortest_switch_path(src_host["dpid"],
                                                  dst_host["dpid"])
                if not path:
                    path_logs.append((
                        src_label,
                        dst_label,
                        "UNREACHABLE",
                        "%s -> X -> %s" % (src_label, dst_label)
                    ))
                    continue

                path_text = " -> ".join(
                    [src_label] +
                    ["s%s" % dpid for dpid in path] +
                    [dst_label]
                )
                path_logs.append((
                    src_label,
                    dst_label,
                    "%s edges" % (len(path) + 1),
                    path_text
                ))

        snapshot = (self.routing_algorithm, tuple(path_logs))
        if snapshot == self.last_logged_paths:
            return
        self.last_logged_paths = snapshot

        if not path_logs:
            return

        self.logger.info("=== Shortest path table: algorithm=%s, hosts=%s ===",
                         self.routing_algorithm, len(hosts))
        for src_label, dst_label, distance_text, path_text in path_logs:
            self.logger.info("%s -> %s | %s", src_label, dst_label,
                             distance_text)
            self.logger.info("  path: %s", path_text)
        self.logger.info("=== End shortest path table ===")

    def _format_host_label(self, ip_addr, mac_addr, host):
        return "%s/%s@s%s:p%s" % (
            ip_addr,
            mac_addr,
            host["dpid"],
            host["port"]
        )
    
