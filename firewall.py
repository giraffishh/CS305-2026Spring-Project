# firewall.py

import json
import os
from dataclasses import dataclass

from os_ken.ofproto import ether, inet


@dataclass(frozen=True)
class FirewallRule:
    # 防火墙规则的数据结构；字段为 None 或通配值时表示“不限制该条件”。
    src_ip: str = None
    dst_ip: str = None
    proto: str = None
    src_port: object = None
    dst_port: object = None
    action: str = "deny"


class Firewall:
    # COOKIE 用于标记本模块安装的流表项，PRIORITY 保证防火墙规则优先匹配。
    COOKIE = 0x305F
    PRIORITY = 60000

    # 协议名称到 IP 协议号的映射；0 表示协议通配。
    PROTO_MAP = {
        None: 0,
        "": 0,
        "*": 0,
        "any": 0,
        "icmp": inet.IPPROTO_ICMP,
        "tcp": inet.IPPROTO_TCP,
        "udp": inet.IPPROTO_UDP,
    }

    # 没有外部规则文件时使用的默认拒绝规则。
    DEFAULT_RULES = [
        FirewallRule(
            src_ip="192.168.117.2",
            dst_ip="192.168.117.3",
            proto="icmp",
            action="deny"
        ),
        FirewallRule(
            src_ip="192.168.117.2",
            dst_ip="192.168.117.3",
            proto="tcp",
            dst_port=80,
            action="deny"
        ),
    ]

    def __init__(self, rule_file="firewall_rules.json"):
        self.rule_file = rule_file
        self.rules = self._load_rules(rule_file)
        # 记录已经安装过的规则，避免重复向交换机下发同一条流表。
        self.installed = set()

    # 将 None、空字符串、*、any 等通配写法统一归一化为 None。
    def _normalize_any(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in ["", "*", "any"]:
            return None
        return value

    def _normalize_proto(self, proto):
        # 协议字段统一转为小写字符串，便于查表和比较。
        proto = self._normalize_any(proto)
        if proto is None:
            return None
        return str(proto).lower()

    def _proto_to_number(self, proto):
        # 未指定或未知协议都按 0 处理，表示不限制 IP 协议号。
        proto = self._normalize_proto(proto)
        return self.PROTO_MAP.get(proto, 0)

    def _normalize_port(self, value):
        # 端口 0 表示通配；非通配端口转换为整数后再校验范围。
        value = self._normalize_any(value)
        if value is None:
            return 0
        return int(value)

    def _load_rules(self, rule_file):
        """
        Load firewall rules from firewall_rules.json and return a list of FirewallRule.
        """
        rules = []
        module_dir = os.path.dirname(os.path.abspath(__file__))
        # 同时尝试当前工作目录和模块所在目录，避免从不同路径启动程序时找不到规则文件。
        candidate_files = [
            rule_file,
            os.path.join(module_dir, rule_file),
        ]
        if rule_file == "firewall_rules.json":
            # 兼容可能存在的旧文件名 firewall_rule.json。
            candidate_files.extend([
                "firewall_rule.json",
                os.path.join(module_dir, "firewall_rule.json"),
            ])

        existing_file = next((path for path in candidate_files if os.path.exists(path)), None)
        if not existing_file:
            # 找不到规则文件时回退到内置默认规则。
            return list(self.DEFAULT_RULES)

        with open(existing_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 支持 {"rules": [...]} 或直接 [...] 两种 JSON 写法。
        raw_rules = data.get("rules", data) if isinstance(data, dict) else data
        if not isinstance(raw_rules, list):
            return list(self.DEFAULT_RULES)

        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                continue
            # 逐条清洗规则字段，非法结构会被跳过，缺省 action 默认为 deny。
            rules.append(FirewallRule(
                src_ip=self._normalize_any(raw_rule.get("src_ip")),
                dst_ip=self._normalize_any(raw_rule.get("dst_ip")),
                proto=self._normalize_proto(raw_rule.get("proto")),
                src_port=self._normalize_any(raw_rule.get("src_port")),
                dst_port=self._normalize_any(raw_rule.get("dst_port")),
                action=str(raw_rule.get("action", "deny")).lower()
            ))

        return rules

    def install_rules(self, ofctls):
        """
        Install firewall rules to all switches.
        """
        for dpid, ofctl in ofctls.items():
            for rule in self.rules:
                # 当前实现只负责安装 deny 规则，其他动作直接忽略。
                if rule.action != "deny":
                    continue

                proto = self._normalize_proto(rule.proto)
                if proto not in self.PROTO_MAP:
                    # 不认识的协议名称无法转换为 OpenFlow 匹配字段，跳过。
                    continue
                proto_num = self._proto_to_number(proto)

                try:
                    src_port = self._normalize_port(rule.src_port)
                    dst_port = self._normalize_port(rule.dst_port)
                except (TypeError, ValueError):
                    continue

                if not self._valid_port(src_port) or not self._valid_port(dst_port):
                    continue

                if (src_port or dst_port) and proto not in ("tcp", "udp"):
                    # 只有 TCP/UDP 才有传输层端口，ICMP/任意协议不能匹配端口。
                    continue

                # match 元组既用于去重，也用于拆出 OpenFlow set_flow 需要的匹配字段。
                match = (
                    dpid,
                    self._normalize_any(rule.src_ip),
                    self._normalize_any(rule.dst_ip),
                    proto_num,
                    src_port,
                    dst_port
                )
                if match in self.installed:
                    continue

                ofctl.set_flow(
                    self.COOKIE,
                    self.PRIORITY,
                    dl_type=ether.ETH_TYPE_IP,
                    nw_src=match[1] or 0,
                    nw_dst=match[2] or 0,
                    nw_proto=proto_num,
                    tp_src=src_port,
                    tp_dst=dst_port,
                    actions=[]
                )
                # actions 为空表示匹配到该流后直接丢弃数据包。
                self.installed.add(match)

    def _valid_port(self, port):
        # TCP/UDP 端口合法范围为 0 到 65535，其中 0 在本模块中表示通配。
        return 0 <= port <= 65535
