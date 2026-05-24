# firewall.py

import json
import os
from dataclasses import dataclass

from os_ken.ofproto import ether, inet


@dataclass(frozen=True)
class FirewallRule:
    src_ip: str = None
    dst_ip: str = None
    proto: str = None
    src_port: object = None
    dst_port: object = None
    action: str = "deny"


class Firewall:
    COOKIE = 0x305F
    PRIORITY = 60000

    PROTO_MAP = {
        None: 0,
        "": 0,
        "*": 0,
        "any": 0,
        "icmp": inet.IPPROTO_ICMP,
        "tcp": inet.IPPROTO_TCP,
        "udp": inet.IPPROTO_UDP,
    }

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
        self.installed = set()

    # Some helper functions that may be useful
    def _normalize_any(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in ["", "*", "any"]:
            return None
        return value

    def _normalize_proto(self, proto):
        proto = self._normalize_any(proto)
        if proto is None:
            return None
        return str(proto).lower()

    def _proto_to_number(self, proto):
        proto = self._normalize_proto(proto)
        return self.PROTO_MAP.get(proto, 0)

    def _normalize_port(self, value):
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
        candidate_files = [
            rule_file,
            os.path.join(module_dir, rule_file),
        ]
        if rule_file == "firewall_rules.json":
            candidate_files.extend([
                "firewall_rule.json",
                os.path.join(module_dir, "firewall_rule.json"),
            ])

        existing_file = next((path for path in candidate_files if os.path.exists(path)), None)
        if not existing_file:
            return list(self.DEFAULT_RULES)

        with open(existing_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_rules = data.get("rules", data) if isinstance(data, dict) else data
        if not isinstance(raw_rules, list):
            return list(self.DEFAULT_RULES)

        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                continue
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
                if rule.action != "deny":
                    continue

                proto = self._normalize_proto(rule.proto)
                if proto not in self.PROTO_MAP:
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
                    continue

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
                self.installed.add(match)

    def _valid_port(self, port):
        return 0 <= port <= 65535
