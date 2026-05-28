import argparse
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_arp(node, count=1):
    node.cmd('arping -c %s -A -I %s-eth0 %s' % (count, node.name, node.IP()))


def do_arp_all(net, rounds=2):
    for _ in range(rounds):
        for host in net.hosts:
            send_arp(host)
        time.sleep(1)


def ping(host, dst, count=2, timeout=1):
    return host.cmd('ping -c %s -W %s %s' % (count, timeout, dst))


class ComplexTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)
        self.addLink(h5, s5)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s1)
        self.addLink(s1, s3)
        self.addLink(s2, s5)


def selected_ping_tests(net):
    tests = [
        ('h1', 'h4'),
        ('h2', 'h5'),
        ('h3', 'h1'),
        ('h4', 'h2'),
    ]
    failed = False
    for src_name, dst_name in tests:
        src = net.get(src_name)
        dst = net.get(dst_name)
        print('\n===== %s -> %s =====' % (src_name, dst_name))
        output = ping(src, dst.IP())
        print(output)
        if ' 0% packet loss' not in output and ', 0% packet loss' not in output:
            failed = True
    return failed


def run_mininet(open_cli=False):
    topo = ComplexTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for host in net.hosts:
        disable_ipv6(host)
    for switch in net.switches:
        disable_ipv6(switch)

    failed = False
    try:
        net.start()
        time.sleep(1)
        print('\n===== Network topology =====')
        for line in net.links:
            print(line)

        do_arp_all(net)

        print('\n===== pingAll =====')
        packet_loss = net.pingAll()
        if packet_loss != 0:
            failed = True

        if selected_ping_tests(net):
            failed = True

        if open_cli:
            CLI(net)
    finally:
        net.stop()

    return 1 if failed else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', action='store_true', help='open Mininet CLI after automated checks')
    args = parser.parse_args()
    setLogLevel('info')
    raise SystemExit(run_mininet(open_cli=args.cli))