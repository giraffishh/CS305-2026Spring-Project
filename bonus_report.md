# Bonus Report

## Bonus A: DHCP lease and duplicate IP prevention

The DHCP server now maintains explicit lease state for every allocated address.

Implemented in `dhcp.py`:

- `Config.lease_time` defines the lease duration in seconds. The current value is `86400`.
- `allocated_ip` maps each client MAC address to its assigned IP address.
- `ip_to_mac` records which MAC owns each IP address, so two clients cannot receive the same IP.
- `lease_expiration` records when each client's lease expires.
- A client renewing its lease keeps the same IP address.
- Expired leases are removed before new allocation, so released addresses can be reused.
- A requested IP is accepted only when it is inside the address pool and not owned by another client.

How to test:

```bash
osken-manager --observe-links controller.py
cd tests/dhcp_test/
sudo env "PATH=$PATH" python test_network.py
```

Expected result: `h1` and `h2` receive different IP addresses in the `192.168.1.2` to `192.168.1.99` range. Internal checks also confirm that renewal preserves the same IP, duplicate IP assignment is prevented, and expired addresses can be reused.

## Bonus B: switchable routing algorithms

The shortest-path switching module now supports two routing algorithms.

Implemented in `controller.py`:

- `dijkstra`: the default shortest-path algorithm.
- `bellman_ford`: an alternative shortest-path algorithm.
- The algorithm is selected with the `CS305_ROUTING_ALGORITHM` environment variable.
- Controller logs print the active algorithm before path output.

Run with the default Dijkstra algorithm:

```bash
osken-manager --observe-links controller.py
```

Run with Bellman-Ford:

```bash
CS305_ROUTING_ALGORITHM=bellman_ford osken-manager --observe-links controller.py
```

Expected result: both algorithms compute valid shortest paths and pass the switching tests with `0% dropped`.

## Complex testcase

A complex topology is provided in `tests/complex_test/test_network.py`.

Topology:

```text
h1--s1--s2--h2
|  / |   /|
| /  |  / |
s5--s3--s4
|    |    |
h5   h3   h4
```

The switch graph contains a ring and extra cross links:

- Ring: `s1-s2-s3-s4-s5-s1`
- Cross links: `s1-s3`, `s2-s5`

The testcase starts five hosts and five switches, sends gratuitous ARP from every host, runs `pingAll`, and runs several selected host-to-host ping checks. It is intended to demonstrate that the controller handles loops and chooses short paths in a non-tree topology.

Run with Dijkstra:

```bash
osken-manager --observe-links controller.py
cd tests/complex_test/
sudo env "PATH=$PATH" python test_network.py
```

Run with Bellman-Ford:

```bash
CS305_ROUTING_ALGORITHM=bellman_ford osken-manager --observe-links controller.py
cd tests/complex_test/
sudo env "PATH=$PATH" python test_network.py
```

Expected result: `pingAll` reports `0% dropped`, selected pings have `0% packet loss`, and the controller log shows paths with the selected routing algorithm.