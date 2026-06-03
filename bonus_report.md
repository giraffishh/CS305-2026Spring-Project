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

---

# 加分报告

## 加分项 A：DHCP 租约与重复 IP 防护

现在，DHCP 服务器会为每一个已分配地址维护明确的租约状态。

实现位置：`dhcp.py`

- `Config.lease_time` 定义了租约时长，单位为秒。当前值为 `86400`。
- `allocated_ip` 将每个客户端的 MAC 地址映射到其分配到的 IP 地址。
- `ip_to_mac` 记录每个 IP 地址归哪个 MAC 地址所有，因此两个客户端不会拿到同一个 IP。
- `lease_expiration` 记录每个客户端租约的过期时间。
- 客户端续租时会保持原来的 IP 地址不变。
- 在进行新的地址分配之前，会先清理已过期的租约，因此释放出来的地址可以被重新使用。
- 只有当请求的 IP 位于地址池范围内，且不属于其他客户端时，该请求才会被接受。

测试方法：

```bash
osken-manager --observe-links controller.py
cd tests/dhcp_test/
sudo env "PATH=$PATH" python test_network.py
```

预期结果：`h1` 和 `h2` 会在 `192.168.1.2` 到 `192.168.1.99` 的范围内获得不同的 IP 地址。内部检查还会确认：续租后 IP 保持不变、不会发生重复 IP 分配、过期地址可以被重新使用。

## 加分项 B：可切换的路由算法

最短路径交换模块现在支持两种路由算法。

实现位置：`controller.py`

- `dijkstra`：默认的最短路径算法。
- `bellman_ford`：另一种可选的最短路径算法。
- 算法通过环境变量 `CS305_ROUTING_ALGORITHM` 进行选择。
- 控制器日志会在输出路径之前打印当前启用的算法。

使用默认的 Dijkstra 算法运行：

```bash
osken-manager --observe-links controller.py
```

使用 Bellman-Ford 运行：

```bash
CS305_ROUTING_ALGORITHM=bellman_ford osken-manager --observe-links controller.py
```

预期结果：两种算法都能够计算出有效的最短路径，并且都能以 `0% dropped` 通过交换测试。

## 复杂测试用例

在 `tests/complex_test/test_network.py` 中提供了一个复杂拓扑。

拓扑如下：

```text
h1--s1--s2--h2
|  / |   /|
| /  |  / |
s5--s3--s4
|    |    |
h5   h3   h4
```

交换机图中包含一个环以及额外的交叉链路：

- 环：`s1-s2-s3-s4-s5-s1`
- 交叉链路：`s1-s3`、`s2-s5`

该测试会启动 5 台主机和 5 台交换机，从每台主机发送 gratuitous ARP，执行 `pingAll`，并额外执行若干组指定主机之间的 ping 检查。这个测试用于展示控制器能够在非树形拓扑中正确处理环路，并选择较短路径。

使用 Dijkstra 运行：

```bash
osken-manager --observe-links controller.py
cd tests/complex_test/
sudo env "PATH=$PATH" python test_network.py
```

使用 Bellman-Ford 运行：

```bash
CS305_ROUTING_ALGORITHM=bellman_ford osken-manager --observe-links controller.py
cd tests/complex_test/
sudo env "PATH=$PATH" python test_network.py
```

预期结果：`pingAll` 显示 `0% dropped`，所选的 ping 检查显示 `0% packet loss`，并且控制器日志会展示使用所选路由算法计算出的路径。
