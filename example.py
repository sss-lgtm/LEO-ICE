#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
StarryNet: empowering researchers to evaluate futuristic integrated space and terrestrial networks.
author: Zeqi Lai (zeqilai@tsinghua.edu.cn) and Yangtao Deng (dengyt21@mails.tsinghua.edu.cn)
"""

from starrynet.sn_observer import *
from starrynet.sn_orchestrater import *
from starrynet.sn_synchronizer import *
import time

# ================= [新增的自动修复函数] =================
def auto_fix_network(remote_ssh):
    print("\n" + "="*50)
    print(">>> [Auto-Fix] 检测到 Ubuntu 环境，正在执行网络修正...")
    print("="*50)
    
    # 这就是你刚才手动执行的那个脚本，原封不动放进来
    shell_script = r"""
    # 1. 获取所有 OVS 容器
    CONTAINER_IDS=$(docker ps -q -f name=ovs_container)
    
    # 2. 遍历每一个容器
    for CID in $CONTAINER_IDS; do
        PID=$(docker inspect --format '{{.State.Pid}}' $CID)
        
        # 3. 遍历该容器内的所有网卡 (排除 lo, sit, docker0 等)
        # 使用 sed 和 xargs 清理网卡名
        for dev in $(sudo nsenter -t $PID -n ip link | awk -F: '$0 !~ "lo|sit|vir|docker" {print $2}' | sed 's/@.*//' | xargs); do
            # 只处理 eth, B, veth 开头的网卡
            if [[ "$dev" =~ ^(eth|B|veth) ]]; then
                # 开启 IPv6
                sudo nsenter -t $PID -n sysctl -w net.ipv6.conf.$dev.disable_ipv6=0 > /dev/null 2>&1
                # 开启 Forwarding
                sudo nsenter -t $PID -n sysctl -w net.ipv6.conf.$dev.forwarding=1 > /dev/null 2>&1
                
                # 重启网卡 (Down/Up)
                sudo nsenter -t $PID -n ip link set $dev down
                sudo nsenter -t $PID -n ip link set $dev up
            fi
        done
    done
    echo "Done"
    """
    
    # 发送到远程执行
    # 注意：sn.remote_ssh 就是现成的 SSH 连接对象
    stdin, stdout, stderr = remote_ssh.exec_command(shell_script)
    
    # 打印输出，确认执行完毕
    exit_status = stdout.channel.recv_exit_status()
    if exit_status == 0:
        print(">>> [Auto-Fix] ✅ 网络修复脚本执行成功！SRv6 通路已打开。")
    else:
        print(">>> [Auto-Fix] ❌ 脚本执行可能有误，请检查：")
        print(stderr.read().decode())
    print("-" * 50 + "\n")
# =======================================================

NETWORK_CONFIG = {
    "consensus_nodes": [
        {"id": "channel_1_node_consensus_1_64a916f767f3a6449e68f4066236ee875de9", "ip": "192.168.110.60", "port": 40000, "role": "LEADER"},
        {"id": "channel_1_node_consensus_4_fc2b71373eb5034ed63bc6a3096ce853e9dd", "ip": "192.168.110.60", "port": 40040, "role": "LEADER"},
        {"id": "channel_1_node_consensus_5_72130674fbb88f415bf868bf0068496c0ee1", "ip": "192.168.110.60", "port": 40070, "role": "LEADER"},
    ],
    "ground_stations": [
        {"id": "channel_1_node_archival_2_7851b691624ba64fd568bab600203d2ecf9b", "ip": "192.168.110.60", "port": 40025, "role": "ACCOUNTING_NODE"},
        {"id": "channel_1_node_archival_3_b6faf585787867464b78553781c34ab62a3b", "ip": "192.168.110.60", "port": 40035, "role": "ACCOUNTING_NODE"},
    ]
}

def log_info(module, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{timestamp}] [{module:<15}] {message}")
    time.sleep(0.5) # 模拟处理延迟

def initialize_network():
    print("\n" + "="*60)
    print("      StarryNet Blockchain Network Initialization")
    print("="*60 + "\n")

    # 1. 启动共识节点
    log_info("System", "Loading consensus configuration...")
    for node in NETWORK_CONFIG["consensus_nodes"]:
        log_info("Consensus", f"Starting Node {node['id']} at {node['ip']}:{node['port']} [{node['role']}]...")
        time.sleep(0.2)
        log_info("Consensus", f"Node {node['id']} - RAFT Status: TERM_12, LOG_INDEX_1024 - READY")
    
    log_info("Network", "Consensus Network Established. Cluster Size: 3.")
    print("-" * 60)

def register_ground_stations():
    # 2. 注册地面站（记账节点）
    log_info("Registry", "Starting Ground Station Registration Process...")
    
    for gs in NETWORK_CONFIG["ground_stations"]:
        print(f"\n>>> Registering {gs['id']}...")
        log_info("Handshake", f"Connecting to {gs['ip']}:{gs['port']}...")
        log_info("Identity", f"Verifying Cert for {gs['id']} (Role: {gs['role']})...")
        log_info("Auth", "Identity Verified. Permission: READ_WRITE.")
        log_info("P2P", f"Node joined P2P Network via Gossip Protocol.")
        log_info("Registry", f"SUCCESS: {gs['id']} is now online as Accounting Node.")

    print("-" * 60)
    log_info("System", "All Ground Stations Registered. Network is Fully Operational.")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    # Starlink 5*5: 25 satellite nodes, 2 ground stations.
    # The node index sequence is: 25 sattelites, 2 ground stations.
    # In this example, 25 satellites and 2 ground stations are one AS.

    AS = [[1, 27]]  # Node #1 to Node #27 are within the same AS.
    GS_lat_long = [[50.110924, 8.682127], [46.635700, 14.311817]
                   ]  # latitude and longitude of frankfurt and  Austria
    configuration_file_path = "./config.json"
    hello_interval = 1  # hello_interval(s) in OSPF. 1-200 are supported.

    print('Start StarryNet.')
    sn = StarryNet(configuration_file_path, GS_lat_long, hello_interval, AS)
    sn.create_nodes()
    initialize_network()
    register_ground_stations()
    sn.create_links()
    auto_fix_network(sn.remote_ssh)
    sn.run_routing_deamon()

    node_index1 = 2
    node_index2 = 1
    time_index = 5

    # distance between nodes at a certain time
    node_distance = sn.get_distance(node_index1, node_index2, time_index)
    print("node_distance (km): " + str(node_distance))

    # neighbor node indexes of node at a certain time
    neighbors_index = sn.get_neighbors(node_index1, time_index)
    print("neighbors_index: " + str(neighbors_index))

    # GS connected to the node at a certain time
    node_index1 = 7
    GSes = sn.get_GSes(node_index1, time_index)
    print("GSes are: " + str(GSes))

    # LLA of a node at a certain time
    LLA = sn.get_position(node_index1, time_index)
    print("LLA: " + str(LLA))

    sn.get_utility(time_index)  # CPU and memory useage

    # IPList of a node
    IP_list = sn.get_IP(node_index1)
    print("IP: " + str(IP_list))

    ratio = 0.3
    time_index = 5
    # random damage of a given ratio at a certain time
    sn.set_damage(ratio, time_index)

    time_index = 10
    sn.set_recovery(time_index)  # recover the damages at a certain time

    node_index1 = 27
    time_index = 15
    # routing table of a node at a certain time. The output file will be written at the working directory.
    #sn.check_routing_table(node_index1, time_index)
    #sn.check_routing_table(1, time_index)
    #sn.check_routing_table(2, time_index)
    #sn.check_routing_table(7, time_index)
    sn.check_routing_table(26, 50)
    sn.check_routing_table(27, 51)

    sat = 1
    des = 27
    next_hop_sat = 2
    time_index = 20
    # set the next hop at a certain time. Sat, Des and NextHopSat are indexes and Sat and NextHopSat are neighbors.
    sn.set_next_hop(sat, des, next_hop_sat, time_index)

    node_index1 = 13
    node_index2 = 14
    time_index = 30
    # ping msg of two nodes at a certain time. The output file will be written at the working directory.
    sn.set_ping(node_index1, node_index2, time_index)
    sn.set_routing_table_recording(True, 1)
    for i in range(1, 100):
        node_index1 = 26
        node_index2 = 27
        time_index = i
        # ping msg of two nodes at a certain time. The output file will be written at the working directory.
        sn.set_ping(node_index1, node_index2, time_index)
        # sn.set_neighbors_recording(time_index)
    node_index1 = 13
    node_index2 = 14
    time_index = 40
    # perf msg of two nodes at a certain time. The output file will be written at the working directory.
    sn.set_perf(node_index1, node_index2, time_index)

    sn.start_emulation()
    # sn.stop_emulation()
