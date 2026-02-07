import os
import threading
import json
import copy
import argparse
import os
from time import sleep
import time
import numpy
import random
import sys
"""Starrynet utils that are used in sn_synchronizer
author: Yangtao Deng (dengyt21@mails.tsinghua.edu.cn) and Zeqi Lai (zeqilai@tsinghua.edu.cn)
"""
# === [修复导入路径] ===
# 1. 获取 sn_utils.py 所在的目录 (StarryNet/starrynet/)
current_dir = os.path.dirname(os.path.abspath(__file__))
# 2. 获取项目根目录 (StarryNet/)
project_root = os.path.dirname(current_dir)

# 3. 将根目录加入 Python 搜索路径，确保能找到 'skycastle'
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 4. 显式导入 (不要用 try-except 包裹，如果失败直接报错，方便排查)
from skycastle.controller import SkyCastleController
try:
    import threading
except ImportError:
    os.system("pip3 install threading")
    import threading

try:
    import paramiko
except ImportError:
    os.system("pip3 install paramiko")
    import paramiko

try:
    import requests
except ImportError:
    os.system("pip3 install requests")
    import requests


def get_right_satellite(current_sat_id, current_orbit_id, orbit_num):
    if current_orbit_id == orbit_num - 1:
        return [current_sat_id, 0]
    else:
        return [current_sat_id, current_orbit_id + 1]


def get_down_satellite(current_sat_id, current_orbit_id, sat_num):
    if current_sat_id == sat_num - 1:
        return [0, current_orbit_id]
    else:
        return [current_sat_id + 1, current_orbit_id]


def sn_load_file(path, GS_lat_long):
    f = open("./config.json", "r", encoding='utf8')
    table = json.load(f)
    data = {}
    data['cons_name'] = table["Name"]
    data['altitude'] = table["Altitude (km)"]
    data['cycle'] = table["Cycle (s)"]
    data['inclination'] = table["Inclination"]
    data['phase_shift'] = table["Phase shift"]
    data['orbit'] = table["# of orbit"]
    data['sat'] = table["# of satellites"]
    data['link'] = table["Satellite link"]
    data['duration'] = table["Duration (s)"]
    data['ip'] = table["IP version"]
    data['intra_as_routing'] = table["Intra-AS routing"]
    data['inter_as_routing'] = table["Inter-AS routing"]
    data['link_policy'] = table["Link policy"]
    data['handover_policy'] = table["Handover policy"]
    data['update_time'] = table["update_time (s)"]
    data['sat_bw'] = table["satellite link bandwidth (\"X\" Gbps)"]
    data['sat_ground_bw'] = table["sat-ground bandwidth (\"X\" Gbps)"]
    data['sat_loss'] = table["satellite link loss (\"X\"% )"]
    data['sat_ground_loss'] = table["sat-ground loss (\"X\"% )"]
    data['ground_num'] = table["GS number"]
    data['multi_machine'] = table[
        "multi-machine (\"0\" for no, \"1\" for yes)"]
    data['antenna_number'] = table["antenna number"]
    data['antenna_inclination'] = table["antenna_inclination_angle"]
    data['remote_machine_IP'] = table["remote_machine_IP"]
    data['remote_machine_username'] = table["remote_machine_username"]
    data['remote_machine_password'] = table["remote_machine_password"]

    parser = argparse.ArgumentParser(description='manual to this script')
    parser.add_argument('--cons_name', type=str, default=data['cons_name'])
    parser.add_argument('--satellite_altitude',
                        type=int,
                        default=data['altitude'])
    parser.add_argument('--inclination', type=int, default=data['inclination'])
    parser.add_argument('--orbit_number', type=int, default=data['orbit'])
    parser.add_argument('--sat_number', type=int, default=data['sat'])
    parser.add_argument('--fac_num', type=int, default=len(GS_lat_long))
    parser.add_argument('--link_style', type=str, default=data['link'])
    parser.add_argument('--IP_version', type=str, default=data['ip'])
    parser.add_argument('--link_policy', type=str, default=data['link_policy'])
    # link delay updating granularity
    parser.add_argument('--update_interval',
                        type=int,
                        default=data['update_time'])
    parser.add_argument('--duration', type=int, default=data['duration'])
    parser.add_argument('--inter_routing',
                        type=str,
                        default=data['inter_as_routing'])
    parser.add_argument('--intra_routing',
                        type=str,
                        default=data['intra_as_routing'])
    parser.add_argument('--cycle', type=int, default=data['cycle'])
    parser.add_argument('--time_slot', type=int, default=100)
    parser.add_argument('--sat_bandwidth', type=int, default=data['sat_bw'])
    parser.add_argument('--sat_ground_bandwidth',
                        type=int,
                        default=data['sat_ground_bw'])
    parser.add_argument('--sat_loss', type=int, default=data['sat_loss'])
    parser.add_argument('--sat_ground_loss',
                        type=int,
                        default=data['sat_ground_loss'])
    parser.add_argument('--ground_num', type=int, default=data['ground_num'])
    parser.add_argument('--multi_machine',
                        type=int,
                        default=data['multi_machine'])
    parser.add_argument('--antenna_number',
                        type=int,
                        default=data['antenna_number'])
    parser.add_argument('--antenna_inclination',
                        type=int,
                        default=data['antenna_inclination'])
    parser.add_argument('--user_num', type=int, default=0)
    parser.add_argument('--remote_machine_IP',
                        type=str,
                        default=data['remote_machine_IP'])
    parser.add_argument('--remote_machine_username',
                        type=str,
                        default=data['remote_machine_username'])
    parser.add_argument('--remote_machine_password',
                        type=str,
                        default=data['remote_machine_password'])

    parser.add_argument('--path',
                        '-p',
                        type=str,
                        default="starrynet/config.xls")
    parser.add_argument('--hello_interval', '-i', type=int, default=10)
    parser.add_argument('--node_number', '-n', type=int, default=27)
    parser.add_argument('--GS',
                        '-g',
                        type=str,
                        default="50.110924/8.682127/46.635700/14.311817")

    sn_args = parser.parse_args()
    return sn_args


def sn_get_param(file_):
    # --- [新增] 必要的模块导入 ---
    import time
    import os

    # --- [新增] 等待机制：最多等 2 秒 ---
    # 既然您确定文件一定会生成，我们就在这里“死等”它一会
    max_retries = 20        # 尝试 20 次
    interval = 0.1          # 每次间隔 0.1 秒
    
    for i in range(max_retries):
        if os.path.exists(file_):
            # 文件出现了！但为了防止文件正在写入中（只写了一半），
            # 稳妥起见，可以再额外微小停顿一下，或者直接 break 尝试打开
            time.sleep(0.01) 
            break
        time.sleep(interval)
    # ---------------------------

    # --- 原有逻辑 (加了一层保护) ---
    try:
        f = open(file_)
    except FileNotFoundError:
        # 如果等了 2 秒还没出来，说明可能真的出问题了（比如仿真已经彻底结束了）
        # 这时候为了不崩，还是建议返回 None
        print(f"[Timeout] File never appeared: {file_}")
        return None

    # ... (后面读取文件的原有代码保持不变) ...
    # 例如:
    # lines = f.readlines()
    # ...
    ADJ = f.readlines()
    for i in range(len(ADJ)):
        ADJ[i] = ADJ[i].strip('\n')
    ADJ = [x.split(',') for x in ADJ]
    f.close()
    return ADJ


def sn_init_remote_machine(host, username, password):
    # transport = paramiko.Transport((host, 22))
    # transport.connect(username=username, password=password)
    remote_machine_ssh = paramiko.SSHClient()
    # remote_machine_ssh._transport = transport
    remote_machine_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    remote_machine_ssh.connect(hostname=host,
                               port=22,
                               username=username,
                               password=password)
    transport = paramiko.Transport((host, 22))
    transport.connect(username=username, password=password)
    return remote_machine_ssh, transport
    # transport.close()


def sn_init_remote_ftp(transport):
    ftp_client = paramiko.SFTPClient.from_transport(transport)  ## ftp client
    return ftp_client


def sn_remote_cmd(remote_ssh, cmd):
    stdin, stdout, stderr = remote_ssh.exec_command(cmd, get_pty=True)
    lines = stdout.readlines()
    return lines

# === [SkyCastle 新增] 部署 Agent 的逻辑 ===
def install_skycastle_agents(remote_ssh, container_id_list):
    print("[SkyCastle] Deploying agents to containers...")
    
    # 1. 在本地计算分簇 (使用项目根目录下的 config.json)
    config_path = "./config.json" 
    controller = SkyCastleController(config_path) 
    sat_to_cluster, cluster_anchors = controller.compute_clusters()
    
    # 2. 远程 Agent 脚本路径 (假设已通过 Link_Init 上传到远程)
    # 注意：这里需要与 sn_Link_Init_Thread 中的上传路径一致
    # 假设上传到了 ~/<file_path>/skycastle/node_agent.py
    # 我们需要先知道 file_path，这里暂时假设脚本已经在宿主机的 /root/node_agent.py (简化版)
    # 或者我们直接在下面构造正确的路径
    
    # 3. 遍历容器启动 Agent
    for sat_idx, container_id in enumerate(container_id_list):
        sat_id = sat_idx + 1 # 卫星ID从1开始
        
        # 简单判断是否是卫星节点（StarryNet中卫星ID在前，地面站在后）
        if sat_id > controller.total_sats:
            continue # 跳过地面站

        # 判断角色
        role = "NORMAL"
        if sat_id in cluster_anchors.values():
            role = "ANCHOR"
            
        # 构造远程路径：假设 file_path 存在于远程用户主目录下
        # 更好的方式是直接从宿主机拷贝到容器
        # 假设我们之前把 node_agent.py 放到了宿主机的 /tmp 或者项目目录
        # 这里使用一个更稳妥的命令：从远程的项目目录拷贝
        
        # 启动命令：后台运行 Agent
        # --id 参数传入卫星ID
        run_cmd = f"docker exec -d {container_id} nohup python3 /root/skycastle/node_agent.py --id {sat_id} --role {role} > /var/log/agent.log 2>&1 &"
        
        # 注意：这里假设容器里已经有了 /root/skycastle/node_agent.py
        # 我们需要在 sn_Link_Init_Thread 里把代码不仅上传到宿主机，还要想办法挂载或拷贝进容器
        # 或者最简单的方法：在启动容器后，用 docker cp 拷贝进去
        
        # [拷贝动作]
        # 假设宿主机路径: ~/cons_name.../skycastle/node_agent.py
        # 我们需要先获取那个长长的 file_path，或者让 Node_Init 传进来
        # 这里为了简化，我们假设 sn_Link_Init 已经把 skycastle 传到了宿主机
        pass 

    # 由于 install_skycastle_agents 独立函数很难获取 file_path，
    # 我们把具体逻辑直接写在 sn_Node_Init_Thread.run() 里更合适
    pass

# A thread designed for initializing working directory.
class sn_init_directory_thread(threading.Thread):

    def __init__(self, file_path, configuration_file_path, remote_ssh):
        threading.Thread.__init__(self)
        self.file_path = file_path
        self.remote_ssh = remote_ssh
        self.configuration_file_path = configuration_file_path

    def run(self):
        # Reset docker environment.
        os.system("rm " + self.configuration_file_path + "/" + self.file_path +
                  "/*.txt")
        if os.path.exists(self.file_path + "/mid_files") == False:
            os.system("mkdir " + self.configuration_file_path + "/" +
                      self.file_path)
            os.system("mkdir " + self.configuration_file_path + "/" +
                      self.file_path + "/delay")
            os.system("mkdir " + self.configuration_file_path + "/" +
                      self.file_path + "/mid_files")
        sn_remote_cmd(self.remote_ssh, "mkdir ~/" + self.file_path)
        sn_remote_cmd(self.remote_ssh, "mkdir ~/" + self.file_path + "/delay")


# A thread designed for initializing constellation nodes.
class sn_Node_Init_Thread(threading.Thread):

    def __init__(self, remote_ssh, docker_service_name, node_size,
                 container_id_list, container_global_idx):
        threading.Thread.__init__(self)
        self.remote_ssh = remote_ssh
        self.docker_service_name = docker_service_name
        self.node_size = node_size
        self.container_global_idx = container_global_idx
        self.container_id_list = copy.deepcopy(container_id_list)

    def run(self):

        # Reset docker environment.
        sn_reset_docker_env(self.remote_ssh, self.docker_service_name,
                            self.node_size)
        # Get container list in each machine.
        self.container_id_list = sn_get_container_info(self.remote_ssh)
        while len(self.container_id_list) != self.node_size:
            print(f"Waiting for containers... ({len(self.container_id_list)}/{self.node_size})")
            time.sleep(2)
            self.container_id_list = sn_get_container_info(self.remote_ssh)
        # Rename all containers with the global idx
        sn_rename_all_container(self.remote_ssh, self.container_id_list,
                                self.container_global_idx)
        self.container_id_list = sn_get_container_info(self.remote_ssh)
        
        print("Constellation initialization done.")

        # === [SkyCastle] 4. 安装并启动 Agent ===
        print("[SkyCastle] Installing Agents into containers...")
        
        # (1) 本地计算分簇
        config_path = "./config.json"
        controller = SkyCastleController(config_path)
        sat_to_cluster, cluster_anchors = controller.compute_clusters()
        
        # (2) 确定远程宿主机上的 Agent 脚本路径
        # 注意：这里我们需要知道 file_path (constellation name + params)
        # 由于这里没有 file_path 参数，我们假设 sn_Link_Init_Thread 会在之后把文件传上去
        # 或者我们在这里做一个临时处理：
        # 更好的方法是：Agent 的安装其实应该在 Link_Init 之后做，因为那时候代码才上传到服务器
        # 但 Link_Init 是用来建链路的。
        
        # 修正策略：我们在 sn_Link_Init_Thread 里做“上传代码”这件事。
        # 但是“启动 Agent” 必须在容器运行之后。
        # 此时容器已经运行了。
        # 但代码可能还没上传（因为 sn_Link_Init_Thread 是和 sn_Node_Init_Thread 并行或之后的）
        # 在 main.py (StarryNet.py) 里，create_nodes 之后才 create_links。
        # 所以此时远程服务器上还 *没有* skycastle 代码！
        
        # 所以我们必须在这里先上传 Agent 代码 (或者只上传 node_agent.py)
        # 为了简单，我们这里临时上传一下 node_agent.py 到 /root/node_agent.py
        
        local_agent_path = os.path.join(os.getcwd(), "skycastle/node_agent.py")
        if not os.path.exists(local_agent_path):
             # 尝试上一级
             local_agent_path = os.path.join(os.getcwd(), "../skycastle/node_agent.py")
             
        # 建立临时 SFTP 连接上传单个文件
        ftp = sn_init_remote_ftp(self.remote_ssh.get_transport())
        try:
            ftp.put(local_agent_path, "/root/node_agent.py")
            print("[SkyCastle] Uploaded node_agent.py to remote host.")
        except Exception as e:
            print(f"[SkyCastle] Error uploading agent: {e}")
        
        # (3) 遍历容器拷贝并启动
        for sat_idx, container_id in enumerate(self.container_id_list):
            sat_id = sat_idx + 1
            if sat_id > controller.total_sats: continue # 地面站暂不处理

            role = "NORMAL"
            if sat_id in cluster_anchors.values():
                role = "ANCHOR"
            
            # 拷贝进去
            sn_remote_cmd(self.remote_ssh, f"docker cp /root/node_agent.py {container_id}:/root/node_agent.py")
            
            # 启动
            cmd = (
                f"docker exec -d {container_id} /bin/sh -c "
                f"'nohup python3 /root/node_agent.py --id {sat_id} --role {role} "
                f"> /var/log/agent.log 2>&1 &'"
            )
            sn_remote_cmd(self.remote_ssh, cmd)
            
        print(f"[SkyCastle] Agents deployed. Anchors: {list(cluster_anchors.values())}")


def sn_get_container_info(remote_machine_ssh):
    #  Read all container information in all_container_info
    all_container_info = sn_remote_cmd(remote_machine_ssh, """docker ps --filter "name=^/(constellation-test|ovs_container)" --format "{{.ID}}" """)
    n_container = len(all_container_info)
    container_id_list = []
    for container_idx in range(0, n_container):
        container_id_list.append(all_container_info[container_idx].split()[0])

    return container_id_list


def sn_delete_remote_network_bridge(remote_ssh):
    all_br_info = sn_remote_cmd(remote_ssh, "docker network ls")
    for line in all_br_info:
        if "La" in line or "Le" in line or "GS" in line:
            network_name = line.split()[1]
            print('docker network rm ' + network_name)
            sn_remote_cmd(remote_ssh, 'docker network rm ' + network_name)


def sn_reset_docker_env(remote_ssh, docker_service_name, node_size):
    print("Reset docker environment for constellation emulation ...")
    print("Remove legacy containers.")
    print(sn_remote_cmd(remote_ssh,
                        "docker service rm " + docker_service_name))
    print(sn_remote_cmd(remote_ssh, """docker ps -a --filter "name=^/constellation-test" --format "{{.ID}}" | xargs -r docker rm -f"""))
    print(sn_remote_cmd(remote_ssh, """docker ps -a --filter "name=^/ovs_container" --format "{{.ID}}" | xargs -r docker rm -f"""))
    print("Remove legacy emulated ISLs.")
    sn_delete_remote_network_bridge(remote_ssh)
    print("Creating new containers...")
    sn_remote_cmd(
        remote_ssh, "docker service create --replicas " + str(node_size) +
        " --name " + str(docker_service_name) +
        " --sysctl net.ipv6.conf.all.disable_ipv6=0 " +
        "--sysctl net.ipv6.conf.all.forwarding=1 " +
        " --cap-add ALL starrynet:latest tail -f /dev/null")


def sn_rename_all_container(remote_ssh, container_id_list, new_idx):
    print("Rename all containers ...")
    new_idx = 1
    for container_id in container_id_list:
        sn_remote_cmd(
            remote_ssh, "docker rename " + str(container_id) +
            " ovs_container_" + str(new_idx))
        new_idx = new_idx + 1


# A thread designed for initializing constellation links.
class sn_Link_Init_Thread(threading.Thread):

    def __init__(self, remote_ssh, remote_ftp, orbit_num, sat_num,
                 constellation_size, fac_num, file_path,
                 configuration_file_path, sat_bandwidth, sat_ground_bandwidth,
                 sat_loss, sat_ground_loss):
        threading.Thread.__init__(self)
        self.remote_ssh = remote_ssh
        self.constellation_size = constellation_size
        self.fac_num = fac_num
        self.orbit_num = orbit_num
        self.sat_num = sat_num
        self.file_path = file_path
        self.configuration_file_path = configuration_file_path
        self.sat_bandwidth = sat_bandwidth
        self.sat_ground_bandwidth = sat_ground_bandwidth
        self.sat_loss = sat_loss
        self.sat_ground_loss = sat_ground_loss
        self.remote_ftp = remote_ftp

    def run(self):
        print('Run in link init thread.')
        self.remote_ftp.put(
            os.path.join(os.getcwd(), "starrynet/sn_orchestrater.py"),
            self.file_path + "/sn_orchestrater.py")
        # === [SkyCastle] 2. 上传 skycastle 目录 (用于远程调用) ===
        print("Uploading SkyCastle modules...")
        local_skycastle_path = os.path.join(os.getcwd(), "skycastle")
        if not os.path.exists(local_skycastle_path):
             local_skycastle_path = os.path.join(os.getcwd(), "../skycastle")
             
        remote_skycastle_path = self.file_path + "/skycastle"
        sn_upload_dir(self.remote_ftp, local_skycastle_path, remote_skycastle_path)
        self.remote_ftp.put(
            self.configuration_file_path + "/" + self.file_path +
            '/delay/1.txt', self.file_path + "/1.txt")
        print('Initializing links ...')
        sn_remote_cmd(
            self.remote_ssh, "/root/StarryNet/venv/bin/python " + self.file_path +
            "/sn_orchestrater.py" + " " + str(self.orbit_num) + " " +
            str(self.sat_num) + " " + str(self.constellation_size) + " " +
            str(self.fac_num) + " " + str(self.sat_bandwidth) + " " +
            str(self.sat_loss) + " " + str(self.sat_ground_bandwidth) + " " +
            str(self.sat_ground_loss) + " " + self.file_path + "/1.txt")


# A thread designed for initializing bird routing.
class sn_Routing_Init_Thread(threading.Thread):

    def __init__(self, remote_ssh, remote_ftp, orbit_num, sat_num,
                 constellation_size, fac_num, file_path, configuration_file_path, sat_bandwidth,
                 sat_ground_bandwidth, sat_loss, sat_ground_loss):
        threading.Thread.__init__(self)
        self.remote_ssh = remote_ssh
        self.constellation_size = constellation_size
        self.fac_num = fac_num
        self.orbit_num = orbit_num
        self.sat_num = sat_num
        self.file_path = file_path
        self.configuration_file_path = configuration_file_path
        self.sat_bandwidth = sat_bandwidth
        self.sat_ground_bandwidth = sat_ground_bandwidth
        self.sat_loss = sat_loss
        self.sat_ground_loss = sat_ground_loss
        self.remote_ftp = remote_ftp

    def run(self):
        print(
            "Copy bird configuration file to each container and run routing process."
        )
        self.remote_ftp.put(
            os.path.join(os.getcwd(), "starrynet/sn_orchestrater.py"),
            self.file_path + "/sn_orchestrater.py")
          # 2. [关键新增] 上传 skycastle 目录
        print("Uploading SkyCastle modules...")
        local_skycastle_path = os.path.join(os.getcwd(), "skycastle") # 注意这里假设运行目录是项目根目录
          # 如果找不到，可以尝试向上查找
        if not os.path.exists(local_skycastle_path):
             local_skycastle_path = os.path.join(os.getcwd(), "../skycastle")
             
        remote_skycastle_path = self.file_path + "/skycastle"
        sn_upload_dir(self.remote_ftp, local_skycastle_path, remote_skycastle_path)
          # 3. 上传拓扑文件
        self.remote_ftp.put(
            self.configuration_file_path + "/" + self.file_path +
            '/delay/1.txt', self.file_path + "/1.txt")
        print('Initializing routing ...')
        sn_remote_cmd(
            self.remote_ssh, "/root/StarryNet/venv/bin/python " + self.file_path +
            "/sn_orchestrater.py" + " " + str(self.constellation_size) + " " +
            str(self.fac_num) + " " + self.file_path)
        print("Routing initialized!")


# A thread designed for emulation.
class sn_Emulation_Start_Thread(threading.Thread):

    def __init__(self, remote_ssh, remote_ftp, sat_loss, sat_ground_bw,
                 sat_ground_loss, container_id_list, file_path,
                 configuration_file_path, update_interval, constellation_size,
                 ping_src, ping_des, ping_time, sr_src, sr_des, sr_target,
                 sr_time, damage_ratio, damage_time, damage_list,
                 recovery_time, route_src, route_time, duration,
                 utility_checking_time, perf_src, perf_des, perf_time,
                 neighbors_recording_time, routing_table_recording_enabled=False,
                 routing_table_recording_interval=1):
        threading.Thread.__init__(self)
        self.remote_ssh = remote_ssh
        self.remote_ftp = remote_ftp
        self.sat_loss = sat_loss
        self.sat_ground_bw = sat_ground_bw
        self.sat_ground_loss = sat_ground_loss
        self.container_id_list = copy.deepcopy(container_id_list)
        self.file_path = file_path
        self.configuration_file_path = configuration_file_path
        self.update_interval = update_interval
        self.constellation_size = constellation_size
        self.ping_src = ping_src
        self.ping_des = ping_des
        self.ping_time = ping_time
        self.perf_src = perf_src
        self.perf_des = perf_des
        self.perf_time = perf_time
        self.sr_src = sr_src
        self.sr_des = sr_des
        self.sr_target = sr_target
        self.sr_time = sr_time
        self.damage_ratio = damage_ratio
        self.damage_time = damage_time
        self.damage_list = damage_list
        self.recovery_time = recovery_time
        self.route_src = route_src
        self.route_time = route_time
        self.duration = duration
        self.utility_checking_time = utility_checking_time
        self.neighbors_recording_time = neighbors_recording_time
        self.routing_table_recording_enabled = routing_table_recording_enabled
        self.routing_table_recording_interval = routing_table_recording_interval
        if self.container_id_list == []:
            self.container_id_list = sn_get_container_info(self.remote_ssh)

    def run(self):
        ping_threads = []
        perf_threads = []
        timeptr = 2  # current emulating time

        # 初始化区块链管理器（可选功能）
        blockchain_manager = None
        try:
            from starrynet.blockchain import BlockchainManager
            blockchain_config_path = os.path.join(
                os.path.dirname(__file__),
                'blockchain',
                'blockchain_config.json'
            )
            if os.path.exists(blockchain_config_path):
                blockchain_manager = BlockchainManager(blockchain_config_path)
                print("[Emulation] 区块链管理器已启用")
            else:
                print("[Emulation] 区块链配置文件不存在，跳过区块链集成")
        except Exception as e:
            print(f"[Emulation] 区块链管理器初始化失败: {e}")
            print("[Emulation] 将继续运行模拟，但不执行区块链命令")

        topo_change_file_path = self.configuration_file_path + "/" + self.file_path + '/Topo_leo_change.txt'
        fi = open(topo_change_file_path, 'r')
        line = fi.readline()
        while line:  # starting reading change information and emulating
            words = line.split()
            if words[0] == 'time':
                print('Emulation in No.' + str(timeptr) + ' second.')
                # the time when the new change occurrs
                current_time = str(int(words[1].strip()[:-1]))
                while int(current_time) > timeptr:
                    start_time = time.time()
                    if timeptr in self.utility_checking_time:
                        sn_check_utility(
                            timeptr, self.remote_ssh,
                            self.configuration_file_path + "/" +
                            self.file_path)
                    if timeptr % self.update_interval == 0:
                        # updating link delays after link changes
                        sn_update_delay(self.file_path,
                                        self.configuration_file_path, timeptr,
                                        self.constellation_size,
                                        self.remote_ssh, self.remote_ftp)
                    if timeptr in self.damage_time:
                        sn_damage(
                            self.damage_ratio[self.damage_time.index(timeptr)],
                            self.damage_list, self.constellation_size,
                            self.remote_ssh, self.remote_ftp, self.file_path,
                            self.configuration_file_path)
                    if timeptr in self.recovery_time:
                        sn_recover(self.damage_list, self.sat_loss,
                                   self.remote_ssh, self.remote_ftp,
                                   self.file_path,
                                   self.configuration_file_path)
                    if timeptr in self.sr_time:
                        index = [
                            i for i, val in enumerate(self.sr_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            sn_sr(self.sr_src[index_num],
                                  self.sr_des[index_num],
                                  self.sr_target[index_num],
                                  self.container_id_list, self.remote_ssh)
                    if timeptr in self.ping_time:
                        if timeptr in self.ping_time:
                            index = [
                                i for i, val in enumerate(self.ping_time)
                                if val == timeptr
                            ]
                            for index_num in index:
                                ping_thread = threading.Thread(
                                    target=sn_ping,
                                    args=(self.ping_src[index_num],
                                          self.ping_des[index_num],
                                          self.ping_time[index_num],
                                          self.constellation_size,
                                          self.container_id_list,
                                          self.file_path,
                                          self.configuration_file_path,
                                          self.remote_ssh))
                                ping_thread.start()
                                ping_threads.append(ping_thread)
                    if timeptr in self.perf_time:
                        if timeptr in self.perf_time:
                            index = [
                                i for i, val in enumerate(self.perf_time)
                                if val == timeptr
                            ]
                            for index_num in index:
                                perf_thread = threading.Thread(
                                    target=sn_perf,
                                    args=(self.perf_src[index_num],
                                          self.perf_des[index_num],
                                          self.perf_time[index_num],
                                          self.constellation_size,
                                          self.container_id_list,
                                          self.file_path,
                                          self.configuration_file_path,
                                          self.remote_ssh))
                                perf_thread.start()
                                perf_threads.append(perf_thread)
                    if timeptr in self.route_time:
                        index = [
                            i for i, val in enumerate(self.route_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            sn_route(self.route_src[index_num],
                                     self.route_time[index_num],
                                     self.file_path,
                                     self.configuration_file_path,
                                     self.container_id_list, self.remote_ssh)
                    timeptr += 1
                    end_time = time.time()
                    passed_time = (
                        end_time -
                        start_time) if (end_time - start_time) < 1 else 1
                    sleep(1 - passed_time)
                    if timeptr in self.neighbors_recording_time:
                        # 记录所有节点的邻居关系
                        sn_record_neighbors(timeptr, self.constellation_size,
                                           self.file_path,
                                           self.configuration_file_path,
                                           self.remote_ssh)
                    # 记录所有节点的路由表（如果启用）
                    if self.routing_table_recording_enabled and timeptr % self.routing_table_recording_interval == 0:
                        sn_record_all_routing_tables(timeptr, self.constellation_size,
                                                   self.file_path,
                                                   self.configuration_file_path,
                                                   self.container_id_list,
                                                   self.remote_ssh)
                    if timeptr >= self.duration:
                        # 清理区块链连接
                        if blockchain_manager:
                            try:
                                blockchain_manager.shutdown_all()
                            except Exception as e:
                                print(f"[Emulation] 关闭区块链连接时出错: {e}")
                        return
                    print('Emulation in No.' + str(timeptr) + ' second.')
                print("A change in time " + current_time + ':')
                line = fi.readline()
                words = line.split()
                line = fi.readline()
                line = fi.readline()
                words = line.split()
                while words[0] != 'del:':  # addlink
                    word = words[0].split('-')
                    s = int(word[0])
                    f = int(word[1])
                    if s > f:
                        tmp = s
                        s = f
                        f = tmp
                    print("add link", s, f)
                    current_topo_path = self.configuration_file_path + "/" + self.file_path + '/delay/' + str(
                        current_time) + '.txt'
                    matrix = sn_get_param(current_topo_path)
                    sn_establish_new_GSL(self.container_id_list, matrix,
                                         self.constellation_size,
                                         self.sat_ground_bw,
                                         self.sat_ground_loss, s, f,
                                         self.remote_ssh)

                    # 区块链集成：处理卫星连接到地面站
                    if blockchain_manager and s <= self.constellation_size < f:
                        sat_id = s
                        gs_id = f - self.constellation_size
                        try:
                            blockchain_manager.handle_satellite_connect(sat_id, gs_id)
                        except Exception as e:
                            print(f"[Emulation] 区块链连接处理失败 (sat={sat_id}, gs={gs_id}): {e}")

                    line = fi.readline()
                    words = line.split()
                line = fi.readline()
                words = line.split()
                if len(words) == 0:
                    return
                while words[0] != 'time':  # delete link
                    word = words[0].split('-')
                    s = int(word[0])
                    f = int(word[1])
                    if s > f:
                        tmp = s
                        s = f
                        f = tmp
                    print("del link " + str(s) + "-" + str(f) + "\n")
                    sn_del_link(s, f, self.container_id_list, self.remote_ssh)

                    # 区块链集成：处理卫星断开地面站连接
                    if blockchain_manager and s <= self.constellation_size < f:
                        sat_id = s
                        gs_id = f - self.constellation_size
                        try:
                            blockchain_manager.handle_satellite_disconnect(sat_id, gs_id)
                        except Exception as e:
                            print(f"[Emulation] 区块链断开处理失败 (sat={sat_id}, gs={gs_id}): {e}")

                    line = fi.readline()
                    words = line.split()
                    if len(words) == 0:
                        return
                if timeptr in self.utility_checking_time:
                    sn_check_utility(
                        timeptr, self.remote_ssh,
                        self.configuration_file_path + "/" + self.file_path)
                if timeptr % self.update_interval == 0:
                    # updating link delays after link changes
                    sn_update_delay(self.file_path,
                                    self.configuration_file_path, timeptr,
                                    self.constellation_size, self.remote_ssh,
                                    self.remote_ftp)
                if timeptr in self.damage_time:
                    sn_damage(
                        self.damage_ratio[self.damage_time.index(timeptr)],
                        self.damage_list, self.constellation_size,
                        self.remote_ssh, self.remote_ftp, self.file_path,
                        self.configuration_file_path)
                if timeptr in self.recovery_time:
                    sn_recover(self.damage_list, self.sat_loss,
                               self.remote_ssh, self.remote_ftp,
                               self.file_path, self.configuration_file_path)
                if timeptr in self.sr_time:
                    index = [
                        i for i, val in enumerate(self.sr_time)
                        if val == timeptr
                    ]
                    for index_num in index:
                        sn_sr(self.sr_src[index_num], self.sr_des[index_num],
                              self.sr_target[index_num],
                              self.container_id_list, self.remote_ssh)
                if timeptr in self.ping_time:
                    if timeptr in self.ping_time:
                        index = [
                            i for i, val in enumerate(self.ping_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            ping_thread = threading.Thread(
                                target=sn_ping,
                                args=(self.ping_src[index_num],
                                      self.ping_des[index_num],
                                      self.ping_time[index_num],
                                      self.constellation_size,
                                      self.container_id_list, self.file_path,
                                      self.configuration_file_path,
                                      self.remote_ssh))
                            ping_thread.start()
                            ping_threads.append(ping_thread)
                if timeptr in self.perf_time:
                    if timeptr in self.perf_time:
                        index = [
                            i for i, val in enumerate(self.perf_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            perf_thread = threading.Thread(
                                target=sn_perf,
                                args=(self.perf_src[index_num],
                                      self.perf_des[index_num],
                                      self.perf_time[index_num],
                                      self.constellation_size,
                                      self.container_id_list, self.file_path,
                                      self.configuration_file_path,
                                      self.remote_ssh))
                            perf_thread.start()
                            perf_threads.append(perf_thread)
                if timeptr in self.route_time:
                    index = [
                        i for i, val in enumerate(self.route_time)
                        if val == timeptr
                    ]
                    for index_num in index:
                        sn_route(self.route_src[index_num],
                                 self.route_time[index_num], self.file_path,
                                 self.configuration_file_path,
                                 self.container_id_list, self.remote_ssh)
                if timeptr in self.neighbors_recording_time:
                    # 记录所有节点的邻居关系
                    sn_record_neighbors(timeptr, self.constellation_size,
                                       self.file_path,
                                       self.configuration_file_path,
                                       self.remote_ssh)
                # 记录所有节点的路由表（如果启用）
                if self.routing_table_recording_enabled and timeptr % self.routing_table_recording_interval == 0:
                    sn_record_all_routing_tables(timeptr, self.constellation_size,
                                               self.file_path,
                                               self.configuration_file_path,
                                               self.container_id_list,
                                               self.remote_ssh)
                timeptr += 1  # current emulating time
                if timeptr >= self.duration:
                    return
        fi.close()
        for ping_thread in ping_threads:
            ping_thread.join()
        for perf_thread in perf_threads:
            perf_thread.join()

        # 清理区块链连接
        if blockchain_manager:
            try:
                blockchain_manager.shutdown_all()
            except Exception as e:
                print(f"[Emulation] 关闭区块链连接时出错: {e}")



def sn_check_utility(time_index, remote_ssh, file_path):
    result = sn_remote_cmd(remote_ssh, "vmstat")
    f = open(file_path + "/utility-info" + "_" + str(time_index) + ".txt", "w")
    f.writelines(result)
    f.close()


def sn_update_delay(file_path, configuration_file_path, timeptr,
                    constellation_size, remote_ssh,
                    remote_ftp):  # updating delays
    remote_ftp.put(os.path.join(os.getcwd(), "starrynet/sn_orchestrater.py"),
                   file_path + "/sn_orchestrater.py")
    remote_ftp.put(
        configuration_file_path + "/" + file_path + '/delay/' + str(timeptr) +
        '.txt', file_path + '/' + str(timeptr) + '.txt')
    sn_remote_cmd(
        remote_ssh,
        "/root/StarryNet/venv/bin/python " + file_path + "/sn_orchestrater.py " + file_path + '/' +
        str(timeptr) + '.txt ' + str(constellation_size) + " update")
    print("Delay updating done.\n")


def sn_damage(ratio, damage_list, constellation_size, remote_ssh, remote_ftp,
              file_path, configuration_file_path):
    print("Randomly setting damaged links...\n")
    random_list = []
    cumulated_damage_list = damage_list
    while len(random_list) < (int(constellation_size * ratio)):
        target = int(random.uniform(0, constellation_size - 1))
        random_list.append(target)
        cumulated_damage_list.append(target)
    numpy.savetxt(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', random_list)
    remote_ftp.put(os.path.join(os.getcwd(), "starrynet/sn_orchestrater.py"),
                   file_path + "/sn_orchestrater.py")
    remote_ftp.put(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', file_path + "/damage_list.txt")
    sn_remote_cmd(remote_ssh,
                  "/root/StarryNet/venv/bin/python " + file_path + "/sn_orchestrater.py " + file_path)
    print("Damage done.\n")


def sn_recover(damage_list, sat_loss, remote_ssh, remote_ftp, file_path,
               configuration_file_path):
    print("Recovering damaged links...\n")
    cumulated_damage_list = damage_list
    numpy.savetxt(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', cumulated_damage_list)
    remote_ftp.put(os.path.join(os.getcwd(), "starrynet/sn_orchestrater.py"),
                   file_path + "/sn_orchestrater.py")
    remote_ftp.put(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', file_path + "/damage_list.txt")
    sn_remote_cmd(
        remote_ssh, "/root/StarryNet/venv/bin/python " + file_path + "/sn_orchestrater.py " +
        file_path + " " + str(sat_loss))
    cumulated_damage_list.clear()
    print("Link recover done.\n")


def sn_sr(src, des, target, container_id_list, remote_ssh):
    ifconfig_output = sn_remote_cmd(
        remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
        " ifconfig | sed 's/[ \t].*//;/^\(eth0\|\)\(lo\|\)$/d'")
    des_IP = sn_remote_cmd(
        remote_ssh,
        "docker exec -it " + str(container_id_list[des - 1]) + " ifconfig " +
        ifconfig_output[0].strip() + "|awk -F '[ :]+' 'NR==2{print $3}'")
    target_IP = sn_remote_cmd(
        remote_ssh, "docker exec -it " + str(container_id_list[target - 1]) +
        " ifconfig B" + str(target) + "-eth" + str(src) +
        "|awk -F '[ :]+' 'NR==2{print $3}'")
    sn_remote_cmd(
        remote_ssh, "docker exec -d " + str(container_id_list[src - 1]) +
        " ip route del " + str(des_IP[0][:-3]) + "0/24")
    sn_remote_cmd(
        remote_ssh, "docker exec -d " + str(container_id_list[src - 1]) +
        " ip route add " + str(des_IP[0][:-3]) + "0/24 dev B%d-eth%d via " %
        (src, target) + target_IP[0])
    print("docker exec -d " + str(container_id_list[src - 1]) +
          " ip route add " + str(des_IP[0][:-3]) + "0/24 dev B%d-eth%d via " %
          (src, target) + target_IP[0])


def sn_ping(src, des, time_index, constellation_size, container_id_list,
            file_path, configuration_file_path, remote_ssh):
    if des <= constellation_size:
        ifconfig_output = sn_remote_cmd(
            remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
            " ifconfig | sed 's/[ \t].*//;/^\(eth0\|\)\(lo\|\)$/d'")
        des_IP = sn_remote_cmd(
            remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
            " ifconfig " + ifconfig_output[0].strip() +
            "|awk -F '[ :]+' 'NR==2{print $3}'")
    else:
        des_IP = sn_remote_cmd(
            remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
            " ifconfig B" + str(des) +
            "-default |awk -F '[ :]+' 'NR==2{print $3}'")
    ping_result = sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[src - 1]) +
        " ping " + str(des_IP[0].strip()) + " -c 4 -i 0.01 ")
    f = open(
        configuration_file_path + "/" + file_path + "/ping-" + str(src) + "-" +
        str(des) + "_" + str(time_index) + ".txt", "w")
    f.writelines(ping_result)
    f.close()


def sn_perf(src, des, time_index, constellation_size, container_id_list,
            file_path, configuration_file_path, remote_ssh):
    if des <= constellation_size:
        ifconfig_output = sn_remote_cmd(
            remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
            " ifconfig | sed 's/[ \t].*//;/^\(eth0\|\)\(lo\|\)$/d'")
        des_IP = sn_remote_cmd(
            remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
            " ifconfig " + ifconfig_output[0].strip() +
            "|awk -F '[ :]+' 'NR==2{print $3}'")
    else:
        des_IP = sn_remote_cmd(
            remote_ssh, "docker exec -it " + str(container_id_list[des - 1]) +
            " ifconfig B" + str(des) +
            "-default |awk -F '[ :]+' 'NR==2{print $3}'")

    sn_remote_cmd(
        remote_ssh,
        "docker exec -id " + str(container_id_list[des - 1]) + " iperf3 -s ")
    print("iperf server success")
    perf_result = sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[src - 1]) +
        " iperf3 -c " + str(des_IP[0].strip()) + " -t 5 ")
    print("iperf client success")
    f = open(
        configuration_file_path + "/" + file_path + "/perf-" + str(src) + "-" +
        str(des) + "_" + str(time_index) + ".txt", "w")
    f.writelines(perf_result)
    f.close()


def sn_route(src, time_index, file_path, configuration_file_path,
             container_id_list, remote_ssh):
    route_result = sn_remote_cmd(
        remote_ssh,
        "docker exec -it " + str(container_id_list[src - 1]) + " route ")
    f = open(
        configuration_file_path + "/" + file_path + "/route-" + str(src) +
        "_" + str(time_index) + ".txt", "w")
    f.writelines(route_result)
    f.close()

def sn_establish_new_GSL(container_id_list, matrix, constellation_size, bw,
                         loss, sat_index, GS_index, remote_ssh):
    import time
    i = sat_index
    j = GS_index
    delay = str(matrix[i - 1][j - 1])
    address_16_23 = (j - constellation_size) & 0xff
    address_8_15 = i & 0xff
    
    # 计算子网段字符串，例如 "9.1.22.0/24"
    target_subnet = "9." + str(address_16_23) + "." + str(address_8_15) + ".0/24"
    GSL_name = "GSL_" + str(i) + "-" + str(j)
    
    # 1. 创建网络
    sn_remote_cmd(
        remote_ssh, 'docker network create ' + GSL_name + " --subnet " + target_subnet)
    print('[Create GSL:]' + 'docker network create ' + GSL_name +
          " --subnet " + target_subnet)

    # ==========================
    #   Part 1: 卫星节点 (Node i)
    # ==========================
    target_ip_i = "9." + str(address_16_23) + "." + str(address_8_15) + ".50"
    
    # 预防性断开
    sn_remote_cmd(remote_ssh, 'docker network disconnect -f ' + GSL_name + " " + str(container_id_list[i - 1]))
    time.sleep(0.2)
    
    # 连接卫星
    res = sn_remote_cmd(
        remote_ssh, 'docker network connect ' + GSL_name + " " +
        str(container_id_list[i - 1]) + " --ip " + target_ip_i)
    if res and len(res) > 0 and ("Error" in res[0] or "failed" in res[0]):
        print(f"!!! Warning: Node {i} connect output: {res}")
    
    # --- 卫星端重试逻辑 ---
    target_interface = None
    for _ in range(20):
        cmd = "docker exec " + str(container_id_list[i - 1]) + \
              " ip addr | grep 'inet " + target_ip_i + "' | awk '{print $NF}'"
        out = sn_remote_cmd(remote_ssh, cmd)
        
        if out and len(out) > 0 and out[0].strip():
            target_interface = out[0].strip()
            if "@" in target_interface: target_interface = target_interface.split('@')[0]
            target_interface = target_interface.replace(":", "")
            break
        time.sleep(0.5)

    if target_interface:
        new_name = "B" + str(i - 1 + 1) + "-eth" + str(j)
        chain_cmd = "ip link set dev " + target_interface + " down && " + \
                    "ip link set dev " + target_interface + " name " + new_name + " && " + \
                    "ip link set dev " + new_name + " up"
        full_cmd = "docker exec " + str(container_id_list[i - 1]) + " /bin/sh -c '" + chain_cmd + "'"
        sn_remote_cmd(remote_ssh, full_cmd)
        
        tc_cmd = "docker exec -d " + str(container_id_list[i - 1]) + " "
        sn_remote_cmd(remote_ssh, tc_cmd + "tc qdisc add dev " + new_name + " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbps")
        
        print('[Add current node:]' + 'docker network connect ' + GSL_name + " " + str(container_id_list[i - 1]) + " --ip " + target_ip_i)
    else:
        print(f"!!! Error: Failed to find interface on Node {i} (IP: {target_ip_i})")

    # ==========================
    #   Part 2: 地面站节点 (Node j)
    # ==========================
    target_ip_j = "9." + str(address_16_23) + "." + str(address_8_15) + ".60"
    
    # 1. 强制断开旧连接
    sn_remote_cmd(remote_ssh, 'docker network disconnect -f ' + GSL_name + " " + str(container_id_list[j - 1]))
    
    # === [关键修复] 2. 强制删除冲突路由 ===
    # 在连接新网络前，先删掉内核里关于这个网段的旧路由（如果有的话）
    # 即使路由不存在报错也没关系，我们要的就是“确保它不存在”
    print(f"[Debug] Deleting conflicting route {target_subnet} on Node {j}")
    sn_remote_cmd(remote_ssh, "docker exec " + str(container_id_list[j - 1]) + " ip route del " + target_subnet)
    
    time.sleep(0.5)
    
    # 3. 连接网络 (现在应该不会报 conflict 了)
    res = sn_remote_cmd(
        remote_ssh, 'docker network connect ' + GSL_name + " " +
        str(container_id_list[j - 1]) + " --ip " + target_ip_j)
    if res and len(res) > 0:
         print(f"!!! Debug: Node {j} connect output: {res}")
    
    # --- 地面站端重试逻辑 ---
    target_interface = None
    for _ in range(20):
        cmd = "docker exec " + str(container_id_list[j - 1]) + \
              " ip addr | grep 'inet " + target_ip_j + "' | awk '{print $NF}'"
        out = sn_remote_cmd(remote_ssh, cmd)
        
        if out and len(out) > 0 and out[0].strip():
            target_interface = out[0].strip()
            if "@" in target_interface: target_interface = target_interface.split('@')[0]
            target_interface = target_interface.replace(":", "")
            break
        time.sleep(0.5)

    if target_interface:
        new_name = "B" + str(j) + "-eth" + str(i - 1 + 1)
        chain_cmd = "ip link set dev " + target_interface + " down && " + \
                    "ip link set dev " + target_interface + " name " + new_name + " && " + \
                    "ip link set dev " + new_name + " up"
        full_cmd = "docker exec " + str(container_id_list[j - 1]) + " /bin/sh -c '" + chain_cmd + "'"
        sn_remote_cmd(remote_ssh, full_cmd)
        
        tc_cmd = "docker exec -d " + str(container_id_list[j - 1]) + " "
        sn_remote_cmd(remote_ssh, tc_cmd + "tc qdisc add dev " + new_name + " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbps")
        
        print('[Add right node:]' + 'docker network connect ' + GSL_name + " " + str(container_id_list[j - 1]) + " --ip " + target_ip_j)
    else:
        print(f"!!! Error: Failed to find interface on Node {j} (IP: {target_ip_j})")

def sn_del_link(first_index, second_index, container_id_list, remote_ssh):
    sn_remote_cmd(
        remote_ssh, "docker exec -d " +
        str(container_id_list[second_index - 1]) + " ip link set dev B" +
        str(second_index) + "-eth" + str(first_index) + " down")
    sn_remote_cmd(
        remote_ssh, "docker exec -d " +
        str(container_id_list[first_index - 1]) + " ip link set dev B" +
        str(first_index) + "-eth" + str(second_index) + " down")
    GSL_name = "GSL_" + str(first_index) + "-" + str(second_index)
    sn_remote_cmd(
        remote_ssh, 'docker network disconnect ' + GSL_name + " " +
        str(container_id_list[first_index - 1]))
    sn_remote_cmd(
        remote_ssh, 'docker network disconnect ' + GSL_name + " " +
        str(container_id_list[second_index - 1]))
    sn_remote_cmd(remote_ssh, 'docker network rm ' + GSL_name)

def sn_record_neighbors(time_index, constellation_size, file_path,
                        configuration_file_path, remote_ssh):
    """
    记录所有节点的邻居关系
    :param time_index: 记录邻居关系的时间点
    :param constellation_size: 星座大小（卫星数量）
    :param file_path: 文件路径
    :param configuration_file_path: 配置文件路径
    :param remote_ssh: 远程 SSH 连接
    """
    # 创建结果目录
    results_dir = "/root/code/satellite-network-vis/data/neighbors"
    os.makedirs(results_dir, exist_ok=True)
    # 获取所有节点的邻居关系
    neighbors_info = {}
    delaypath = configuration_file_path + "/" + file_path + '/delay/' + str(
        time_index) + '.txt'
    adjacency_matrix = sn_get_param(delaypath)

    if adjacency_matrix is None:
        # 既然文件还没生成且超时了，说明这个时间片的数据确实拿不到
        # 直接 return 结束本次记录，不要让线程崩溃
        return 
    # 遍历所有节点，包括卫星和地面站
    total_nodes = len(adjacency_matrix)
    for node in range(1, total_nodes + 1):
        neighbors = []
        for neighbor in range(total_nodes):
            if float(adjacency_matrix[node - 1][neighbor]) > 0.01:
                neighbors.append(neighbor + 1)
        neighbors_info[node] = neighbors
    
    # 将邻居关系写入文件
    f = open(
        results_dir + "/neighbors_" + str(time_index) + ".txt", "w")
    for node, neighbors in neighbors_info.items():
        f.write(f"Node {node}: {neighbors}\n")
    f.close()
    print(f"Neighbors recorded at time {time_index}")


def sn_record_all_routing_tables(time_index, constellation_size, file_path,
                                 configuration_file_path, container_id_list, remote_ssh):
    """
    记录所有节点的路由表
    :param time_index: 记录路由表的时间点
    :param constellation_size: 星座大小（卫星数量）
    :param file_path: 文件路径
    :param configuration_file_path: 配置文件路径
    :param container_id_list: 容器 ID 列表
    :param remote_ssh: 远程 SSH 连接
    """
    # 创建结果目录
    results_dir = "/root/code/satellite-network-vis/data/routing_tables"
    os.makedirs(results_dir, exist_ok=True)
    
    # 获取所有节点的路由表
    routing_tables = {}
    
    # 遍历所有节点，包括卫星和地面站
    total_nodes = len(container_id_list)
    for node in range(1, total_nodes + 1):
        try:
            # 获取节点的路由表
            route_result = sn_remote_cmd(
                remote_ssh,
                "docker exec -it " + str(container_id_list[node - 1]) + " route "
            )
            # 解析路由表
            routes = []
            for line in route_result:
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 8:
                        route = {
                            "destination": parts[0],
                            "gateway": parts[1],
                            "genmask": parts[2],
                            "flags": parts[3],
                            "metric": parts[4],
                            "ref": parts[5],
                            "use": parts[6],
                            "interface": parts[7]
                        }
                        routes.append(route)
            routing_tables[str(node)] = routes
        except Exception as e:
            print(f"Error recording routing table for node {node}: {e}")
            routing_tables[str(node)] = []
    
    # 构建路由表记录数据结构
    routing_table_data = {
        "time_index": time_index,
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "node_count": total_nodes,
        "routing_tables": routing_tables
    }
    
    # 将路由表记录写入文件
    result_file = os.path.join(results_dir, f"routing_tables_{time_index}.json")
    with open(result_file, 'w') as f:
        json.dump(routing_table_data, f, indent=2)
    
    print(f"All routing tables recorded at time {time_index}")

# === [新增函数] 递归上传目录 ===
def sn_upload_dir(sftp, local_dir, remote_dir):
    try:
        sftp.mkdir(remote_dir)
    except IOError:
        pass 
    for item in os.listdir(local_dir):
        if item.startswith("__") or item.endswith(".pyc") or item == ".git":
            continue
        local_path = os.path.join(local_dir, item)
        remote_path = remote_dir + "/" + item
        if os.path.isfile(local_path):
            sftp.put(local_path, remote_path)
        elif os.path.isdir(local_path):
            sn_upload_dir(sftp, local_path, remote_path)

# A thread designed for stopping the emulation.
class sn_Emulation_Stop_Thread(threading.Thread):

    def __init__(self, remote_ssh, remote_ftp, file_path):
        threading.Thread.__init__(self)
        self.remote_ssh = remote_ssh
        self.remote_ftp = remote_ftp
        self.file_path = file_path

    def run(self):
        print("Deleting all native bridges and containers...")
        self.remote_ftp.put(
            os.path.join(os.getcwd(), "starrynet/sn_orchestrater.py"),
            self.file_path + "/sn_orchestrater.py")
        sn_remote_cmd(self.remote_ssh,
                      "/root/StarryNet/venv/bin/python " + self.file_path + "/sn_orchestrater.py")
