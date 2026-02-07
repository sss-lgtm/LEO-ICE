import os
import json
import time
import random
import math
import sys
import yaml
import base64
import binascii
import ssl
import socket
import grpc

# ================= 1. 路径修复与依赖库导入 =================
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from gmssl import sm2, func
    from asn1crypto import keys, pem, x509
except ImportError:
    print("[Error] 缺少加密库，请安装: pip install gmssl asn1crypto")
    sys.exit(1)

try:
    import service_for_sdk_pb2
    import service_for_sdk_pb2_grpc
    import contractID_pb2
except ImportError:
    try:
        from starrynet import service_for_sdk_pb2
        from starrynet import service_for_sdk_pb2_grpc
        from starrynet import contractID_pb2
    except ImportError:
        print("[Error] 找不到 *_pb2.py 文件")
        service_for_sdk_pb2 = None

# ================= 2. 上链核心工具类 =================

class SM2_KEY_UTILS:
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

    @staticmethod
    def _inv(a, n):
        return pow(a, n - 2, n)

    @staticmethod
    def _add(p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        (x1, y1), (x2, y2) = p1, p2
        if x1 == x2:
            if (y1 + y2) % SM2_KEY_UTILS.p == 0: return None
            return None
        lam = ((y2 - y1) * SM2_KEY_UTILS._inv(x2 - x1, SM2_KEY_UTILS.p)) % SM2_KEY_UTILS.p
        x3 = (lam * lam - x1 - x2) % SM2_KEY_UTILS.p
        y3 = (lam * (x1 - x3) - y1) % SM2_KEY_UTILS.p
        return (x3, y3)

    @staticmethod
    def _double(p):
        if p is None: return None
        (x, y) = p
        lam = ((3 * x * x + SM2_KEY_UTILS.a) * SM2_KEY_UTILS._inv(2 * y, SM2_KEY_UTILS.p)) % SM2_KEY_UTILS.p
        x3 = (lam * lam - 2 * x) % SM2_KEY_UTILS.p
        y3 = (lam * (x - x3) - y) % SM2_KEY_UTILS.p
        return (x3, y3)

    @staticmethod
    def _multiply(k, p):
        res = None
        while k > 0:
            if k % 2 == 1:
                res = SM2_KEY_UTILS._add(res, p)
            p = SM2_KEY_UTILS._double(p)
            k //= 2
        return res

    @staticmethod
    def get_public_key_hex(private_key_hex):
        d = int(private_key_hex, 16)
        G = (SM2_KEY_UTILS.Gx, SM2_KEY_UTILS.Gy)
        P = SM2_KEY_UTILS._multiply(d, G)
        x_hex = hex(P[0])[2:].zfill(64)
        y_hex = hex(P[1])[2:].zfill(64)
        return x_hex + y_hex

def get_server_certificate_and_cn(host, port):
    print(f"[Auto-Fetch] Downloading certificate from {host}:{port}...")
    try:
        cert_pem = ssl.get_server_certificate((host, port))
        cert_bytes = cert_pem.encode('utf-8')
        if pem.detect(cert_bytes):
            _, _, der_bytes = pem.unarmor(cert_bytes)
        else:
            der_bytes = cert_bytes
        cert_obj = x509.Certificate.load(der_bytes)
        subject = cert_obj['tbs_certificate']['subject'].native
        common_name = subject.get('common_name')
        if not common_name:
            common_name = host
        print(f"[Auto-Fetch] Parsed CN: {common_name}")
        return cert_bytes, common_name
    except Exception as e:
        print(f"[Auto-Fetch Error] Failed: {e}")
        return None, None

def load_config(yaml_path="application.yml"):
    search_paths = [
        yaml_path, 
        os.path.join(os.path.dirname(os.path.abspath(__file__)), yaml_path),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", yaml_path)
    ]
    final_path = None
    for p in search_paths:
        if os.path.exists(p):
            final_path = p
            break
    if not final_path:
        raise FileNotFoundError(f"Config file {yaml_path} not found.")
    with open(final_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    return config, final_path

def load_sm2_private_key_hex(key_path):
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    with open(key_path, 'rb') as f:
        key_bytes = f.read()
    if pem.detect(key_bytes):
        _, _, der_bytes = pem.unarmor(key_bytes)
    else:
        der_bytes = key_bytes
    key_info = keys.PrivateKeyInfo.load(der_bytes)
    raw = key_info['private_key'].native
    priv_bytes = None
    if isinstance(raw, (dict, object)) and hasattr(raw, 'get'):
        priv_bytes = raw['private_key']
    elif isinstance(raw, bytes):
        ec_key = keys.ECPrivateKey.load(raw)
        priv_bytes = ec_key['private_key'].native
    if isinstance(priv_bytes, int):
        return hex(priv_bytes)[2:].zfill(64)
    return priv_bytes.hex()

def sm2_sign_data(private_key_hex, data_str):
    public_key_hex = SM2_KEY_UTILS.get_public_key_hex(private_key_hex)
    sm2_crypt = sm2.CryptSM2(public_key=public_key_hex, private_key=private_key_hex)
    data_bytes = data_str.encode('utf-8')
    signature_hex = sm2_crypt.sign_with_sm3(data_bytes)
    if len(signature_hex) > 130:
        return base64.b64encode(binascii.unhexlify(signature_hex)).decode('utf-8')
    len_hex = len(signature_hex)
    r_hex = signature_hex[0:len_hex//2]
    s_hex = signature_hex[len_hex//2:]
    r_int = int(r_hex, 16)
    s_int = int(s_hex, 16)
    def encode_int(num):
        h = hex(num)[2:]
        if len(h) % 2 != 0: h = '0' + h
        b = binascii.unhexlify(h)
        if b[0] & 0x80: b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    content = encode_int(r_int) + encode_int(s_int)
    der_seq = b'\x30' + bytes([len(content)]) + content
    return base64.b64encode(der_seq).decode('utf-8')

def internal_upload_consensus_data(result_info, vote_records, value_summary):
    try:
        conf, conf_path = load_config("application.yml")
        app_conf = conf['raybaas']['app']
        channel_conf = conf['raybaas']['channels']['channel[0]']
        APP_ID = str(app_conf['appId'])
        CHANNEL_NAME = channel_conf['name']
        
        KEY_FILE_NAME = "sm2_private_7bff4c20c76e0a74be3fbdec6cde8dc036433996.key"
        base_dir = os.path.dirname(os.path.abspath(__file__))
        KEY_PATH = os.path.join(base_dir, KEY_FILE_NAME)
        if not os.path.exists(KEY_PATH):
             yml_key_path = app_conf['privateKeyPath']
             KEY_PATH = os.path.join(os.path.dirname(conf_path), yml_key_path)

        TARGET_IP = "192.168.110.60"
        TARGET_PORT = 40005
        BLOCKCHAIN_SERVER = f"{TARGET_IP}:{TARGET_PORT}"

        print(f"[ChainClient] KeyPath: {KEY_PATH}")
        print(f"[ChainClient] Target: {BLOCKCHAIN_SERVER}")
        
        server_cert_bytes, server_cn = get_server_certificate_and_cn(TARGET_IP, TARGET_PORT)
        if not server_cert_bytes:
            return False, "Cert fetch failed"

        options = [('grpc.max_send_message_length', 50 * 1024 * 1024),
                   ('grpc.max_receive_message_length', 50 * 1024 * 1024)]
        creds = grpc.ssl_channel_credentials(root_certificates=server_cert_bytes)
        options.append(('grpc.ssl_target_name_override', server_cn))
        channel_ctx = grpc.secure_channel(BLOCKCHAIN_SERVER, creds, options=options)
        
        private_key_hex = load_sm2_private_key_hex(KEY_PATH)

        with channel_ctx as channel:
            stub = service_for_sdk_pb2_grpc.SdkInvokeServiceStub(channel)

            rand_key = int(time.time() * 1000) % 1000000
            votes_str = json.dumps(vote_records, ensure_ascii=False)
            
            real_payload_dict = {
                "key": rand_key,
                "value": value_summary,
                "info": str(result_info),
                "votes": votes_str
            }
            real_payload_json = json.dumps(real_payload_dict, ensure_ascii=False)
            
            print(f"[ChainClient] Signing payload (Size: {len(real_payload_json)} bytes)...")
            signature = sm2_sign_data(private_key_hex, real_payload_json)

            contract_id_obj = contractID_pb2.ContractID(
                name="GeneralContract",
                version="1.0.0",
                type="2",                     
                language_type="2",            
                identity="GeneralContract"    
            )

            request = service_for_sdk_pb2.SdkInvokeRequest(
                contract_id=contract_id_obj,
                method="create",
                payload=real_payload_json,
                channel_name=CHANNEL_NAME,
                app_id=APP_ID,
                sign=signature
            )

            print("[ChainClient] Invoking 'create'...")
            response = stub.invoke(request)
            
            if response.code == 200 or response.message == "SUCCESS" or response.txHash:
                return True, response.txHash
            else:
                return False, response.message

    except Exception as e:
        print(f"[ChainClient Error] {e}")
        return False, str(e)


# ================= 3. 共识算法类 =================

class ConsensusAlgorithm:
    def __init__(self, sn_instance):
        self.sn = sn_instance
        self.results_dir = "/root/code/satellite-network-vis/data/consensus"
        os.makedirs(self.results_dir, exist_ok=True)
        self.node_weights = {}
        self.initialize_node_weights()
    
    def get_random_timestamp(self):
        base_time = time.time()
        random_offset = random.uniform(0, 0.999)
        timestamp = base_time + random_offset
        return time.strftime("%Y%m%d_%H%M%S", time.localtime(timestamp)) + f".{int((timestamp % 1) * 1000):03d}"
    
    def simulate_network_latency(self, base_delay=0.1, variance=0.05):
        delay = random.normalvariate(base_delay, variance)
        return max(0.001, delay)
    
    def initialize_node_weights(self):
        # 初始权重均为 1.0
        for node in range(1, self.sn.node_size + 1):
            self.node_weights[node] = 1.0
    
    def calculate_random_domains(self, num_domains=5):
        """【修改】随机划分5个域，每个域至少3个节点"""
        total_nodes = 50 
        nodes = list(range(1, total_nodes + 1))
        
        # 保持节点ID顺序 (模拟轨道邻近性)，但切割点随机
        # 需要找 num_domains-1 个切割点
        # 剩余可用位置：total_nodes - (min_size * num_domains)
        min_size = 3
        
        # 简单算法：先给每个域分配3个，剩下的随机分配
        domain_sizes = [min_size] * num_domains
        remaining = total_nodes - (min_size * num_domains)
        
        for _ in range(remaining):
            idx = random.randint(0, num_domains - 1)
            domain_sizes[idx] += 1
            
        # 根据生成的size切分nodes
        domains = []
        start_idx = 0
        for size in domain_sizes:
            end_idx = start_idx + size
            domains.append(nodes[start_idx:end_idx])
            start_idx = end_idx
            
        print(f"[System] 随机分域完成: 各域节点数 -> {domain_sizes}")
        return domains

    def save_domain_info(self, domains, timestamp):
        """【新增】保存分域信息到文件，供前端展示"""
        domain_data = []
        for idx, nodes in enumerate(domains):
            # 假设域内第一个节点为默认接入节点(Leader)，用于前端高亮显示
            leader = nodes[0] if nodes else None
            domain_data.append({
                "domain_id": idx,
                "nodes": nodes,
                "leader": leader,
                "node_count": len(nodes)
            })
        
        output_data = {
            "timestamp": timestamp,
            "strategy": "random_partition", # 分域策略标识
            "total_domains": len(domains),
            "domains": domain_data
        }
        
        filename = os.path.join(self.results_dir, f"wda_domains_{timestamp}.json")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"[System] 分域拓扑信息已保存至: {filename}")
    
    def _log_and_print(self, sender, receiver, msg_type, content, timestamp, latency=0, status="success"):
        if "PBFT" in content:
            if receiver == 1 or random.random() < 0.05:
                arrow = "-->" if status == "success" else "-x->"
                print(f"[{timestamp}] [PBFT] N{sender} {arrow} N{receiver} | {msg_type} | {content}")
        else:
            arrow = "-->" if status == "success" else "-x->"
            print(f"[{timestamp}] [WDA] N{sender} {arrow} N{receiver} | {msg_type.upper()} | {content}")
            
        return {
            "sender": sender,
            "receiver": receiver,
            "type": msg_type,
            "content": content,
            "timestamp": timestamp,
            "latency": round(latency, 3),
            "status": status
        }

    def run_consensus_group(self, group_name, nodes, proposal, time_index, algo_type="WDA"):
        start_time = time.time()
        total_ping = 0
        access_node = nodes[0] # Leader
        node_count = len(nodes)
        
        print(f"\n>>> 启动 [{algo_type}] 共识组: {group_name} (节点数: {node_count}, Leader: {access_node}) <<<")
        
        prepare_msgs = []
        commit_msgs = []
        reply_msgs = []
        message_logs = []
        voting_results = []
        
        # P1: Pre-prepare
        if algo_type == "WDA": print(f"--- P1: Pre-prepare ---")
        for node in nodes:
            if node != access_node:
                try:
                    self.sn.set_ping(access_node, node, time_index)
                    total_ping += 1
                    status = "success"
                except:
                    status = "failed"
                log = self._log_and_print(access_node, node, "pre-prepare", f"提案: {proposal}", self.get_random_timestamp(), 0.02, status)
                message_logs.append(log)

        # P2: Prepare
        if algo_type == "WDA": print(f"--- P2: Prepare ---")
        for node in nodes:
            if node != access_node:
                # 【修改】所有节点 30% 概率投反对票 (模拟恶意/故障)
                # 随机生成一个 0-1 的数，大于 0.3 则赞成(70%)，否则反对(30%)
                is_approve = random.random() > 0.3
                
                vote_type = "approve" if is_approve else "reject"
                voting_results.append({
                    "node": node,
                    "vote": vote_type,
                    "timestamp": self.get_random_timestamp()
                })
                
                if is_approve:
                    prepare_msgs.append(node)
                    if algo_type == "PBFT":
                        targets = random.sample(nodes, 50) 
                        for t in targets:
                            if t != node:
                                self._log_and_print(node, t, "prepare", "PBFT_Prepare", self.get_random_timestamp(), 0.02, "success")
                                total_ping += 1
                    else:
                        pass # WDA 简化为直接响应 Leader
                else:
                    # 打印反对票日志
                    self._log_and_print(node, access_node, "reject", f"拒绝提案", self.get_random_timestamp(), 0.02, "failed")

        # P3: Commit
        threshold = node_count * 2 // 3
        if len(prepare_msgs) >= threshold:
            if algo_type == "WDA": print(f"--- P3: Commit ---")
            for node in nodes:
                if node != access_node:
                    commit_msgs.append(node)
                    if algo_type == "PBFT":
                         targets = random.sample(nodes, 50)
                         for t in targets:
                             if t != node:
                                 self._log_and_print(node, t, "commit", "PBFT_Commit", self.get_random_timestamp(), 0.02, "success")
                                 total_ping += 1
                    else:
                        self._log_and_print(node, access_node, "commit", "锁定", self.get_random_timestamp(), 0.02, "success")

        # P4: Reply
        if algo_type == "WDA": print(f"--- P4: Reply ---")
        for node in nodes:
            if node != access_node:
                reply_msgs.append(node)
                self.sn.set_ping(node, access_node, time_index + 3)
                total_ping += 1
                self._log_and_print(node, access_node, "reply", "Reply", self.get_random_timestamp(), 0.02, "success")

        success = len(reply_msgs) >= threshold
        end_time = time.time()
        
        stats = {
            "success": success,
            "time": round(end_time - start_time, 3),
            "total_votes": len(voting_results),
            "approve_votes": len(prepare_msgs)
        }
        
        print(f">>> [{algo_type}] {group_name} 结束. 结果: {success} (赞成: {len(prepare_msgs)+1}/{len(nodes)}) <<<\n")
        
        # 返回投票详情以便更新权重
        return success, stats, total_ping, access_node, message_logs, voting_results

    def update_node_weights_by_vote(self, voting_results, consensus_success):
        """【修改】根据投票情况精细调整权重"""
        for record in voting_results:
            node = record['node']
            vote = record['vote']
            old_w = self.node_weights.get(node, 1.0)
            
            # 逻辑：
            # 1. 共识成功(主流通过) -> 投approve的加分(贡献者)，投reject的减分(捣乱)
            # 2. 共识失败(主流拒绝) -> 投reject的加分(准确预警)，投approve的减分(盲目)
            
            if consensus_success:
                if vote == "approve":
                    new_w = min(1.0, old_w + 0.05)
                else:
                    new_w = max(0.1, old_w - 0.1)
            else:
                if vote == "reject":
                    new_w = min(1.0, old_w + 0.05)
                else:
                    new_w = max(0.1, old_w - 0.05)
            
            self.node_weights[node] = round(new_w, 2)

    # ================= 核心：PBFT 仿真 =================
    def simulate_pbft(self, time_index):
        start_time = time.time()
        all_nodes = list(range(1, 51))
        
        print(f"\n{'#'*20} 开始 PBFT 全网共识 (Nodes: 1-50) {'#'*20}")
        
        success, stats, total_ping, leader, logs, votes = self.run_consensus_group(
            "Global_PBFT", all_nodes, "PBFT_Block_001", time_index, algo_type="PBFT"
        )
        
        print(f"[PBFT] 正在上链共识结果...")
        value_summary = f"PBFT_Res:{'OK' if success else 'FAIL'}_Votes:{stats['approve_votes']}/{len(all_nodes)}"
        simple_votes = {v['node']: v['vote'] for v in votes}
        
        is_uploaded, tx_hash = internal_upload_consensus_data(
            f"PBFT_Global_Consensus", simple_votes, value_summary
        )
        
        if is_uploaded:
             print(f"[PBFT] ✅ 上链成功! TxHash: {tx_hash} | Value: {value_summary}")
        else:
             print(f"[PBFT] ❌ 上链失败")
             
        return time.time() - start_time, total_ping, logs

    # ================= 核心：WDA 仿真 (含权重更新) =================
    def simulate_wda(self, dummy_size, time_index):
        start_time = time.time()
        # 【修改】使用随机分域
        domains = self.calculate_random_domains(num_domains=5)
        
        # 【新增】保存分域拓扑信息
        self.save_domain_info(domains, self.get_random_timestamp())
        
        total_ping = 0
        all_logs = []
        
        access_nodes_list = []
        all_intra_domain_votes = {}
        
        # 1. 域内共识 (Phase 1)
        print(f"\n{'='*15} WDA 阶段一：并行域内共识 {'='*15}")
        for idx, domain in enumerate(domains):
            success, stats, d_ping, acc_node, logs, votes = self.run_consensus_group(
                f"Domain_{idx}", domain, f"WDA_Prop_{idx}", time_index
            )
            
            # 【修改】基于投票结果更新权重
            self.update_node_weights_by_vote(votes, success)
            
            total_ping += d_ping
            all_logs.extend(logs)
            access_nodes_list.append(acc_node)
            for v in votes:
                all_intra_domain_votes[v['node']] = v['vote']

        # 2. 域间共识 (Phase 2)
        print(f"\n{'='*15} WDA 阶段二：接入节点域间共识 {'='*15}")
        success_inter = False
        votes_inter = []
        
        if len(access_nodes_list) >= 3:
            success_inter, stats_inter, d_ping_inter, _, logs_inter, votes_inter = self.run_consensus_group(
                "Inter_Backbone", access_nodes_list, "WDA_Final_Block", time_index + 100
            )
            total_ping += d_ping_inter
            all_logs.extend(logs_inter)
            
            # 【修改】更新接入节点的权重
            self.update_node_weights_by_vote(votes_inter, success_inter)

        # 3. 结果上链 (Phase 3)
        print(f"\n{'='*15} WDA 阶段三：结果打包上链 {'='*15}")
        total_approve = len([v for v in all_intra_domain_votes.values() if v == 'approve'])+5
        total_votes_count = len(all_intra_domain_votes)+5
        value_summary = f"WDA_Final:{'OK' if success_inter else 'FAIL'}_Votes:{total_approve}/{total_votes_count}"
        
        final_data = {
            "intra_votes": all_intra_domain_votes,
            "inter_votes": {v['node']: v['vote'] for v in votes_inter}
        }
        
        is_uploaded, tx_hash = internal_upload_consensus_data(
            "WDA_Hierarchical_Consensus", final_data, value_summary
        )
        if is_uploaded:
             print(f"[WDA] ✅ 上链成功! TxHash: {tx_hash} | Value: {value_summary}")
        
        # 4. 权重记录 (Phase 4)
        print(f"\n{'='*15} WDA 阶段四：记录全网权重 {'='*15}")
        weight_file = os.path.join(self.results_dir, f"final_node_weights.json")
        with open(weight_file, 'w', encoding='utf-8') as f:
            json.dump(self.node_weights, f, indent=2, sort_keys=True)
        print(f"[System] 所有节点权重已保存至: {weight_file}")
        
        # 打印几个样本
        print("样本权重展示:")
        for n in [1, 15, 30, 45, 50]:
            print(f"  - Node {n}: {self.node_weights[n]}")

        return time.time() - start_time, total_ping, all_logs
    
    def compare_algorithms(self, time_index):
        results = []
        
        # 1. 运行 PBFT
        pbft_time, pbft_ping, pbft_logs = self.simulate_pbft(time_index)
        results.append({
            "algo": "PBFT",
            "time": pbft_time,
            "ping": pbft_ping,
            "logs": pbft_logs
        })
        
        # 2. 运行 WDA
        wda_time, wda_ping, wda_logs = self.simulate_wda(10, time_index + 200)
        results.append({
            "algo": "WDA",
            "time": wda_time,
            "ping": wda_ping,
            "logs": wda_logs
        })
        
        result_file = os.path.join(self.results_dir, f"consensus_comparison_{self.get_random_timestamp()}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[System] 对比结束. 详细日志已保存至: {result_file}")
        return results
