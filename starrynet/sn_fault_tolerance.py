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

# ================= 0. 基础设置 =================
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# ANSI 颜色代码 (已补全 DARKCYAN)
class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'  # 补回这个缺失的属性
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    GREY = '\033[90m'
    END = '\033[0m'

# ================= 1. 依赖库导入 =================
try:
    from gmssl import sm2, func
    from asn1crypto import keys, pem, x509
except ImportError:
    print(f"{Color.RED}[System Error] 缺少加密库{Color.END}")
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
        service_for_sdk_pb2 = None

# ================= 2. 上链工具类 (保持不变) =================
class SM2_KEY_UTILS:
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    @staticmethod
    def _inv(a, n): return pow(a, n - 2, n)
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
            if k % 2 == 1: res = SM2_KEY_UTILS._add(res, p)
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
    try:
        cert_pem = ssl.get_server_certificate((host, port))
        cert_bytes = cert_pem.encode('utf-8')
        if pem.detect(cert_bytes): _, _, der_bytes = pem.unarmor(cert_bytes)
        else: der_bytes = cert_bytes
        cert_obj = x509.Certificate.load(der_bytes)
        subject = cert_obj['tbs_certificate']['subject'].native
        common_name = subject.get('common_name', host)
        return cert_bytes, common_name
    except: return None, None

def load_config(yaml_path="application.yml"):
    search_paths = [yaml_path, os.path.join(os.path.dirname(os.path.abspath(__file__)), yaml_path),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", yaml_path)]
    for p in search_paths:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f: return yaml.safe_load(f), p
    raise FileNotFoundError(f"Config file {yaml_path} not found.")

def load_sm2_private_key_hex(key_path):
    if not os.path.exists(key_path): raise FileNotFoundError(f"Key file not found: {key_path}")
    with open(key_path, 'rb') as f: key_bytes = f.read()
    if pem.detect(key_bytes): _, _, der_bytes = pem.unarmor(key_bytes)
    else: der_bytes = key_bytes
    key_info = keys.PrivateKeyInfo.load(der_bytes)
    raw = key_info['private_key'].native
    if isinstance(raw, (dict, object)) and hasattr(raw, 'get'): priv_bytes = raw['private_key']
    elif isinstance(raw, bytes): 
        ec_key = keys.ECPrivateKey.load(raw)
        priv_bytes = ec_key['private_key'].native
    return hex(priv_bytes)[2:].zfill(64) if isinstance(priv_bytes, int) else priv_bytes.hex()

def sm2_sign_data(private_key_hex, data_str):
    public_key_hex = SM2_KEY_UTILS.get_public_key_hex(private_key_hex)
    sm2_crypt = sm2.CryptSM2(public_key=public_key_hex, private_key=private_key_hex)
    signature_hex = sm2_crypt.sign_with_sm3(data_str.encode('utf-8'))
    if len(signature_hex) > 130: return base64.b64encode(binascii.unhexlify(signature_hex)).decode('utf-8')
    r_hex, s_hex = signature_hex[:len(signature_hex)//2], signature_hex[len(signature_hex)//2:]
    def encode_int(num):
        h = hex(num)[2:]
        if len(h)%2!=0: h='0'+h
        b = binascii.unhexlify(h)
        if b[0]&0x80: b=b'\x00'+b
        return b'\x02'+bytes([len(b)])+b
    content = encode_int(int(r_hex,16)) + encode_int(int(s_hex,16))
    return base64.b64encode(b'\x30'+bytes([len(content)])+content).decode('utf-8')

def internal_upload_consensus_data(result_info, vote_records, value_summary):
    try:
        conf, conf_path = load_config("application.yml")
        app_conf = conf['raybaas']['app']
        channel_conf = conf['raybaas']['channels']['channel[0]']
        
        KEY_FILE_NAME = "sm2_private_7bff4c20c76e0a74be3fbdec6cde8dc036433996.key"
        base_dir = os.path.dirname(os.path.abspath(__file__))
        KEY_PATH = os.path.join(base_dir, KEY_FILE_NAME)
        if not os.path.exists(KEY_PATH):
             KEY_PATH = os.path.join(os.path.dirname(conf_path), app_conf['privateKeyPath'])

        TARGET_IP, TARGET_PORT = "192.168.110.60", 40005
        server_cert_bytes, server_cn = get_server_certificate_and_cn(TARGET_IP, TARGET_PORT)
        if not server_cert_bytes: return False, "Cert fetch failed"

        options = [('grpc.max_send_message_length', 50*1024*1024), ('grpc.max_receive_message_length', 50*1024*1024)]
        creds = grpc.ssl_channel_credentials(root_certificates=server_cert_bytes)
        options.append(('grpc.ssl_target_name_override', server_cn))
        channel_ctx = grpc.secure_channel(f"{TARGET_IP}:{TARGET_PORT}", creds, options=options)
        
        with channel_ctx as channel:
            stub = service_for_sdk_pb2_grpc.SdkInvokeServiceStub(channel)
            rand_key = int(time.time() * 1000) % 1000000
            
            real_payload_dict = {
                "key": rand_key,
                "value": value_summary,
                "info": str(result_info),
                "votes": json.dumps(vote_records, ensure_ascii=False)
            }
            real_payload_json = json.dumps(real_payload_dict, ensure_ascii=False)
            
            signature = sm2_sign_data(load_sm2_private_key_hex(KEY_PATH), real_payload_json)

            request = service_for_sdk_pb2.SdkInvokeRequest(
                contract_id=contractID_pb2.ContractID(name="GeneralContract", version="1.0.0", type="2", language_type="2", identity="GeneralContract"),
                method="create", payload=real_payload_json, channel_name=channel_conf['name'], app_id=str(app_conf['appId']), sign=signature
            )
            response = stub.invoke(request)
            if response.code == 200 or response.message == "SUCCESS" or response.txHash: return True, response.txHash
            else: return False, response.message
    except Exception as e:
        print(f"{Color.RED}[Chain Error] {e}{Color.END}")
        return False, str(e)


# ================= 3. 容错仿真核心类 =================

class FaultTolerance:
    def __init__(self, sn_instance):
        self.sn = sn_instance
        self.results_dir = "/root/code/satellite-network-vis/data/fault_tolerance"
        os.makedirs(self.results_dir, exist_ok=True)
        self.failed_nodes = set()
        self.malicious_nodes = set()
    
    def get_random_timestamp(self):
        base_time = time.time()
        random_offset = random.uniform(0, 0.999)
        timestamp = base_time + random_offset
        return time.strftime("%Y%m%d_%H%M%S", time.localtime(timestamp)) + f".{int((timestamp % 1) * 1000):03d}"
    
    def calculate_random_domains(self):
        total_nodes = 50 
        nodes = list(range(1, total_nodes + 1))
        random.shuffle(nodes)
        domains = []
        for i in range(0, 50, 10):
            domains.append(nodes[i:i+10])
        return domains

    def _record_log(self, sender, receiver, msg_type, content, timestamp, status="success"):
        return {
            "sender": sender, "receiver": receiver, "type": msg_type,
            "content": content, "timestamp": timestamp, "status": status
        }

    def run_consensus_group_with_faults(self, group_name, nodes, proposal, time_index, vote_override=None):
        """
        [Rhythmic Version] 带节奏感的详细打印
        """
        start_time = time.time()
        access_node = nodes[0] # Leader
        
        print(f"\n{Color.PURPLE}{Color.BOLD}[SYSTEM] 启动共识组 [{group_name}] 成员数: {len(nodes)} | Leader: Node {access_node}{Color.END}")
        print(f"{Color.PURPLE}{'-'*70}{Color.END}")
        
        prepare_msgs = []
        commit_msgs = []
        reply_msgs = []
        message_logs = []
        voting_results = []
        
        # Phase 1: 提案
        if access_node in self.failed_nodes:
            print(f" {Color.RED}[CRITICAL] Leader Node {access_node} 发生物理故障(Failed)! 共识发起失败。{Color.END}")
            return False, {}, 0, access_node, [], []
        
        # Phase 2: 投票详情
        print(f" {Color.CYAN}[Phase 2] 节点验证与投票详情 (Voting Details){Color.END}")
        print(f" {'ID':<5} | {'Role':<12} | {'Status':<15} | {'Vote Action'}")
        print(f" {'-'*5}-+-{'-'*12}-+-{'-'*15}-+-{'-'*20}")
        
        for node in nodes:
            time.sleep(0.15) # 节奏控制
            
            if node != access_node:
                # 1. 失效节点
                if node in self.failed_nodes:
                    print(f" {Color.GREY}{node:<5} | FAILED       | No Response     | [TIMEOUT] No Vote{Color.END}")
                    voting_results.append({"node": node, "vote": "none", "role": "failed"})
                    
                # 2. 恶意节点
                elif node in self.malicious_nodes:
                    print(f" {Color.RED}{node:<5} | MALICIOUS    | Attack Detected | [REJECT] Malicious Vote{Color.END}")
                    voting_results.append({"node": node, "vote": "reject", "role": "malicious"})
                    message_logs.append(self._record_log(node, access_node, "reject", "Malicious Reject", self.get_random_timestamp(), "failed"))
                    
                # 3. 诚实节点
                else:
                    # 默认投赞成
                    vote_action = "approve"
                    log_msg = "[APPROVE] Honest Vote"
                    log_color = Color.GREEN
                    
                    # Phase 2 逻辑：Leader 依据自己域的结果投票
                    if vote_override and node in vote_override:
                        if vote_override[node] == "reject":
                            vote_action = "reject"
                            log_msg = "[REJECT] Domain Failed"
                            log_color = Color.YELLOW
                    
                    if vote_action == "approve":
                        print(f" {log_color}{node:<5} | NORMAL       | Verified        | {log_msg}{Color.END}")
                        voting_results.append({"node": node, "vote": "approve", "role": "honest"})
                        prepare_msgs.append(node)
                        message_logs.append(self._record_log(node, access_node, "prepare", "Prepare OK", self.get_random_timestamp(), "success"))
                    else:
                        print(f" {log_color}{node:<5} | NORMAL       | Mandate Reject  | {log_msg}{Color.END}")
                        voting_results.append({"node": node, "vote": "reject", "role": "honest"})
                        message_logs.append(self._record_log(node, access_node, "reject", "Honest Reject", self.get_random_timestamp(), "failed"))

            else:
                # Leader 自己的票
                leader_action = "approve"
                if vote_override and node in vote_override and vote_override[node] == "reject":
                    leader_action = "reject"
                
                if leader_action == "approve":
                    print(f" {Color.BLUE}{node:<5} | LEADER       | Proposer        | [APPROVE] Auto{Color.END}")
                    prepare_msgs.append(node)
                else:
                    print(f" {Color.YELLOW}{node:<5} | LEADER       | Domain Failed   | [REJECT] Honest Report{Color.END}")

        # Phase 3: 统计
        time.sleep(0.5) 
        
        threshold = len(nodes) * 2 // 3
        approve_count = len(prepare_msgs)
        reject_count = len([x for x in voting_results if x['vote']=='reject'])
        dead_count = len([x for x in voting_results if x['vote']=='none'])
        
        # 补上 Leader 自己的反对票统计 (如果它投了反对)
        if vote_override and access_node in vote_override and vote_override[access_node] == "reject":
            reject_count += 1
        
        print(f"\n {Color.CYAN}[Phase 3] 票数统计 (Threshold >= {threshold}){Color.END}")
        print(f"   > 赞成票 (APPROVE): {Color.GREEN}{approve_count}{Color.END}")
        print(f"   > 反对票 (REJECT) : {Color.RED}{reject_count}{Color.END}")
        print(f"   > 未响应 (FAILED) : {Color.GREY}{dead_count}{Color.END}")
        
        if approve_count >= threshold:
            print(f"   {Color.GREEN}>>> 结果: 多数派达成 (Consensus Reached){Color.END}")
            for node in nodes:
                if node != access_node and node not in self.failed_nodes:
                    commit_msgs.append(node)
                    reply_msgs.append(node)
        else:
            print(f"   {Color.RED}>>> 结果: 共识失败 (Consensus Failed){Color.END}")
            return False, {"success": False}, 0, access_node, message_logs, voting_results

        success = len(reply_msgs) >= threshold
        
        stats = {
            "success": success,
            "total_nodes": len(nodes),
            "approve_votes": approve_count,
            "reject_votes": reject_count,
            "failed_nodes": dead_count
        }
        
        if success:
            print(f"{Color.GREEN}[SUCCESS] 共识组 {group_name} 任务完成。{Color.END}")
        else:
            print(f"{Color.RED}[FAILED] 共识组 {group_name} 任务失败。{Color.END}")

        return success, stats, 0, access_node, message_logs, voting_results

    def run_simulation(self):
        """主入口"""
        print(f"\n{Color.PURPLE}{Color.BOLD}{'='*80}")
        print(f"          StarryNet WDA 容错性与攻击防御仿真测试")
        print(f"          场景: 30% 异常节点 (10% 物理失效 + 20% 恶意攻击)")
        print(f"          前提: 假设所有 Leader 节点必然诚实且在线")
        print(f"{'='*80}{Color.END}")
        
        # 1. 随机分域 & 锁定 Leaders
        domains = self.calculate_random_domains()
        leaders = [d[0] for d in domains]
        all_nodes = list(range(1, 51))
        
        follower_nodes = list(set(all_nodes) - set(leaders))
        
        # 2. 角色分配
        self.failed_nodes = set(random.sample(follower_nodes, 5))
        remaining_followers = list(set(follower_nodes) - self.failed_nodes)
        self.malicious_nodes = set(random.sample(remaining_followers, 10))
        
        # 计算诚实节点总数 (Followers + Leaders)
        honest_followers = set(remaining_followers) - self.malicious_nodes
        all_honest_nodes = honest_followers.union(set(leaders))
        
        print(f"\n{Color.YELLOW}[Config] 全网节点身份预设:{Color.END}")
        print(f" {Color.BLUE}● 指挥官 (Leaders): {leaders} (必然诚实){Color.END}")
        print(f" {Color.GREY}● 失效节点 (10%): {sorted(list(self.failed_nodes))}{Color.END}")
        print(f" {Color.RED}● 恶意节点 (20%): {sorted(list(self.malicious_nodes))}{Color.END}")
        print(f" {Color.GREEN}● 诚实节点 (70%): 共 {len(all_honest_nodes)} 个{Color.END}")
        
        all_logs = []
        access_nodes_list = []
        all_intra_domain_votes = {}
        
        backbone_mandates = {}
        
        # 3. 域内共识 (Phase 1)
        print(f"\n{Color.BLUE}{Color.BOLD}>>> 阶段一：全网并行域内共识 (Intra-Domain Consensus) <<<{Color.END}")
        for idx, domain in enumerate(domains):
            success, stats, _, acc_node, logs, votes = self.run_consensus_group_with_faults(
                f"Domain_{idx}", domain, f"Proposal_D{idx}", 10
            )
            
            all_logs.extend(logs)
            access_nodes_list.append(acc_node)
            mandate = "approve" if success else "reject"
            backbone_mandates[acc_node] = mandate
            
            if success:
                print(f"{Color.DARKCYAN}   -> 域 {idx} 达成一致，Leader {acc_node} 将在骨干网投 [赞成] 票{Color.END}")
            else:
                print(f"{Color.YELLOW}   -> 域 {idx} 共识失败，Leader {acc_node} 将在骨干网投 [反对] 票{Color.END}")
            
            for v in votes:
                all_intra_domain_votes[v['node']] = v['vote']
            
            print(f"{Color.GREY}... 正在切换至下一个战区 ...{Color.END}")
            time.sleep(2.0) 

        # 4. 域间共识 (Phase 2)
        print(f"\n{Color.BLUE}{Color.BOLD}>>> 阶段二：骨干网域间共识 (Inter-Domain Consensus) <<<{Color.END}")
        print(f" {Color.CYAN}参与者 (5位指挥官): {access_nodes_list}{Color.END}")
        time.sleep(1.0)
        
        success_inter, stats_inter, _, _, logs_inter, votes_inter = self.run_consensus_group_with_faults(
            "Inter_Backbone", access_nodes_list, "Final_Global_Block", 110, 
            vote_override=backbone_mandates 
        )
        all_logs.extend(logs_inter)

        # 5. 上链 (Phase 3)
        print(f"\n{Color.BLUE}{Color.BOLD}>>> 阶段三：抗毁数据存证上链 (Blockchain Upload) <<<{Color.END}")
        
        total_approve = len([v for v in all_intra_domain_votes.values() if v == 'approve'])
        total_reject = len([v for v in all_intra_domain_votes.values() if v == 'reject'])
        total_fail = 50 - total_approve - total_reject
        
        res_text = "SUCCESS" if success_inter else "FAIL"
        value_summary = f"FT_Test_30%:{res_text}_Votes:{total_approve}Y/{total_reject}N/{total_fail}Dead"
        
        print(f" {Color.CYAN}正在打包数据...{Color.END}")
        time.sleep(1.0)
        print(f"   - 交易摘要: {value_summary}")
        print(f"   - 包含记录: {len(all_intra_domain_votes)} 条域内投票 + {len(votes_inter)} 条骨干投票")
        
        final_data = {
            "test_config": "Fault Tolerance Test (10% Fail, 20% Malicious)",
            "roles": {
                "failed": list(self.failed_nodes),
                "malicious": list(self.malicious_nodes)
            },
            "intra_votes": all_intra_domain_votes,
            "inter_votes": {v['node']: v['vote'] for v in votes_inter}
        }
        
        is_uploaded, tx_hash = internal_upload_consensus_data(
            "Fault_Tolerance_Simulation", final_data, value_summary
        )
        
        if is_uploaded:
            print(f"\n{Color.GREEN}✅ [上链成功] 交易哈希: {tx_hash}{Color.END}")
        else:
            print(f"\n{Color.RED}❌ [上链失败] 请检查网络连接{Color.END}")
            
        ft_log = [{
            "algo": "WDA_Fault_Tolerance",
            "time": 2.5,
            "ping": len(all_logs),
            "timestamp": self.get_random_timestamp(),
            "logs": all_logs
        }]
        result_file = os.path.join(self.results_dir, f"fault_tolerance_simulation.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(ft_log, f, indent=2, ensure_ascii=False)
        print(f"\n{Color.GREY}[System] 详细仿真日志已保存: {result_file}{Color.END}")
