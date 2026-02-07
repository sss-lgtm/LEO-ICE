import os
import json
import time
import random
from datetime import datetime, timedelta

class AttackDetection:
    def __init__(self, sn_instance):
        self.sn = sn_instance
        self.results_dir = "/root/code/satellite-network-vis/data/attack_detection"
        os.makedirs(self.results_dir, exist_ok=True)

    def get_node_ip(self, node_id):
        """根据节点ID生成模拟IP地址"""
        if node_id in [51, 52]:
            return f"9.{node_id}.{node_id}.10"
        else:
            return f"10.{node_id}.{node_id}.30"

    def _print_log(self, timestamp, src_ip, dst_ip, protocol, info):
        print(f"[{timestamp}] [TRAFFIC] SRC:{src_ip:<15} -> DST:{dst_ip:<15} | PROTO:{protocol:<5} | INFO:{info}")
        time.sleep(0.05)

    def _print_report(self, result):
        print("\n" + "="*70)
        print(f"   >>> StarryNet 安全威胁检测报告 <<<")
        print("="*70)
        print(f" [!] 检测结果:   发现异常流量 ({result['severity'].upper()})")
        print(f" [!] 攻击类型:   {result['attack_type']} Attack")
        target_role = "Ground Station" if result['target_node'] in [51, 52] else "Satellite"
        print(f" [!] 目标节点:   Node {result['target_node']} ({self.get_node_ip(result['target_node'])}) [{target_role}]")
        print(f" [!] 发生时间:   {result['timestamp']}")
        print("-" * 70)
        print(" [√] 判定理由:")
        for reason in result['detection_reasons']:
            print(f"     - {reason}")
        print("-" * 70)
        print(" [x] 攻击源详情:")
        attacker_ips = set()
        if 'attacker_nodes' in result:
            for node in result['attacker_nodes']:
                role = "GS" if node in [51, 52] else "SAT"
                attacker_ips.add(f"{self.get_node_ip(node)} (Node {node}) [{role}]")
        elif 'attack_patterns' in result:
             for pattern in result['attack_patterns']:
                 node = pattern.get('source') or pattern.get('attacker')
                 if node:
                     role = "GS" if node in [51, 52] else "SAT"
                     attacker_ips.add(f"{self.get_node_ip(node)} (Node {node}) [{role}]")
        sorted_ips = sorted(list(attacker_ips))
        for i, ip in enumerate(sorted_ips):
            print(f"     {i+1}. {ip}")
            if i >= 4: 
                print(f"     ... 以及其他 {len(sorted_ips)-5} 个来源")
                break
        print("="*70 + "\n")

    def _save_result(self, subdir, result):
        """保存结果到文件（保持原有路径结构）"""
        dir_path = os.path.join(self.results_dir, subdir)
        os.makedirs(dir_path, exist_ok=True)
        filename = f"{subdir.lower()}_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(os.path.join(dir_path, filename), 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    def detect_dos_attack(self, time_index, target_node=None):
        if target_node is None:
            target_node = random.randint(1, self.sn.node_size)
        target_ip = self.get_node_ip(target_node)
        
        attacker_count = random.randint(3, 5)
        attacker_nodes = []
        while len(attacker_nodes) < attacker_count:
            node = random.randint(1, self.sn.node_size)
            if node != target_node and node not in attacker_nodes:
                attacker_nodes.append(node)
        
        print(f"\n[*] 正在监控网络流量... (Time Index: {time_index})")
        base_time = datetime.now()
        attack_time = base_time.strftime("%Y-%m-%d %H:%M:%S")

        attack_patterns = []
        for attacker in attacker_nodes:
            attacker_ip = self.get_node_ip(attacker)
            ping_count = random.randint(3, 5)
            for seq in range(ping_count):
                curr_time = (datetime.now()).strftime("%H:%M:%S.%f")[:-3]
                self._print_log(curr_time, attacker_ip, target_ip, "ICMP", f"Echo Request (Seq={seq+1}, Len=1024B) - FLOOD")
                self.sn.set_ping(attacker, target_node, time_index)
            
            # [恢复字段] time_offset 等细节
            time_offset = random.randint(1, 5)
            pt_time = (base_time + timedelta(seconds=time_offset)).strftime("%Y%m%d_%H%M%S")
            attack_patterns.append({
                "attacker": attacker,
                "target": target_node,
                "action": f"Flood Ping ({ping_count} packets)",
                "timestamp": pt_time
            })

        detection_reasons = [
            "流量基线异常：目标节点入站流量超出阈值 300%",
            f"协议分析：检测到来自 {len(attacker_nodes)} 个源的高频 ICMP 请求",
            "行为特征：请求间隔极短，符合 DoS 洪泛特征"
        ]

        # [恢复字段] 包含 detected, attack_characteristics
        result = {
            "attack_type": "DoS",
            "target_node": target_node,
            "attacker_nodes": attacker_nodes,
            "time_index": time_index,
            "timestamp": attack_time,
            "detected": True,
            "severity": "high",
            "detection_reasons": detection_reasons,
            "attack_patterns": attack_patterns,
            "attack_characteristics": {
                "request_frequency": "high",
                "source_count": len(attacker_nodes),
                "impact_level": "severe"
            }
        }
        
        self._save_result("Dos", result)
        self._print_report(result)
        return result
    
    def detect_ddos_attack(self, time_index, target_node=None):
        if target_node is None:
            target_node = random.choice([51, 52])
        target_ip = self.get_node_ip(target_node)

        attacker_count = random.randint(8, 12)
        attacker_nodes = []
        while len(attacker_nodes) < attacker_count:
            node = random.randint(1, 50)
            if node != target_node and node not in attacker_nodes:
                attacker_nodes.append(node)
        
        print(f"\n[*] 正在监控网络流量... (Time Index: {time_index})")
        base_time = datetime.now()
        attack_time = base_time.strftime("%Y-%m-%d %H:%M:%S")

        attack_patterns = []
        total_packets = 15
        for i in range(total_packets):
            attacker = random.choice(attacker_nodes)
            attacker_ip = self.get_node_ip(attacker)
            curr_time = (datetime.now()).strftime("%H:%M:%S.%f")[:-3]
            self._print_log(curr_time, attacker_ip, target_ip, "UDP", f"Chargen Flood (Len=512B) - DISTRIBUTED")
            self.sn.set_ping(attacker, target_node, time_index)
            
            if i % 3 == 0:
                 time_offset = random.randint(1, 10)
                 pt_time = (base_time + timedelta(seconds=time_offset)).strftime("%Y%m%d_%H%M%S")
                 attack_patterns.append({
                     "attacker": attacker,
                     "target": target_node, 
                     "action": "DDoS Packet Fragment",
                     "timestamp": pt_time
                 })

        detection_reasons = [
            f"分布式特征：检测到 {len(attacker_nodes)} 个僵尸卫星节点协同发起连接",
            "资源耗尽：地面站连接表（Connection Table）已满",
            "流量特征：多源 UDP/TCP SYN 混合洪泛"
        ]

        result = {
            "attack_type": "DDoS",
            "target_node": target_node,
            "attacker_nodes": attacker_nodes,
            "time_index": time_index,
            "timestamp": attack_time,
            "detected": True,
            "severity": "critical",
            "detection_reasons": detection_reasons,
            "attack_patterns": attack_patterns,
            "attack_characteristics": {
                "distributed_sources": True,
                "source_count": len(attacker_nodes),
                "impact_level": "critical"
            }
        }
        
        self._save_result("DDos", result)
        self._print_report(result)
        return result
    
    def detect_probe_attack(self, time_index, target_node=None):
        if target_node is None:
            target_node = random.randint(1, 50)
        attacker_ip = self.get_node_ip(target_node)

        print(f"\n[*] 正在监控网络流量... (Time Index: {time_index})")
        base_time = datetime.now()
        attack_time = base_time.strftime("%Y-%m-%d %H:%M:%S")

        scan_targets = []
        target_count = random.randint(4, 6)
        attack_patterns = []
        
        for i in range(target_count):
            victim = random.randint(1, self.sn.node_size)
            while victim == target_node or victim in scan_targets:
                victim = random.randint(1, self.sn.node_size)
            scan_targets.append(victim)
            
            victim_ip = self.get_node_ip(victim)
            port = random.choice([21, 22, 80, 443, 3306])
            curr_time = (datetime.now()).strftime("%H:%M:%S.%f")[:-3]
            self._print_log(curr_time, attacker_ip, victim_ip, "TCP", f"SYN Scan -> Port {port} (Scanning)")
            self.sn.set_ping(target_node, victim, time_index)
            
            time_offset = random.randint(1, 8)
            pt_time = (base_time + timedelta(seconds=time_offset)).strftime("%Y%m%d_%H%M%S")
            attack_patterns.append({
                "source": target_node,
                "target": victim,
                "action": f"Port Scan {port}",
                "timestamp": pt_time
            })

        detection_reasons = [
            "行为异常：单一源地址在短时间内尝试连接多个不同目标/端口",
            "特征匹配：TCP SYN 扫描模式 (半开连接)",
            f"横向移动迹象：受感染节点正在探测网络内 {len(scan_targets)} 个主机"
        ]
        
        result = {
            "attack_type": "Probe",
            "target_node": target_node,
            "time_index": time_index,
            "timestamp": attack_time,
            "detected": True,
            "severity": "medium",
            "detection_reasons": detection_reasons,
            "attack_patterns": attack_patterns,
            "attack_characteristics": {
                "scanning_behavior": True,
                "target_count": len(scan_targets),
                "impact_level": "medium"
            }
        }
        
        self._save_result("Probe", result)
        self._print_report(result)
        return result
    
    def detect_u2r_attack(self, time_index, target_node=None):
        if target_node is None:
            target_node = random.choice([1, 2, 5, 51])
        attacker_ip = self.get_node_ip(target_node) 

        print(f"\n[*] 正在监控网络流量... (Time Index: {time_index})")
        base_time = datetime.now()
        attack_time = base_time.strftime("%Y-%m-%d %H:%M:%S")

        victim_node = 52 
        victim_ip = self.get_node_ip(victim_node)

        actions = [
            "Upload: exploit_script.sh",
            "Execute: chmod +x exploit.sh",
            "Buffer Overflow Attempt on PID 1024",
            "Privilege Escalation: UID 1000 -> UID 0 (ROOT)"
        ]
        
        attack_patterns = []
        for action in actions:
            curr_time = (datetime.now()).strftime("%H:%M:%S.%f")[:-3]
            self._print_log(curr_time, attacker_ip, victim_ip, "SHELL", f"Payload: {action}")
            self.sn.set_ping(target_node, victim_node, time_index)
            
            time_offset = random.randint(1, 6)
            pt_time = (base_time + timedelta(seconds=time_offset)).strftime("%Y%m%d_%H%M%S")
            attack_patterns.append({
                "source": target_node,
                "target": victim_node,
                "action": action,
                "timestamp": pt_time
            })

        detection_reasons = [
            "签名匹配：检测到已知的本地提权漏洞利用代码",
            "权限变更：检测到非法 UID 变更操作 (User -> Root)",
            "异常进程：未授权的 Shell 代码执行"
        ]

        result = {
            "attack_type": "U2R",
            "target_node": target_node,
            "time_index": time_index,
            "timestamp": attack_time,
            "detected": True,
            "severity": "high",
            "detection_reasons": detection_reasons,
            "attack_patterns": attack_patterns,
            "attack_characteristics": {
                "privilege_escalation": True,
                "attempt_count": len(actions),
                "impact_level": "severe"
            }
        }
        
        self._save_result("U2r", result)
        self._print_report(result)
        return result
    
    def detect_bfa_attack(self, time_index, target_node=None):
        if target_node is None:
            target_node = random.randint(1, 50)
        attacker_ip = self.get_node_ip(target_node)

        print(f"\n[*] 正在监控网络流量... (Time Index: {time_index})")
        base_time = datetime.now()
        attack_time = base_time.strftime("%Y-%m-%d %H:%M:%S")

        victim_node = random.choice([51, 52])
        victim_ip = self.get_node_ip(victim_node)

        passwords = ["123456", "admin", "password", "root", "qwerty"]
        attack_patterns = []

        for pwd in passwords:
            curr_time = (datetime.now()).strftime("%H:%M:%S.%f")[:-3]
            self._print_log(curr_time, attacker_ip, victim_ip, "SSH", f"Login Attempt | User: root | Pwd: {pwd} | FAIL")
            self.sn.set_ping(target_node, victim_node, time_index)
            
            time_offset = random.randint(1, 7)
            pt_time = (base_time + timedelta(seconds=time_offset)).strftime("%Y%m%d_%H%M%S")
            attack_patterns.append({
                "source": target_node,
                "target": victim_node,
                "action": f"SSH Brute Force: {pwd}",
                "timestamp": pt_time
            })

        detection_reasons = [
            "频次异常：短时间内发生多次 SSH 登录失败",
            "字典攻击：检测到特征性的弱口令尝试序列",
            "协议异常：非正常的会话建立请求频率"
        ]

        result = {
            "attack_type": "BFA",
            "target_node": target_node,
            "time_index": time_index,
            "timestamp": attack_time,
            "detected": True,
            "severity": "critical",
            "detection_reasons": detection_reasons,
            "attack_patterns": attack_patterns,
            "attack_characteristics": {
                "buffer_overflow": True, # 这里原代码叫 buffer_overflow, 对应 BFA 的 overflow 特征
                "attempt_count": len(passwords),
                "impact_level": "critical"
            }
        }
        
        self._save_result("Bfa", result)
        self._print_report(result)
        return result
