#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
StarryNet 恶意攻击检测测试
支持 DoS、DDoS、Probe、U2R、BFA 等攻击检测
"""

import time
from starrynet.sn_synchronizer import StarryNet
from starrynet.sn_attack_detection import AttackDetection

if __name__ == "__main__":
    # 配置参数
    configuration_file_path = "./config.json"
    
    # 51 和 52 是地面站坐标
    GS_lat_long = [[50.110924, 8.682127], [46.635700, 14.311817]]
    
    hello_interval = 1
    # AS列表：节点 ID 范围从 1 到 52
    # 1-50: 卫星 (Satellite)
    # 51-52: 地面站 (Ground Station)
    AS = [[1, 52]]
    
    print('='*70)
    print('Starting StarryNet Attack Detection System Simulation')
    print('Target Topology: 50 Satellites + 2 Ground Stations (Node 51, 52)')
    print('='*70)
    
    # 初始化系统
    sn = StarryNet(configuration_file_path, GS_lat_long, hello_interval, AS)
    #sn.create_nodes()
    #sn.create_links()
    #sn.run_routing_deamon()
    
    # 初始化测试模块
    attack_detector = AttackDetection(sn)
    
    # 模拟攻击场景
    # 场景1: DoS 攻击 (普通卫星互攻)
    time.sleep(3)
    attack_detector.detect_dos_attack(5)
    
    # 场景2: DDoS 攻击 (僵尸卫星围攻地面站 51/52)
    time.sleep(14)
    # 传入 target_node=51 强制演示攻击地面站
    attack_detector.detect_ddos_attack(6, target_node=51)
    
    # 场景3: Probe (扫描)
    time.sleep(5)
    attack_detector.detect_probe_attack(7)
    
    # 场景4: U2R (提权)
    time.sleep(8)
    attack_detector.detect_u2r_attack(8)
    
    # 场景5: BFA (暴力破解地面站)
    time.sleep(20)
    attack_detector.detect_bfa_attack(9, target_node=10) # 假设节点10尝试破解
    
    # 停止仿真
    print('='*70)
    #sn.stop_emulation()
    print('Attack detection simulation completed.')
    print('='*70)
