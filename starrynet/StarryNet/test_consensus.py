#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
StarryNet 共识算法仿真测试入口
功能：执行 WDA 共识流程，打印交互日志，并将结果上链
"""

from starrynet.sn_synchronizer import StarryNet
from starrynet.sn_consensus import ConsensusAlgorithm
import time

if __name__ == "__main__":
    # 配置参数
    configuration_file_path = "./config.json"
    
    # 51 和 52 为地面站
    GS_lat_long = [[50.110924, 8.682127], [46.635700, 14.311817]]
    hello_interval = 1
    AS = [[1, 52]]
    
    print('='*60)
    print('Starting StarryNet Consensus Simulation with Blockchain Integration')
    print('='*60)
    
    # 1. 初始化网络拓扑
    print("[Init] Initializing satellite network topology...")
    sn = StarryNet(configuration_file_path, GS_lat_long, hello_interval, AS)
    #sn.create_nodes()
    #sn.create_links()
    #sn.run_routing_deamon()
    
    # 2. 初始化共识模块
    consensus_module = ConsensusAlgorithm(sn)
    
    # 3. 执行单次共识仿真
    # 传入 time_index = 10 (模拟的时间切片)
    print('\n[Action] Executing WDA Consensus Protocol...')
    consensus_module.compare_algorithms(10)
    
    # 4. 结束
    print('\n[System] Stopping emulation...')
    #sn.stop_emulation()
    print('Consensus simulation completed successfully!')
