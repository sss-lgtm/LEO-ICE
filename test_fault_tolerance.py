#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
StarryNet 容错能力仿真测试 (WDA)
场景：50节点，10%节点失效，20%节点恶意，验证共识能否达成
"""

from starrynet.sn_synchronizer import StarryNet
from starrynet.sn_fault_tolerance import FaultTolerance

if __name__ == "__main__":
    # 配置参数
    configuration_file_path = "./config.json"
    GS_lat_long = [[50.110924, 8.682127], [46.635700, 14.311817]]
    hello_interval = 1
    AS = [[1, 52]]
    
    print('='*60)
    print('Starting StarryNet Fault Tolerance Simulation (WDA)')
    print('Target: 30% Adversary (10% Fail + 20% Malicious)')
    print('='*60)
    
    # 1. 初始化系统
    sn = StarryNet(configuration_file_path, GS_lat_long, hello_interval, AS)
    #sn.create_nodes()
    #sn.create_links()
    #sn.run_routing_deamon()
    
    # 2. 执行容错仿真
    ft_module = FaultTolerance(sn)
    ft_module.run_simulation()
    
    # 3. 结束
    #sn.stop_emulation()
    print('\nFault tolerance simulation completed successfully!')
