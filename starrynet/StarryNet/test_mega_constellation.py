#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
StarryNet 巨型星座支持测试
测试支持卫星数量不低于 1000 颗的能力
"""

from starrynet.sn_synchronizer import StarryNet
from starrynet.sn_mega_constellation import MegaConstellation

if __name__ == "__main__":
    # 配置参数
    configuration_file_path = "./config.json"
    GS_lat_long = [[50.110924, 8.682127], [46.635700, 14.311817]]
    hello_interval = 1
    AS = [[1, 52]]
    
    print('Starting mega constellation tests...')
    
    # 初始化系统
    sn = StarryNet(configuration_file_path, GS_lat_long, hello_interval, AS)
    sn.create_nodes()
    sn.create_links()
    sn.run_routing_deamon()
    
    # 初始化测试模块
    mega_test = MegaConstellation(sn)
    
    # 执行测试
    print('Testing scalability with different satellite counts...')
    mega_test.test_scalability([100, 500, 1000])
    
    print('Testing network performance...')
    mega_test.test_network_performance([50, 100, 200])
    
    # 停止仿真
    sn.stop_emulation()
    print('Mega constellation tests completed successfully!')
