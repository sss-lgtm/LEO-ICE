# -*- coding: utf-8 -*-
"""
区块链模块测试文件 - 用于测试 BlockchainClient 和 BlockchainManager
"""

import sys
import os
import json
import time

# 添加父目录到搜索路径
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from blockchain_client import BlockchainClient
from blockchain_manager import BlockchainManager


# ================= 测试函数 =================

def test_blockchain_client(config_path='blockchain_config.json'):
    """
    测试单个 BlockchainClient 的功能

    Args:
        config_path (str): 配置文件路径
    """
    print("\n" + "=" * 80)
    print("=== 测试 BlockchainClient ===")
    print("=" * 80)

    try:
        # 加载配置文件
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        global_config = config['global']

        # 测试卫星节点（如果配置中有）
        if config.get('satellites') and len(config['satellites']) > 0:
            sat_config = config['satellites'][0]
            print(f"\n[测试] 使用卫星节点: {sat_config['node_name']}")

            # 创建客户端
            client = BlockchainClient(
                node_config=sat_config['blockchain_node'],
                global_config=global_config
            )

            print(f"[测试] 客户端创建成功")
            print(f"  节点标识: {sat_config['blockchain_node']['node_identifier']}")
            print(f"  连接地址: {sat_config['blockchain_node']['host']}:{sat_config['blockchain_node']['port']}")

            # 测试连接
            print(f"\n[测试] 正在建立连接...")
            if client.connect():
                print(f"[测试] ✓ 连接成功")
            else:
                print(f"[测试] ✗ 连接失败")
                return

            # 测试 network start 命令
            print(f"\n[测试] 正在执行 network start 命令...")
            result = client.start_network()
            print(f"[测试] 命令执行结果:")
            print(f"  状态码: {result['code']}")
            print(f"  消息: {result['message']}")
            print(f"  成功: {result['success']}")
            if result['payload']:
                print(f"  返回数据: {result['payload']}")

            # 等待一段时间
            print(f"\n[测试] 等待 3 秒...")
            time.sleep(3)

            # 测试 network stop 命令
            print(f"\n[测试] 正在执行 network stop 命令...")
            result = client.stop_network()
            print(f"[测试] 命令执行结果:")
            print(f"  状态码: {result['code']}")
            print(f"  消息: {result['message']}")
            print(f"  成功: {result['success']}")
            if result['payload']:
                print(f"  返回数据: {result['payload']}")

            # 关闭连接
            print(f"\n[测试] 正在关闭连接...")
            client.shutdown()
            print(f"[测试] ✓ 测试完成")

        else:
            print(f"[测试] 配置文件中没有卫星节点配置")

    except Exception as e:
        import traceback
        print(f"\n[测试] ✗ 测试失败: {e}")
        traceback.print_exc()


def test_blockchain_manager(config_path='blockchain_config.json'):
    """
    测试 BlockchainManager 的功能

    Args:
        config_path (str): 配置文件路径
    """
    print("\n" + "=" * 80)
    print("=== 测试 BlockchainManager ===")
    print("=" * 80)

    try:
        # 创建 BlockchainManager
        print(f"\n[测试] 正在初始化 BlockchainManager...")
        manager = BlockchainManager(config_path)
        print(f"[测试] ✓ BlockchainManager 初始化成功")

        # 加载配置以获取节点信息
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # 测试卫星连接到地面站
        if config.get('satellites') and config.get('ground_stations'):
            sat_id = config['satellites'][0]['sat_id']
            gs_id = config['ground_stations'][0]['gs_id']

            print(f"\n[测试] 模拟卫星 {sat_id} 连接到地面站 {gs_id}...")
            success = manager.handle_satellite_connect(sat_id, gs_id)
            if success:
                print(f"[测试] ✓ 卫星连接处理成功")
            else:
                print(f"[测试] ✗ 卫星连接处理失败")

            # 检查连接状态
            status = manager.get_satellite_status(sat_id)
            print(f"[测试] 卫星 {sat_id} 连接状态: {status}")

            # 等待一段时间
            print(f"\n[测试] 等待 3 秒...")
            time.sleep(3)

            # 测试卫星断开地面站
            print(f"\n[测试] 模拟卫星 {sat_id} 断开地面站 {gs_id}...")
            success = manager.handle_satellite_disconnect(sat_id, gs_id)
            if success:
                print(f"[测试] ✓ 卫星断开处理成功")
            else:
                print(f"[测试] ✗ 卫星断开处理失败")

            # 检查连接状态
            status = manager.get_satellite_status(sat_id)
            print(f"[测试] 卫星 {sat_id} 连接状态: {status}")

        else:
            print(f"[测试] 配置文件中缺少卫星或地面站配置")

        # 关闭所有连接
        print(f"\n[测试] 正在关闭所有连接...")
        manager.shutdown_all()
        print(f"[测试] ✓ 测试完成")

    except Exception as e:
        import traceback
        print(f"\n[测试] ✗ 测试失败: {e}")
        traceback.print_exc()


# ================= 主程序 =================

if __name__ == "__main__":
    """
    主程序 - 提供多种测试选项
    """
    print("\n" + "=" * 80)
    print("=== 区块链模块测试程序 ===")
    print("=" * 80)

    # 确定配置文件路径
    config_path = os.path.join(os.path.dirname(__file__), 'blockchain_config.json')

    if not os.path.exists(config_path):
        print(f"\n[错误] 配置文件不存在: {config_path}")
        print(f"[提示] 请先配置 blockchain_config.json 文件")
        sys.exit(1)

    print(f"\n[信息] 使用配置文件: {config_path}")

    # 显示测试选项
    print(f"\n请选择测试项目:")
    print(f"  1. 测试 BlockchainClient（单个客户端）")
    print(f"  2. 测试 BlockchainManager（管理器）")
    print(f"  3. 运行所有测试")
    print(f"  0. 退出")

    try:
        choice = input(f"\n请输入选项 (0-3): ").strip()

        if choice == '1':
            test_blockchain_client(config_path)
        elif choice == '2':
            test_blockchain_manager(config_path)
        elif choice == '3':
            test_blockchain_client(config_path)
            test_blockchain_manager(config_path)
        elif choice == '0':
            print(f"\n[信息] 退出测试程序")
        else:
            print(f"\n[错误] 无效的选项: {choice}")

    except KeyboardInterrupt:
        print(f"\n\n[信息] 用户中断测试")
    except Exception as e:
        import traceback
        print(f"\n[错误] 测试过程中发生异常: {e}")
        traceback.print_exc()

    print(f"\n" + "=" * 80)
    print(f"=== 测试程序结束 ===")
    print(f"=" * 80 + "\n")
