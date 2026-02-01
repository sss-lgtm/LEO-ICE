# -*- coding: utf-8 -*-
"""
区块链管理器 - 管理卫星和地面站的区块链节点连接和状态
"""

import os
import json
from typing import Dict, Optional

from .blockchain_client import BlockchainClient


class BlockchainManager:
    """
    区块链管理器类 - 负责管理所有节点的区块链客户端和连接状态
    """

    def __init__(self, config_path=None):
        """
        初始化区块链管理器

        Args:
            config_path (str): 配置文件路径，默认为 blockchain/blockchain_config.json
        """
        # 确定配置文件路径
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__),
                'blockchain_config.json'
            )

        self.config_path = config_path
        self.config = self._load_config()

        # 全局配置
        self.global_config = self.config.get('global', {})

        # 客户端实例缓存
        self.satellite_clients: Dict[int, BlockchainClient] = {}
        self.ground_station_clients: Dict[int, BlockchainClient] = {}

        # 卫星连接状态跟踪 {sat_id: is_connected}
        self.satellite_connection_status: Dict[int, bool] = {}

        # 初始化客户端
        self._initialize_clients()

        print(f"[BlockchainManager] 初始化完成")
        print(f"  - 地面站节点数: {len(self.ground_station_clients)}")
        print(f"  - 卫星节点数: {len(self.satellite_clients)}")

    def _load_config(self):
        """
        加载配置文件

        Returns:
            dict: 配置字典
        """
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        return config

    def _initialize_clients(self):
        """
        初始化所有区块链客户端实例
        """
        # 初始化地面站客户端
        for gs_config in self.config.get('ground_stations', []):
            gs_id = gs_config['gs_id']
            try:
                client = BlockchainClient(
                    node_config=gs_config['blockchain_node'],
                    global_config=self.global_config
                )
                self.ground_station_clients[gs_id] = client
                print(f"[BlockchainManager] 地面站 {gs_id} 客户端已创建")
            except Exception as e:
                print(f"[BlockchainManager] 地面站 {gs_id} 客户端创建失败: {e}")

        # 初始化卫星客户端
        for sat_config in self.config.get('satellites', []):
            sat_id = sat_config['sat_id']
            try:
                client = BlockchainClient(
                    node_config=sat_config['blockchain_node'],
                    global_config=self.global_config
                )
                self.satellite_clients[sat_id] = client
                self.satellite_connection_status[sat_id] = False
                print(f"[BlockchainManager] 卫星 {sat_id} 客户端已创建")
            except Exception as e:
                print(f"[BlockchainManager] 卫星 {sat_id} 客户端创建失败: {e}")

    def handle_satellite_connect(self, sat_id, gs_id):
        """
        处理卫星连接到地面站的事件

        Args:
            sat_id (int): 卫星节点 ID
            gs_id (int): 地面站节点 ID

        Returns:
            bool: 是否成功执行命令
        """
        # 检查卫星是否已经连接
        if self.satellite_connection_status.get(sat_id, False):
            print(f"[BlockchainManager] 卫星 {sat_id} 已经处于连接状态，跳过")
            return True

        # 获取卫星客户端
        client = self.satellite_clients.get(sat_id)
        if not client:
            print(f"[BlockchainManager] 警告: 卫星 {sat_id} 没有配置区块链客户端")
            return False

        try:
            print(f"[BlockchainManager] 卫星 {sat_id} 连接到地面站 {gs_id}，执行 network start")

            # 执行 network start 命令
            result = client.start_network()

            if result['success']:
                # 更新连接状态
                self.satellite_connection_status[sat_id] = True
                print(f"[BlockchainManager] 卫星 {sat_id} 网络启动成功")
                return True
            else:
                print(f"[BlockchainManager] 卫星 {sat_id} 网络启动失败: {result['message']}")
                return False

        except Exception as e:
            print(f"[BlockchainManager] 卫星 {sat_id} 网络启动异常: {e}")
            return False

    def handle_satellite_disconnect(self, sat_id, gs_id):
        """
        处理卫星断开地面站连接的事件

        Args:
            sat_id (int): 卫星节点 ID
            gs_id (int): 地面站节点 ID

        Returns:
            bool: 是否成功执行命令
        """
        # 检查卫星是否已经断开
        if not self.satellite_connection_status.get(sat_id, False):
            print(f"[BlockchainManager] 卫星 {sat_id} 已经处于断开状态，跳过")
            return True

        # 获取卫星客户端
        client = self.satellite_clients.get(sat_id)
        if not client:
            print(f"[BlockchainManager] 警告: 卫星 {sat_id} 没有配置区块链客户端")
            return False

        try:
            print(f"[BlockchainManager] 卫星 {sat_id} 断开地面站 {gs_id}，执行 network stop")

            # 执行 network stop 命令
            result = client.stop_network()

            if result['success']:
                # 更新连接状态
                self.satellite_connection_status[sat_id] = False
                print(f"[BlockchainManager] 卫星 {sat_id} 网络停止成功")
                return True
            else:
                print(f"[BlockchainManager] 卫星 {sat_id} 网络停止失败: {result['message']}")
                return False

        except Exception as e:
            print(f"[BlockchainManager] 卫星 {sat_id} 网络停止异常: {e}")
            return False

    def get_satellite_status(self, sat_id):
        """
        获取卫星的连接状态

        Args:
            sat_id (int): 卫星节点 ID

        Returns:
            bool: 是否已连接
        """
        return self.satellite_connection_status.get(sat_id, False)

    def shutdown_all(self):
        """
        关闭所有区块链客户端连接
        """
        print("[BlockchainManager] 正在关闭所有区块链连接...")

        # 关闭所有卫星客户端
        for sat_id, client in self.satellite_clients.items():
            try:
                client.shutdown()
            except Exception as e:
                print(f"[BlockchainManager] 关闭卫星 {sat_id} 连接时出错: {e}")

        # 关闭所有地面站客户端
        for gs_id, client in self.ground_station_clients.items():
            try:
                client.shutdown()
            except Exception as e:
                print(f"[BlockchainManager] 关闭地面站 {gs_id} 连接时出错: {e}")

        print("[BlockchainManager] 所有连接已关闭")

    def __del__(self):
        """析构函数，确保所有连接被关闭"""
        self.shutdown_all()
