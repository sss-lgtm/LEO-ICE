# -*- coding: utf-8 -*-
"""
区块链客户端封装类 - 用于执行区块链网络命令
"""

import sys
import os
import json
import grpc
import time

# 添加父目录到搜索路径，以便导入 sn_client 和 test_node_command
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)
sys.path.insert(0, os.path.join(parent_dir, 'raychain-sdk-python'))

from raychain.sdk.grpc.grpc_client import GrpcClient
from raychain.sdk.grpc.generated.node import service_for_sdk_admin_pb2 as admin_pb2

# 导入 sn_client 中的工具函数和类
from sn_client import (
    SM2_KEY_UTILS,
    load_sm2_private_key_hex,
    sm2_sign_data,
    get_server_certificate_and_cn,
    create_ssl_secure_config
)


class CmdType:
    """命令类型枚举"""
    NETWORK = "network"


class CmdOperateType:
    """命令操作类型枚举"""
    START = "start"
    STOP = "stop"


class BaseCommand:
    """基础命令类"""

    def __init__(self, cmd_type, cmd_operate_type, payload="none"):
        self.cmdType = cmd_type
        self.cmdOperateType = cmd_operate_type
        self.payload = payload

    def to_dict(self):
        """转换为字典"""
        return {
            "cmdType": self.cmdType,
            "cmdOperateType": self.cmdOperateType,
            "payload": self.payload
        }


class BlockchainClient:
    """
    区块链客户端类 - 封装区块链节点的网络命令调用
    """

    def __init__(self, node_config, global_config):
        """
        初始化区块链客户端

        Args:
            node_config (dict): 节点配置，包含 host, port, sign_key_path 等
            global_config (dict): 全局配置，包含 channel_identifier, app_id 等
        """
        self.node_config = node_config
        self.global_config = global_config

        # 提取配置参数
        self.host = node_config.get('host')
        self.port = node_config.get('port')
        self.node_identifier = node_config.get('node_identifier')
        self.channel_identifier = node_config.get('channel_identifier')
        self.sign_key_path = node_config.get('sign_key_path')

        self.app_id = global_config.get('app_id', 'zero_node')

        # 验证必要参数
        if not all([self.host, self.port, self.channel_identifier, self.sign_key_path]):
            raise ValueError("缺少必要的节点配置参数")

        # 处理签名密钥文件路径（转换为绝对路径）
        self.sign_key_path = self._resolve_path(self.sign_key_path)

        # 验证签名密钥文件
        if not os.path.exists(self.sign_key_path):
            raise FileNotFoundError(f"签名密钥文件不存在: {self.sign_key_path}")

        # gRPC 客户端（延迟初始化）
        self.grpc_client = None
        self.connected = False

    def _resolve_path(self, path):
        """
        解析路径，将相对路径转换为绝对路径

        Args:
            path (str): 原始路径

        Returns:
            str: 绝对路径
        """
        # 如果已经是绝对路径，直接返回
        if os.path.isabs(path):
            return path

        # 获取 starrynet 目录的绝对路径
        # blockchain_client.py 在 starrynet/blockchain/ 目录下
        # 所以 starrynet 目录是父目录的父目录
        starrynet_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 将相对路径转换为相对于 starrynet 目录的绝对路径
        abs_path = os.path.join(starrynet_dir, path)

        return abs_path


    def connect(self):
        """
        建立 gRPC 连接

        Returns:
            bool: 连接是否成功
        """
        if self.connected:
            return True

        try:
            # 使用 sn_client.py 中的 SSL 配置函数
            ssl_config = create_ssl_secure_config(self.host, self.port)

            # 构建 SDK 配置
            sdk_properties = {
                "channels": {
                    "channel": [
                        {
                            "name": self.channel_identifier,
                            "grpcTimeOut": self.global_config.get('grpc_timeout', 5000)
                        }
                    ]
                },
                "app": {
                    "appId": self.app_id
                },
                "cryptology": {
                    "signatureAlgorithm": self.global_config.get(
                        'signature_algorithm', 'SM2withSM3'
                    )
                },
                "ssl": ssl_config
            }

            # 创建 gRPC 客户端
            self.grpc_client = GrpcClient(
                host=self.host,
                port=self.port,
                node_type="CONSENSUS",
                channel_identifier=self.channel_identifier,
                sdk_properties=sdk_properties
            )

            self.connected = True
            print(f"[BlockchainClient] 成功连接到节点: {self.node_identifier} ({self.host}:{self.port})")
            return True

        except Exception as e:
            print(f"[BlockchainClient] 连接失败: {e}")
            self.connected = False
            return False

    def execute_network_command(self, operation):
        """
        执行网络命令（start 或 stop）

        Args:
            operation (str): 操作类型，"start" 或 "stop"

        Returns:
            dict: 命令执行结果
        """
        # 确保已连接
        if not self.connected:
            if not self.connect():
                return {
                    "success": False,
                    "message": "未连接到区块链节点",
                    "code": -1
                }

        try:
            # 创建命令对象
            base_command = BaseCommand(
                cmd_type=CmdType.NETWORK,
                cmd_operate_type=operation,
                payload="none"
            )

            # 转换为 JSON
            payload = json.dumps(base_command.to_dict(), ensure_ascii=False)

            # 对 payload 进行签名
            private_key_hex = load_sm2_private_key_hex(self.sign_key_path)
            signature = sm2_sign_data(private_key_hex, payload)

            # 构建 CommandRequest
            command_request = admin_pb2.CommandRequest(
                app_id=self.app_id,
                cmd=CmdType.NETWORK,
                payload=payload,
                sign=signature
            )

            # 执行命令
            reply = self.grpc_client.command(command_request)

            # 构建返回结果
            result = {
                "code": reply.code,
                "message": reply.message,
                "payload": reply.payload,
                "txHash": reply.txHash,
                "success": reply.code == 200 or reply.message == "SUCCESS"
            }

            return result

        except Exception as e:
            print(f"[BlockchainClient] 命令执行失败: {e}")
            return {
                "code": -1,
                "message": str(e),
                "payload": "",
                "txHash": "",
                "success": False
            }

    def start_network(self):
        """
        启动网络

        Returns:
            dict: 命令执行结果
        """
        print(f"[BlockchainClient] 节点 {self.node_identifier} 执行 network start")
        return self.execute_network_command(CmdOperateType.START)

    def stop_network(self):
        """
        停止网络

        Returns:
            dict: 命令执行结果
        """
        print(f"[BlockchainClient] 节点 {self.node_identifier} 执行 network stop")
        return self.execute_network_command(CmdOperateType.STOP)

    def shutdown(self):
        """
        关闭 gRPC 连接
        """
        if self.grpc_client and self.connected:
            try:
                self.grpc_client.shutdown()
                self.connected = False
                print(f"[BlockchainClient] 节点 {self.node_identifier} 连接已关闭")
            except Exception as e:
                print(f"[BlockchainClient] 关闭连接时出错: {e}")

    def __del__(self):
        """析构函数，确保连接被关闭"""
        self.shutdown()

