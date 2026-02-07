# -*- coding: utf-8 -*-
"""
测试节点命令调用 - 用于调用节点的网络命令接口
"""

import sys
import os
import json
import ssl
import grpc
import time
import base64
import binascii
from asn1crypto import keys, pem, x509

# 引入加密相关库
from gmssl import sm2, func

# 添加项目根目录到搜索路径
sys.path.insert(0, os.path.abspath('./raychain-sdk-python'))

from raychain.sdk.grpc.grpc_client import GrpcClient
from raychain.sdk.grpc.generated.node import service_for_sdk_admin_pb2 as admin_pb2

# 导入sn_client中的签名工具函数
from sn_client import load_sm2_private_key_hex, sm2_sign_data


# ================= 命令相关工具 =================

class CmdType:
    """命令类型枚举"""
    NETWORK = ("network", "网络")
    
    @classmethod
    def get_code(cls, cmd_type):
        """获取命令类型代码"""
        for attr_name in dir(cls):
            if not attr_name.startswith('_'):
                attr_value = getattr(cls, attr_name)
                if isinstance(attr_value, tuple) and attr_value[0] == cmd_type:
                    return attr_value[0]
        return None


class CmdOperateType:
    """命令操作类型枚举"""
    READ = ("read", "读取")
    WRITE = ("write", "写入")
    START = ("start", "启动网络")
    STOP = ("stop", "关闭网络") 
    @classmethod
    def get_code(cls, operate_type):
        """获取操作类型代码"""
        for attr_name in dir(cls):
            if not attr_name.startswith('_'):
                attr_value = getattr(cls, attr_name)
                if isinstance(attr_value, tuple) and attr_value[0] == operate_type:
                    return attr_value[0]
        return None


class BaseCommand:
    """基础命令类，模拟Java中的BaseCommand"""
    
    def __init__(self):
        self.cmdOperateType = None
        self.cmdType = None
        self.payload = None
    
    def to_dict(self):
        """转换为字典"""
        return {
            "cmdOperateType": self.cmdOperateType,
            "cmdType": self.cmdType,
            "payload": self.payload
        }


# ================= 核心客户端类 =================

class NodeCommandClient:
    """
    节点命令客户端，用于调用节点的命令接口
    """

    def __init__(self, host, port, app_id="node_62WvJxio7o7p", sign_key_path=None):
        """
        初始化NodeCommandClient

        Args:
            host (str): 节点主机地址
            port (int): 节点端口
            app_id (str): 应用ID，默认为zero_node
            sign_key_path (str): 签名密钥文件路径，默认使用org-1目录下的sign_private_key.key
        """
        self.host = host
        self.port = port
        self.app_id = app_id
        
        # 如果没有指定签名密钥路径，使用默认路径
        if sign_key_path is None:
            # 尝试从多个位置查找密钥文件
            base_dir = os.path.dirname(os.path.abspath(__file__))
            # 先尝试使用sn_chain_client.py中使用的密钥文件
            key_file_name = "sm2_private_7bff4c20c76e0a74be3fbdec6cde8dc0364339961.key"
            self.sign_key_path = os.path.join(base_dir, key_file_name)
            
            # 如果上述文件不存在，使用org-1目录下的sign_private_key.key
            if not os.path.exists(self.sign_key_path):
                self.sign_key_path = '/data/chain-net/node_62WvJxio7o7p/node/data/cert/node_62WvJxio7o7p/4d3fbd7679754966b0e6f5b020c08497/sign_private_key.key'
        else:
            self.sign_key_path = sign_key_path
        
        # 验证签名密钥文件是否存在
        if not os.path.exists(self.sign_key_path):
            raise FileNotFoundError(f"签名密钥文件不存在: {self.sign_key_path}")
        
        print(f"[NodeCommandClient] 使用签名密钥文件: {self.sign_key_path}")
        
        # 构建基础SDK配置
        self.base_sdk_properties = {
            "channels": {
                "channel": [
                    {
                        "name": "channel_identifier",
                        "grpcTimeOut": 5000
                    }
                ]
            },
            "app": {
                "appId": "app_id"
            },
            "cryptology": {
                "signatureAlgorithm": "SM2withSM3"
            }
        }
        
        # 创建SSL安全配置
        self.ssl_config = self._create_ssl_secure_config(host, port)
        
        # 构建完整的SDK配置
        self.sdk_properties = self.base_sdk_properties.copy()
        self.sdk_properties["ssl"] = self.ssl_config
        
        # 创建gRPC客户端
        print(f"[NodeCommandClient] 正在创建gRPC客户端...")
        self.grpc_client = GrpcClient(
            host=host,
            port=port,
            node_type="CONSENSUS",
            channel_identifier="1330c9aaec6a40fca235c660aded8b46",
            sdk_properties=self.sdk_properties
        )
        print(f"[NodeCommandClient] gRPC客户端初始化完成")

    def _create_ssl_secure_config(self, host, port):
        """
        创建SSL安全连接配置，使用自动获取的服务器证书

        Args:
            host (str): 主机地址
            port (int): 端口号

        Returns:
            dict: SSL配置字典
        """
        ssl_config = {
            "enabled": True,
            "sslMutual": False,
            "disableHostnameVerification": True  # 必须设置为True，否则会验证主机名
        }

        # 导入sn_client中的get_server_certificate_and_cn函数
        from sn_client import get_server_certificate_and_cn
        
        # 自动获取服务器证书
        server_cert_bytes, server_cn = get_server_certificate_and_cn(host, port)
        if server_cert_bytes:
            # 保存服务器证书到临时文件
            temp_cert_path = os.path.join(os.path.dirname(__file__), 'temp_server_cert.crt')
            with open(temp_cert_path, 'wb') as f:
                f.write(server_cert_bytes)
            
            ssl_config["sslTrustCertFilePath"] = temp_cert_path
            ssl_config["sslTargetNameOverride"] = server_cn  # 使用解析出的common_name作为sslTargetNameOverride
            print(f"[SSL Config] 使用服务器证书: {temp_cert_path}")
            print(f"[SSL Config] 覆盖SSL目标名称为: {server_cn}")
        else:
            print(f"[警告] 无法获取服务器证书，使用默认配置")
            # 即使无法获取证书，也设置sslTargetNameOverride为主机名
            ssl_config["sslTargetNameOverride"] = host

        # 使用宽松模式，不验证主机名（适合测试环境）
        print(f"[SSL Config] SSL验证模式: 使用服务器证书验证，禁用主机名验证")

        return ssl_config

    def execute_network_command(self):
        """
        执行网络命令

        Returns:
            dict: 命令执行结果，包含code、message、payload、txHash等字段
        """
        try:
            # 创建基础命令对象
            base_command = BaseCommand()
            base_command.cmdOperateType = CmdOperateType.get_code("read")
            base_command.cmdType = CmdType.get_code("network")
            base_command.payload = "none"
            
            # 转换为JSON字符串
            payload = json.dumps(base_command.to_dict(), ensure_ascii=False)
            print(f"[NodeCommandClient] 命令payload: {payload}")
            
            # 对payload进行签名
            private_key_hex = load_sm2_private_key_hex(self.sign_key_path)
            print(f"[NodeCommandClient] 正在对payload进行签名...")
            signature = sm2_sign_data(private_key_hex, payload)
            
            # 构建CommandRequest
            command_request = admin_pb2.CommandRequest(
                app_id="node_62WvJxio7o7p",
                cmd=CmdType.get_code("network"),
                payload=payload,
                sign=signature
            )
            
            # 执行命令
            print(f"[NodeCommandClient] 正在执行网络命令...")
            reply = self.grpc_client.command(command_request)
            
            # 构建返回结果
            result = {
                "code": reply.code,
                "message": reply.message,
                "payload": reply.payload,
                "txHash": reply.txHash,
                "success": reply.code == 200 or reply.message == "SUCCESS"
            }
            
            print(f"[NodeCommandClient] 命令执行成功!")
            print(f"  响应状态码: {reply.code}")
            print(f"  响应消息: {reply.message}")
            if reply.payload:
                print(f"  返回数据: {reply.payload}")
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[NodeCommandClient] 命令执行失败: {e}")
            return {
                "code": -1,
                "message": str(e),
                "payload": "",
                "txHash": "",
                "success": False
            }

    def shutdown(self):
        """
        关闭gRPC连接
        """
        if hasattr(self, 'grpc_client'):
            self.grpc_client.shutdown()
            print(f"[NodeCommandClient] 连接已关闭")


# ================= 便捷函数 =================

def create_node_command_client_from_config(config_path='chain-net/cfg/chain-net-config.json'):
    """
    从配置文件创建NodeCommandClient实例

    Args:
        config_path (str): 配置文件路径

    Returns:
        NodeCommandClient: NodeCommandClient实例
    """
    # 导入sn_client中的load_chain_net_config函数
    from sn_client import load_chain_net_config
    
    # 加载配置文件
    config = load_chain_net_config(config_path)
    
    # 获取节点信息
    node_info = config['nodeInfo']
    business_rpc_network = node_info['network']['businessRpcNetwork']
    internal_network = business_rpc_network['internal']
    
    # 获取通道标识符
    channel_identifier = config['rootChain']['channelIdentifier']
    
    # 创建NodeCommandClient实例
    client = NodeCommandClient(
        host=internal_network['ip'],
        port=int(internal_network['port'])
    )
    
    print(f"[NodeCommandClient] 从配置文件创建客户端成功:")
    print(f"  节点信息: {node_info['nodeName']} ({node_info['nodeIdentifier']})")
    print(f"  连接地址: {internal_network['ip']}:{internal_network['port']}")
    print(f"  通道标识符: {channel_identifier}")
    
    return client


# ================= 示例用法 =================

if __name__ == "__main__":
    """
    示例用法：从配置文件创建客户端并执行网络命令
    """
    try:
        # 从配置文件创建客户端
        client = create_node_command_client_from_config()
        
        # 执行网络命令
        result = client.execute_network_command()
        
        # 打印结果
        print("\n" + "=" * 80)
        print("=== 命令执行结果 ===")
        print(f"状态码: {result['code']}")
        print(f"消息: {result['message']}")
        print(f"成功: {result['success']}")
        if result['payload']:
            print(f"返回数据: {result['payload']}")
        print("=" * 80)
        
    except Exception as e:
        print(f"[错误] 执行失败: {e}")
    finally:
        # 关闭连接
        if 'client' in locals():
            client.shutdown()
