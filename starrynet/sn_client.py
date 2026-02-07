# -*- coding: utf-8 -*-
"""
SN Client - 用于与区块链节点建立SSL安全连接并执行合约调用
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
from raychain.sdk.data.data_models import ContractID


# ================= SM2 公钥推导工具 (核心补丁) =================
class SM2_KEY_UTILS:
    """
    用于从私钥推导公钥，确保 gmssl 能正确计算 Z 值
    """
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

    @staticmethod
    def _inv(a, n):
        return pow(a, n - 2, n)

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
            if k % 2 == 1:
                res = SM2_KEY_UTILS._add(res, p)
            p = SM2_KEY_UTILS._double(p)
            k //= 2
        return res

    @staticmethod
    def get_public_key_hex(private_key_hex):
        """
        从私钥推导公钥
        """
        d = int(private_key_hex, 16)
        G = (SM2_KEY_UTILS.Gx, SM2_KEY_UTILS.Gy)
        P = SM2_KEY_UTILS._multiply(d, G)
        x_hex = hex(P[0])[2:].zfill(64)
        y_hex = hex(P[1])[2:].zfill(64)
        return x_hex + y_hex


# ================= 证书与密钥加载工具 =================

def get_server_certificate_and_cn(host, port):
    """
    自动获取服务器证书并解析Common Name

    Args:
        host (str): 主机地址
        port (int): 端口号

    Returns:
        tuple: (证书字节数据, 通用名称)
    """
    print(f"[Auto-Fetch] 正在从 {host}:{port} 获取证书...")
    try:
        # 获取服务器证书
        cert_pem = ssl.get_server_certificate((host, port))
        cert_bytes = cert_pem.encode('utf-8')

        # 解析证书
        if pem.detect(cert_bytes):
            _, _, der_bytes = pem.unarmor(cert_bytes)
        else:
            der_bytes = cert_bytes

        cert_obj = x509.Certificate.load(der_bytes)
        subject = cert_obj['tbs_certificate']['subject'].native
        common_name = subject.get('common_name')

        if not common_name:
            print(f"[Auto-Fetch] 警告: 未找到Common Name，使用主机名 {host} 作为默认值")
            common_name = host

        print(f"[Auto-Fetch] 解析到CN: {common_name}")
        return cert_bytes, common_name
    except Exception as e:
        print(f"[Auto-Fetch 错误] 获取证书失败: {e}")
        return None, None


def load_sm2_private_key_hex(key_path):
    """
    加载SM2私钥并转换为十六进制格式

    Args:
        key_path (str): 私钥文件路径

    Returns:
        str: 十六进制格式的私钥
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"密钥文件未找到: {key_path}")
    with open(key_path, 'rb') as f:
        key_bytes = f.read()
    if pem.detect(key_bytes):
        _, _, der_bytes = pem.unarmor(key_bytes)
    else:
        der_bytes = key_bytes
    key_info = keys.PrivateKeyInfo.load(der_bytes)
    raw = key_info['private_key'].native
    priv_bytes = None
    if isinstance(raw, (dict, object)) and hasattr(raw, 'get'):
        priv_bytes = raw['private_key']
    elif isinstance(raw, bytes):
        ec_key = keys.ECPrivateKey.load(raw)
        priv_bytes = ec_key['private_key'].native
    if isinstance(priv_bytes, int):
        return hex(priv_bytes)[2:].zfill(64)
    return priv_bytes.hex()


def sm2_sign_data(private_key_hex, data_str):
    """
    使用SM2算法对数据进行签名

    Args:
        private_key_hex (str): 十六进制格式的私钥
        data_str (str): 要签名的数据

    Returns:
        str: Base64编码的签名结果
    """
    # 1. 必须推导公钥！gmssl 需要它来计算 Z 值
    public_key_hex = SM2_KEY_UTILS.get_public_key_hex(private_key_hex)

    # 2. 初始化 CryptSM2 时传入 public_key
    sm2_crypt = sm2.CryptSM2(public_key=public_key_hex, private_key=private_key_hex)

    data_bytes = data_str.encode('utf-8')
    signature_hex = sm2_crypt.sign_with_sm3(data_bytes)

    # 3. 如果结果已是 DER 编码 (长度 > 130)，直接 Base64
    if len(signature_hex) > 130:
        return base64.b64encode(binascii.unhexlify(signature_hex)).decode('utf-8')

    # 4. 手动 DER 编码 (r, s)
    len_hex = len(signature_hex)
    r_hex = signature_hex[0:len_hex // 2]
    s_hex = signature_hex[len_hex // 2:]
    r_int = int(r_hex, 16)
    s_int = int(s_hex, 16)

    def encode_int(num):
        h = hex(num)[2:]
        if len(h) % 2 != 0: h = '0' + h
        b = binascii.unhexlify(h)
        if b[0] & 0x80: b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b

    content = encode_int(r_int) + encode_int(s_int)
    der_seq = b'\x30' + bytes([len(content)]) + content
    return base64.b64encode(der_seq).decode('utf-8')


# ================= SSL 配置工具 =================

def create_ssl_secure_config(host, port):
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


# ================= 配置加载工具 =================

def load_chain_net_config(config_path='chain-net/cfg/chain-net-config.json'):
    """
    加载chain-net-config.json配置文件

    Args:
        config_path (str): 配置文件路径

    Returns:
        dict: 配置字典
    """
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config


# ================= 核心客户端类 =================

class SNClient:
    """
    SN Client 类，用于与区块链节点建立SSL安全连接并执行合约调用
    """

    def __init__(self, host, port, channel_identifier, sign_key_path=None):
        """
        初始化SNClient

        Args:
            host (str): 节点主机地址
            port (int): 节点端口
            channel_identifier (str): 通道标识符
            sign_key_path (str): 签名密钥文件路径，默认使用org-1目录下的sign_private_key.key
        """
        self.host = host
        self.port = port
        self.channel_identifier = channel_identifier
        
        # 如果没有指定签名密钥路径，使用默认路径
        if sign_key_path is None:
            self.sign_key_path = 'chain-net/data/cert/org-1/30199da1daa94f1bb201821dae4d7d4b/sign_private_key.key'
        else:
            self.sign_key_path = sign_key_path
        
        # 验证签名密钥文件是否存在
        if not os.path.exists(self.sign_key_path):
            raise FileNotFoundError(f"签名密钥文件不存在: {self.sign_key_path}")
        
        # 构建基础SDK配置
        self.base_sdk_properties = {
            "channels": {
                "channel": [
                    {
                        "name": channel_identifier,
                        "grpcTimeOut": 5000
                    }
                ]
            },
            "app": {
                "appId": "zero_node"
            },
            "cryptology": {
                "signatureAlgorithm": "SM2withSM3"
            }
        }
        
        # 创建SSL安全配置
        self.ssl_config = create_ssl_secure_config(host, port)
        
        # 构建完整的SDK配置
        self.sdk_properties = self.base_sdk_properties.copy()
        self.sdk_properties["ssl"] = self.ssl_config
        
        # 创建gRPC客户端
        print(f"[SNClient] 正在创建gRPC客户端...")
        self.grpc_client = GrpcClient(
            host=host,
            port=port,
            node_type="CONSENSUS",
            channel_identifier=channel_identifier,
            sdk_properties=self.sdk_properties
        )
        print(f"[SNClient] gRPC客户端初始化完成")

    def invoke_system_contract(self, method="registerDid", payload=""):
        """
        执行系统合约调用

        Args:
            method (str): 合约方法名，默认为findBlockHeight
            payload (str): 方法参数，默认为空字符串

        Returns:
            dict: 调用结果，包含code、message、payload、txHash等字段
        """
        try:
            # 导入protobuf请求类
            from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2

            # 构建合约ID
            contract_id = ContractID(
                identity="test1",
                name="test1",
                version="1.3.5",
                language_type="2",
                type="2"
            )

            # 对payload进行签名
            private_key_hex = load_sm2_private_key_hex(self.sign_key_path)
            print(f"[SNClient] 正在对payload进行签名...")
            signature = sm2_sign_data(private_key_hex, payload)

            # 构建invoke请求
            proto_request = common_pb2.SdkInvokeRequest(
                contract_id=contract_id.to_proto(),
                method=method,
                payload=payload,
                channel_identifier="af65e522e1e844609c70bb847cb01775",
                app_id="zero_node",
                sign=signature
            )

            # 执行合约调用
            print(f"[SNClient] 正在执行系统合约调用: {method}")
            reply = self.grpc_client.invoke(proto_request)
            
            # 构建返回结果
            result = {
                "code": reply.code,
                "message": reply.message,
                "payload": reply.payload,
                "txHash": reply.txHash,
                "success": reply.code == 200 or reply.message == "SUCCESS"
            }
            
            print(f"[SNClient] 合约调用成功!")
            print(f"  响应状态码: {reply.code}")
            print(f"  响应消息: {reply.message}")
            if reply.txHash:
                print(f"  交易哈希: {reply.txHash}")
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[SNClient] 合约调用失败: {e}")
            return {
                "code": -1,
                "message": str(e),
                "payload": "",
                "txHash": "",
                "success": False
            }

    def invoke_user_contract(self, contract_name, method, payload):
        """
        执行用户合约调用

        Args:
            contract_name (str): 合约名称
            method (str): 合约方法名
            payload (str): 方法参数

        Returns:
            dict: 调用结果，包含code、message、payload、txHash等字段
        """
        try:
            # 导入protobuf请求类
            from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2

            # 构建合约ID
            contract_id = ContractID(
                identity=contract_name,
                name=contract_name,
                version="1.6.3",
                language_type="4",
                type="2"
            )

            # 对payload进行签名
            private_key_hex = load_sm2_private_key_hex(self.sign_key_path)
            print(f"[SNClient] 正在对payload进行签名...")
            signature = sm2_sign_data(private_key_hex, payload)

            # 构建invoke请求
            proto_request = common_pb2.SdkInvokeRequest(
                contract_id=contract_id.to_proto(),
                method=method,
                payload=payload,
                channel_identifier=self.channel_identifier,
                app_id="zero_node",
                sign=signature
            )

            # 执行合约调用
            print(f"[SNClient] 正在执行用户合约调用: {contract_name}.{method}")
            reply = self.grpc_client.invoke(proto_request)
            
            # 构建返回结果
            result = {
                "code": reply.code,
                "message": reply.message,
                "payload": reply.payload,
                "txHash": reply.txHash,
                "success": reply.code == 200 or reply.message == "SUCCESS" or reply.txHash
            }
            
            print(f"[SNClient] 合约调用完成!")
            print(f"  响应状态码: {reply.code}")
            print(f"  响应消息: {reply.message}")
            if reply.txHash:
                print(f"  交易哈希: {reply.txHash}")
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[SNClient] 合约调用失败: {e}")
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
            print(f"[SNClient] 连接已关闭")


# ================= 便捷函数 =================

def create_sn_client_from_config(config_path='chain-net/cfg/chain-net-config.json'):
    """
    从配置文件创建SNClient实例

    Args:
        config_path (str): 配置文件路径

    Returns:
        SNClient: SNClient实例
    """
    # 加载配置文件
    config = load_chain_net_config(config_path)
    
    # 获取节点信息
    node_info = config['nodeInfo']
    business_rpc_network = node_info['network']['businessRpcNetwork']
    internal_network = business_rpc_network['internal']
    
    # 获取通道标识符
    channel_identifier = config['rootChain']['channelIdentifier']
    
    # 创建SNClient实例
    client = SNClient(
        host=internal_network['ip'],
        port=int(internal_network['port']),
        channel_identifier="af65e522e1e844609c70bb847cb01775"
    )
    
    print(f"[SNClient] 从配置文件创建客户端成功:")
    print(f"  节点信息: {node_info['nodeName']} ({node_info['nodeIdentifier']})")
    print(f"  连接地址: {internal_network['ip']}:{internal_network['port']}")
    print(f"  通道标识符: {channel_identifier}")
    
    return client


# ================= 示例用法 =================

if __name__ == "__main__":
    """
    示例用法：从配置文件创建客户端并执行系统合约调用
    """
    try:
        # 从配置文件创建客户端
        client = create_sn_client_from_config()
        
        # 执行系统合约调用（获取区块高度）
        real_payload_dict = {
                "key": "66666",
                "value": "success_test",
                "info": "test"
            }
        real_payload_json = json.dumps(real_payload_dict, ensure_ascii=False)
        result = client.invoke_user_contract("test5", "create", real_payload_json)
        
        # 打印结果
        print("\n" + "=" * 80)
        print("=== 合约调用结果 ===")
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
