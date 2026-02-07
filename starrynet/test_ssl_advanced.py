# -*- coding: utf-8 -*-
"""
SSL安全连接测试文件
测试SSL安全连接模式下的gRPC调用和合约调用
"""

import sys
import os
import json
import ssl
import grpc
import time
import base64
import binascii
import yaml
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


def load_config(yaml_path="application.yml"):
    """
    加载配置文件

    Args:
        yaml_path (str): 配置文件路径

    Returns:
        tuple: (配置字典, 配置文件路径)
    """
    search_paths = [yaml_path, os.path.join(os.path.dirname(__file__), yaml_path)]
    final_path = None
    for p in search_paths:
        if os.path.exists(p):
            final_path = p
            break
    if not final_path:
        raise FileNotFoundError(f"配置文件 {yaml_path} 未找到.")
    with open(final_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    return config, final_path


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


def test_grpc_and_contract_call(host, port, channel_identifier, base_sdk_properties):
    """
    测试SSL安全连接模式下的gRPC调用和合约调用

    Args:
        host (str): 主机地址
        port (int): 端口号
        channel_identifier (str): 通道标识符
        base_sdk_properties (dict): 基础SDK配置

    Returns:
        dict: 测试结果
    """
    print(f"\n=== SSL安全连接测试 ({host}:{port}) ===")

    result = {
        "host": host,
        "port": port,
        "grpc_connection": False,
        "contract_call": False,
        "error": "",
        "details": ""
    }

    try:
        # 检查端口是否有效（TCP/IP端口范围：0-65535）
        if port < 0 or port > 65535:
            print(f"[错误] 无效端口: {port}，端口必须在0-65535范围内")
            result["error"] = "无效端口"
            result["details"] = f"端口 {port} 超出有效范围（0-65535）"
            return result

        # 配置参数（直接使用通道标识符和固定APP_ID）
        APP_ID = "test-app-id"
        CHANNEL_NAME = channel_identifier

        print(f"[配置] 使用通道标识符: {CHANNEL_NAME}")
        print(f"[配置] 使用APP_ID: {APP_ID}")

        # 使用org-1目录下的sign证书进行签名
        sign_cert_dir = 'chain-net/data/cert/org-1/30199da1daa94f1bb201821dae4d7d4b'
        sign_key_path = os.path.join(sign_cert_dir, 'sign_private_key.key')
        
        if not os.path.exists(sign_key_path):
            print(f"[错误] 找不到签名密钥文件: {sign_key_path}")
            result["error"] = "找不到签名密钥文件"
            result["details"] = f"签名密钥文件 {sign_key_path} 不存在"
            return result
        
        print(f"[签名配置] 使用签名密钥: {sign_key_path}")

        # 创建SSL安全配置
        ssl_config = create_ssl_secure_config(host, port)

        # 构建完整的SDK配置
        sdk_properties = base_sdk_properties.copy()
        sdk_properties["ssl"] = ssl_config

        # 创建gRPC客户端
        print(f"[测试] 正在创建gRPC客户端...")
        grpc_client = GrpcClient(
            host=host,
            port=port,
            node_type="CONSENSUS",
            channel_identifier=CHANNEL_NAME,
            sdk_properties=sdk_properties
        )

        print(f"[测试] gRPC客户端初始化完成，准备执行合约调用...")

        # 导入protobuf请求类
        from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2

        # 构建合约ID（与sn_chain_client.py保持一致）
        contract_id = ContractID(
            identity="ray_chainnet_node_manage_contract",
            name="ray_chainnet_node_manage_contract",
            version="1.0.0",
            language_type="2",
            type="2"
        )

        # 构建请求payload（与sn_chain_client.py保持一致）
        print(f"[测试] 正在构造请求...")
        
        # 使用随机 Key 避免 Code 1 (重复主键错误)
        rand_key = int(time.time() * 1000) % 1000000

        # 构造 Payload
        real_payload_dict = {
            "key": rand_key,
            "value": "success_test",
            "info": "test_ssl_advanced"
        }
        real_payload_json = json.dumps(real_payload_dict, ensure_ascii=False)

        # 加载签名密钥并进行签名
        private_key_hex = load_sm2_private_key_hex(sign_key_path)
        print(f"[测试] 正在对payload进行签名...")
        signature = sm2_sign_data(private_key_hex, real_payload_json)

        # 构建invoke请求
        proto_request = common_pb2.SdkInvokeRequest(
            contract_id=contract_id.to_proto(),
            method="getAll",  # 使用create方法，与sn_chain_client.py保持一致
            payload=real_payload_json,
            channel_identifier="root-chain",  # 使用正确的字段名channel_identifier
            app_id=APP_ID,
            sign=signature
        )
        # 执行合约调用（这一步才会真正建立gRPC连接）
        print(f"[测试] 正在执行合约调用...")
        reply = grpc_client.invoke(proto_request)  # 使用invoke方法，与sn_chain_client.py保持一致
        print(f"✓ 合约调用成功!")
        print(f"  响应状态码: {reply.code}")
        print(f"  响应消息: {reply.message}")
        
        if hasattr(reply, 'txHash') and reply.txHash:
            print(f"  交易哈希: {reply.txHash}")

        # 合约调用成功，说明gRPC连接也成功
        result["grpc_connection"] = True
        
        if reply.code == 200 or reply.message == "SUCCESS" or (hasattr(reply, 'txHash') and reply.txHash):
            result["contract_call"] = True
            result["details"] = f"合约调用成功，响应状态码: {reply.code}"
        else:
            result["contract_call"] = False
            result["details"] = f"合约调用返回非成功状态，响应状态码: {reply.code}，消息: {reply.message}"

        # 关闭连接
        grpc_client.shutdown()
        print(f"✓ 连接已关闭")

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"✗ 测试失败: {e}")
        result["error"] = str(e)
        result["details"] = str(e)

    print(f"=== SSL安全连接测试完成 ===")
    return result


def test_ssl_secure_mode():
    """
    测试SSL安全连接模式下的gRPC调用和合约调用
    """
    # 从配置文件中读取节点信息
    config_path = 'chain-net/cfg/chain-net-config.json'
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    node_info = config['nodeInfo']
    business_rpc_network = node_info['network']['businessRpcNetwork']
    internal_network = business_rpc_network['internal']

    # 构建基础SDK配置
    base_sdk_properties = {
        "channels": {
            "channel": [
                {
                    "name": "root-chain",
                    "grpcTimeOut": 5000
                }
            ]
        },
        "app": {
            "appId": "test-app-id"
            # 移除privateKeyPath设置，因为不需要本地TLS证书
        },
        "cryptology": {
            "signatureAlgorithm": "SHA256withRSA"
        }
    }

    print("=== SSL安全连接测试 ===")
    print(f"节点信息: {node_info['nodeName']} ({node_info['nodeIdentifier']})")
    print(f"测试地址: {internal_network['ip']}:{internal_network['port']}")
    print("通道标识符: {root-chain}")
    print("=" * 80)

    # 测试SSL安全连接模式下的gRPC调用和合约调用
    result = test_grpc_and_contract_call(
        internal_network['ip'],
        int(internal_network['port']),
        "root-chain",
        base_sdk_properties
    )

    # 总结测试结果
    print("\n" + "=" * 80)
    print("=== SSL安全连接测试结果总结 ===")

    print(f"\ngRPC连接状态: {'✅ 成功' if result['grpc_connection'] else '❌ 失败'}")
    print(f"合约调用状态: {'✅ 成功' if result['contract_call'] else '❌ 失败'}")

    if result['grpc_connection'] and result['contract_call']:
        print(f"\n✅ SSL安全连接模式下gRPC调用和合约调用都成功!")
    elif result['grpc_connection']:
        print(f"\n⚠️  SSL安全连接模式下gRPC连接成功，但合约调用失败")
    else:
        print(f"\n❌ SSL安全连接模式下gRPC连接失败")

    if result['details']:
        print(f"\n详情: {result['details']}")

    if result['error']:
        print(f"\n错误信息: {result['error']}")

    print("\n" + "=" * 80)
    print("=== 测试完成 ===")


if __name__ == "__main__":
    test_ssl_secure_mode()
