# -*- coding: utf-8 -*-
"""
同时测试内部地址和外部地址的gRPC连接
"""

import sys
import os
import json
# 添加项目根目录到搜索路径
sys.path.insert(0, os.path.abspath('./raychain-sdk-python'))

from raychain.sdk.grpc.grpc_client import GrpcClient
from raychain.sdk.data.data_models import ContractID


def test_address(address_name, host, port, ssl_enabled, ssl_mutual, cert_dir, channel_identifier, sdk_properties):
    """
    测试单个地址的连接情况
    
    Args:
        address_name (str): 地址名称
        host (str): 主机地址
        port (int): 端口
        ssl_enabled (bool): 是否启用SSL
        ssl_mutual (bool): 是否启用双向认证
        cert_dir (str): 证书目录
        channel_identifier (str): 通道标识符
        sdk_properties (dict): SDK配置
        
    Returns:
        dict: 测试结果
    """
    print(f"\n=== 测试 {address_name} ({host}:{port}) ===")
    print(f"SSL: {ssl_enabled}, SSL Mutual: {ssl_mutual}")
    print(f"证书目录: {cert_dir}")
    
    result = {
        "address_name": address_name,
        "host": host,
        "port": port,
        "ssl_enabled": ssl_enabled,
        "ssl_mutual": ssl_mutual,
        "success": False,
        "error": "",
        "details": ""
    }
    
    try:
        # 创建gRPC客户端
        grpc_client = GrpcClient(
            host=host,
            port=port,
            node_type="CONSENSUS",
            channel_identifier=channel_identifier,
            sdk_properties=sdk_properties
        )
        
        print(f"✓ {address_name} 连接成功!")
        result["success"] = True
        result["details"] = "连接成功"
        
        # 构建一个简单的测试请求
        contract_id = ContractID(
            identity="system-contract",
            name="system-contract",
            version="1.0.0",
            language_type="JAVA",
            type="SYSTEM"
        )
        
        # 从common模块导入SdkInvokeRequest
        from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2
        proto_request = common_pb2.SdkInvokeRequest(
            contract_id=contract_id.to_proto(),
            method="findBlockHeight",
            payload="",
            channel_identifier=channel_identifier,
            app_id="test-app-id",
            sign="test-sign"
        )
        
        # 尝试执行查询（可能会失败，因为链可能未部署）
        print(f"尝试执行查询...")
        reply = grpc_client.query(proto_request)
        print(f"✓ 查询请求发送成功，响应状态码: {reply.code}")
        print(f"  响应消息: {reply.message}")
        result["details"] = f"连接成功，查询响应状态码: {reply.code}"
        
        # 关闭连接
        grpc_client.shutdown()
        print(f"✓ 连接已关闭")
        
    except Exception as e:
        print(f"✗ {address_name} 测试失败: {e}")
        result["success"] = False
        result["error"] = str(e)
        import traceback
        # 只获取前10行错误信息，避免输出过长
        error_lines = traceback.format_exc().splitlines()[:10]
        result["details"] = "\n".join(error_lines)
    
    print(f"=== {address_name} 测试完成 ===")
    return result


def test_both_addresses():
    """
    同时测试内部地址和外部地址
    """
    # 从配置文件中读取节点信息
    config_path = 'chain-net/cfg/chain-net-config.json'
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 获取节点信息
    node_info = config['nodeInfo']
    business_rpc_network = node_info['network']['businessRpcNetwork']
    internal_network = business_rpc_network['internal']
    external_network = business_rpc_network['external']

    # 证书路径
    cert_dir = 'chain-net/data/cert/org-1/30199da1daa94f1bb201821dae4d7d4b'
    tls_cert_path = os.path.join(cert_dir, 'tls_cert.crt')
    tls_key_path = os.path.join(cert_dir, 'tls_private_key.key')

    # 构建SDK配置
    sdk_properties = {
        "channels": {
            "channel": [
                {
                    "name": config['rootChain']['channelIdentifier'],
                    "grpcTimeOut": 5000
                }
            ]
        },
        "ssl": {
            "enabled": True,
            "sslMutual": False,
            "sslCertFilePath": tls_cert_path,
            "sslPrivateKeyPath": tls_key_path,
            "sslTrustCertFilePath": tls_cert_path
        },
        "app": {
            "appId": "test-app-id",
            "privateKeyPath": tls_key_path
        },
        "cryptology": {
            "signatureAlgorithm": "SHA256withRSA"
        }
    }

    print("=== gRPC连接测试（同时测试内部地址和外部地址） ===")
    print(f"节点信息: {node_info['nodeName']} ({node_info['nodeIdentifier']})")
    print(f"内部地址: {internal_network['ip']}:{internal_network['port']} (SSL: {internal_network['ssl']})")
    print(f"外部地址: {external_network['ip']}:{external_network['port']} (SSL: {external_network['ssl']})")
    print(f"通道标识符: {config['rootChain']['channelIdentifier']}")
    print("=" * 80)

    # 测试内部地址
    internal_result = test_address(
        "内部地址",
        internal_network['ip'],
        int(internal_network['port']),
        internal_network['ssl'],
        internal_network['sslMutual'],
        cert_dir,
        config['rootChain']['channelIdentifier'],
        sdk_properties
    )

    # 测试外部地址
    external_result = test_address(
        "外部地址",
        external_network['ip'],
        int(external_network['port']),
        external_network['ssl'],
        external_network['sslMutual'],
        cert_dir,
        config['rootChain']['channelIdentifier'],
        sdk_properties
    )

    # 总结结果
    print("\n" + "=" * 80)
    print("=== 测试结果总结 ===")
    
    print(f"\n内部地址 ({internal_network['ip']}:{internal_network['port']}):")
    print(f"  状态: {'✓ 成功' if internal_result['success'] else '✗ 失败'}")
    if internal_result['success']:
        print(f"  详情: {internal_result['details']}")
    else:
        print(f"  错误: {internal_result['error']}")
    
    print(f"\n外部地址 ({external_network['ip']}:{external_network['port']}):")
    print(f"  状态: {'✓ 成功' if external_result['success'] else '✗ 失败'}")
    if external_result['success']:
        print(f"  详情: {external_result['details']}")
    else:
        print(f"  错误: {external_result['error']}")
    
    print("\n" + "=" * 80)
    
    # 比较结果
    if internal_result['success'] and external_result['success']:
        print("✅ 内部地址和外部地址都连接成功!")
    elif internal_result['success']:
        print("⚠️  只有内部地址连接成功，外部地址连接失败")
    elif external_result['success']:
        print("⚠️  只有外部地址连接成功，内部地址连接失败")
    else:
        print("❌ 内部地址和外部地址都连接失败")
    
    print("\n=== 测试完成 ===")


if __name__ == "__main__":
    test_both_addresses()
