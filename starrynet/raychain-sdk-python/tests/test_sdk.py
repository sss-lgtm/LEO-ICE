# -*- coding: utf-8 -*-
"""
SDK测试用例
"""

import sys
import os
# 添加项目根目录到搜索路径
sys.path.insert(0, os.path.abspath('.'))

import unittest
from unittest.mock import MagicMock, patch

from raychain.sdk.grpc.grpc_client import GrpcClient
from raychain.sdk.data.data_models import ContractID, SdkInvokeRequest, CommonResponse
from raychain.sdk.utils.utils import get_signature, build_contract_id


class TestGrpcClient(unittest.TestCase):
    """测试GrpcClient类"""

    def setUp(self):
        """设置测试环境"""
        self.host = "localhost"
        self.port = 50051
        self.node_type = "CONSENSUS"
        self.channel_identifier = "test-channel"
        self.sdk_properties = {
            "channels": {
                "channel": [
                    {
                        "name": "test-channel",
                        "grpcTimeOut": 5000
                    }
                ]
            },
            "ssl": {
                "enabled": False
            }
        }

    @patch('grpc.insecure_channel')
    def test_init_insecure(self, mock_insecure_channel):
        """测试初始化非TLS模式连接"""
        # 模拟gRPC通道和stub
        mock_channel = MagicMock()
        mock_insecure_channel.return_value = mock_channel

        # 创建GrpcClient实例
        client = GrpcClient(
            self.host, self.port, self.node_type, self.channel_identifier, self.sdk_properties
        )

        # 验证连接参数
        mock_insecure_channel.assert_called_once()
        self.assertEqual(client.host, self.host)
        self.assertEqual(client.port, self.port)
        self.assertEqual(client.node_type, self.node_type)
        self.assertEqual(client.grpc_time_out, 5000)  # 从配置中获取的超时时间

    @patch('grpc.secure_channel')
    @patch('raychain.sdk.grpc.grpc_client.GrpcClient._build_ssl_context')
    def test_init_secure(self, mock_build_ssl_context, mock_secure_channel):
        """测试初始化TLS模式连接"""
        # 模拟SSL上下文
        mock_ssl_context = MagicMock()
        mock_build_ssl_context.return_value = mock_ssl_context

        # 模拟gRPC通道
        mock_channel = MagicMock()
        mock_secure_channel.return_value = mock_channel

        # 更新配置为TLS模式
        self.sdk_properties['ssl']['enabled'] = True

        # 创建GrpcClient实例
        client = GrpcClient(
            self.host, self.port, self.node_type, self.channel_identifier, self.sdk_properties
        )

        # 验证连接参数
        mock_secure_channel.assert_called_once()
        mock_build_ssl_context.assert_called_once()

    def test_shutdown(self):
        """测试关闭连接"""
        # 使用真实的gRPC通道进行测试
        client = GrpcClient(
            self.host, self.port, self.node_type, self.channel_identifier, self.sdk_properties
        )

        # 调用shutdown方法
        client.shutdown()

        # 验证通道已关闭
        self.assertIsNotNone(client.channel)


class TestDataModels(unittest.TestCase):
    """测试数据模型"""

    def test_contract_id(self):
        """测试ContractID类"""
        # 创建ContractID实例
        contract_id = ContractID(
            identity="test-contract",
            name="test-contract",
            version="1.0.0",
            language_type="JAVA",
            type="SYSTEM"
        )

        # 验证属性
        self.assertEqual(contract_id.identity, "test-contract")
        self.assertEqual(contract_id.name, "test-contract")
        self.assertEqual(contract_id.version, "1.0.0")
        self.assertEqual(contract_id.language_type, "JAVA")
        self.assertEqual(contract_id.type, "SYSTEM")

    def test_sdk_invoke_request(self):
        """测试SdkInvokeRequest类"""
        # 创建ContractID实例
        contract_id = ContractID(
            identity="test-contract",
            name="test-contract",
            version="1.0.0",
            language_type="JAVA"
        )

        # 创建SdkInvokeRequest实例
        request = SdkInvokeRequest(
            contract_id=contract_id,
            method="get",
            payload='{"key": "test-key"}',
            channel_identifier="test-channel",
            app_id="test-app-id",
            sign="test-sign"
        )

        # 验证属性
        self.assertEqual(request.method, "get")
        self.assertEqual(request.payload, '{"key": "test-key"}')
        self.assertEqual(request.channel_identifier, "test-channel")
        self.assertEqual(request.app_id, "test-app-id")
        self.assertEqual(request.sign, "test-sign")

    def test_common_response(self):
        """测试CommonResponse类"""
        # 创建CommonResponse实例
        response = CommonResponse(
            success=True,
            message="Success",
            data={"result": "test-result"},
            tx_hash="test-tx-hash"
        )

        # 验证属性
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Success")
        self.assertEqual(response.data, {"result": "test-result"})
        self.assertEqual(response.tx_hash, "test-tx-hash")

        # 测试转换为JSON
        json_str = response.to_json()
        self.assertIn("Success", json_str)
        self.assertIn("test-result", json_str)
        self.assertIn("test-tx-hash", json_str)


class TestUtils(unittest.TestCase):
    """测试工具类"""

    def test_build_contract_id(self):
        """测试build_contract_id函数"""
        # 测试构建用户合约ID
        contract_id = build_contract_id("test-contract", "1.0.0", "JAVA", False)
        self.assertEqual(contract_id.identity, "test-contract")
        self.assertEqual(contract_id.name, "test-contract")
        self.assertEqual(contract_id.version, "1.0.0")
        self.assertEqual(contract_id.language_type, "JAVA")
        self.assertEqual(contract_id.type, "USER")

        # 测试构建系统合约ID
        contract_id = build_contract_id("system-contract", "1.0.0", "JAVA", True)
        self.assertEqual(contract_id.type, "SYSTEM")

    @patch('builtins.open', new_callable=MagicMock)
    @patch('raychain.sdk.utils.utils.serialization.load_pem_private_key')
    def test_get_signature(self, mock_load_pem_private_key, mock_open):
        """测试get_signature函数"""
        # 模拟私钥和签名
        mock_private_key = MagicMock()
        mock_private_key.sign.return_value = b"test-signature"
        mock_load_pem_private_key.return_value = mock_private_key

        # 模拟文件对象
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        # 测试参数
        payload = "test-payload"
        sdk_properties = {
            "app": {
                "privateKeyPath": "/path/to/private.key"
            },
            "cryptology": {
                "signatureAlgorithm": "SHA256withRSA"
            }
        }

        # 调用函数
        signature = get_signature(payload, sdk_properties)

        # 验证结果
        self.assertEqual(signature, "746573742d7369676e6174757265")  # "test-signature"的十六进制表示
        mock_private_key.sign.assert_called_once()


class TestSdkClient(unittest.TestCase):
    """测试SdkClient类"""

    def setUp(self):
        """设置测试环境"""
        # 创建模拟通道
        self.mock_channel = MagicMock()
        self.mock_channel.get_channel_identifier.return_value = "test-channel"
        self.mock_channel.get_sdk_properties.return_value = {
            "app": {
                "appId": "test-app-id",
                "privateKeyPath": "/path/to/private.key"
            },
            "cryptology": {
                "signatureAlgorithm": "SHA256withRSA"
            }
        }

    @patch('raychain.sdk.client.sdk_client.SdkClient')
    def test_invoke_system_contract(self, mock_sdk_client):
        """测试invoke_system_contract方法"""
        # 模拟SDK客户端和响应
        mock_response = CommonResponse(
            success=True,
            message="Success",
            data={"result": "test-result"}
        )
        mock_sdk_client.return_value.invoke_system_contract.return_value = mock_response

        # 创建SDK客户端实例
        from raychain.sdk.client.sdk_client import SdkClient
        sdk_client = SdkClient(self.mock_channel)

        # 调用方法
        result = sdk_client.invoke_system_contract(
            "test-contract", "1.0.0", "get", '{"key": "test-key"}'
        )

        # 验证结果
        self.assertTrue(result.success)
        self.assertEqual(result.message, "Success")


if __name__ == '__main__':
    unittest.main()
