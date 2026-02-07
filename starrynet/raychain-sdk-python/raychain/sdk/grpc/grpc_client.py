# -*- coding: utf-8 -*-
"""
gRPC客户端实现
"""

import grpc
from raychain.sdk.grpc.generated.node import service_for_sdk_pb2 as sdk_pb2
from raychain.sdk.grpc.generated.node import service_for_sdk_pb2_grpc as sdk_pb2_grpc
from raychain.sdk.grpc.generated.node import service_for_sdk_admin_pb2 as admin_pb2
from raychain.sdk.grpc.generated.node import service_for_sdk_admin_pb2_grpc as admin_pb2_grpc
from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2


class GrpcClient:
    """gRPC客户端类，负责与区块链节点建立连接并进行通信"""

    def __init__(self, host, port, node_type, channel_identifier, sdk_properties):
        """
        初始化gRPC客户端

        Args:
            host (str): 节点主机地址
            port (int): 节点端口
            node_type (str): 节点类型，如CONSENSUS, ARCHIVAL
            channel_identifier (str): 通道标识符
            sdk_properties (dict): SDK配置属性
        """
        self.host = host
        self.port = port
        self.node_type = node_type
        self.sdk_properties = sdk_properties
        self.grpc_time_out = 3000  # 默认超时时间3秒
        self.channel_identifier = channel_identifier

        # 从配置中获取通道超时时间
        if sdk_properties and sdk_properties.get('channels'):
            for channel in sdk_properties['channels'].get('channel', []):
                if channel.get('name') == channel_identifier and channel.get('grpcTimeOut'):
                    self.grpc_time_out = channel['grpcTimeOut']

        # 构建gRPC通道
        if sdk_properties and sdk_properties.get('ssl', {}).get('enabled', False):
            # TLS模式
            ssl_config = sdk_properties['ssl']
            
            # 配置SSL验证选项
            options = [
                ('grpc.max_send_message_length', -1),
                ('grpc.max_receive_message_length', -1),
            ]
            
            # 处理SSL目标名称覆盖
            if ssl_config.get('sslTargetNameOverride'):
                # 使用配置的sslTargetNameOverride值
                options.append(('grpc.ssl_target_name_override', ssl_config['sslTargetNameOverride']))
                print(f"[SSL Config] 使用SSL目标名称覆盖: {ssl_config['sslTargetNameOverride']}")
            elif ssl_config.get('disableHostnameVerification', False):
                # 如果没有配置sslTargetNameOverride，但禁用了主机名验证，则使用host作为覆盖值
                options.append(('grpc.ssl_target_name_override', host))
                print(f"[SSL Config] 禁用主机名验证，使用主机名作为SSL目标名称: {host}")
            
            # 禁用SSL验证（用于开发环境）
            if ssl_config.get('disableVerification', False):
                # 使用不安全的SSL上下文，不验证证书
                # 创建一个空的SSL上下文，不验证任何证书
                self.channel = grpc.secure_channel(
                    f'{host}:{port}',
                    grpc.ssl_channel_credentials(),  # 空的SSL上下文
                    options=options
                )
            else:
                # 正常SSL验证
                ssl_context = self._build_ssl_context(ssl_config)
                self.channel = grpc.secure_channel(
                    f'{host}:{port}',
                    ssl_context,
                    options=options
                )
        else:
            # 非TLS模式
            self.channel = grpc.insecure_channel(
                f'{host}:{port}',
                options=[
                    ('grpc.max_send_message_length', -1),
                    ('grpc.max_receive_message_length', -1),
                ]
            )

        # 创建stub
        self.blocking_stub = sdk_pb2_grpc.SdkInvokeServiceStub(self.channel)
        # 创建管理员服务stub
        self.admin_blocking_stub = admin_pb2_grpc.SdkAdminInvokeServiceStub(self.channel)

    def _build_ssl_context(self, ssl_config):
        """
        构建SSL上下文

        Args:
            ssl_config (dict): SSL配置

        Returns:
            grpc.ssl_channel_credentials: SSL通道凭据
        """
        root_certificates = None
        private_key = None
        certificate_chain = None
        
        # 读取证书文件（如果配置了）
        if ssl_config.get('sslTrustCertFilePath'):
            try:
                with open(ssl_config['sslTrustCertFilePath'], 'rb') as trust_file:
                    root_certificates = trust_file.read()
                print(f"[SSL Config] 使用信任证书: {ssl_config['sslTrustCertFilePath']}")
            except Exception as e:
                print(f"[警告] 无法读取信任证书文件: {e}")
        
        # 处理双向认证
        if ssl_config.get('sslMutual', False):
            try:
                with open(ssl_config['sslCertFilePath'], 'rb') as cert_file, \
                     open(ssl_config['sslPrivateKeyPath'], 'rb') as key_file:
                    certificate_chain = cert_file.read()
                    private_key = key_file.read()
                print(f"[SSL Config] 使用双向认证，客户端证书: {ssl_config['sslCertFilePath']}")
            except Exception as e:
                print(f"[警告] 无法读取双向认证证书文件: {e}")
        
        # 创建SSL通道凭据
        # 注意：根据Java SDK的实现，默认情况下不验证服务器证书
        # 与Java SDK保持一致，使用不安全的SSL上下文
        ssl_credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain
        )
        
        return ssl_credentials

    def query(self, sdk_invoke_request):
        """
        执行查询操作

        Args:
            sdk_invoke_request (SdkInvokeRequest): 查询请求

        Returns:
            RpcReply: 查询响应
        """
        return self.blocking_stub.query(sdk_invoke_request)

    def invoke(self, sdk_invoke_request):
        """
        执行合约调用

        Args:
            sdk_invoke_request (SdkInvokeRequest): 调用请求

        Returns:
            RpcReply: 调用响应
        """
        return self.blocking_stub.invoke(sdk_invoke_request)

    def send_transaction(self, sdk_send_transaction_request):
        """
        发送交易

        Args:
            sdk_send_transaction_request (SdkSendTransactionRequest): 交易请求

        Returns:
            RpcReply: 交易响应
        """
        return self.blocking_stub.sendTransaction(sdk_send_transaction_request)

    def command(self, command_request):
        """
        执行节点命令

        Args:
            command_request (CommandRequest): 命令请求

        Returns:
            RpcReply: 命令响应
        """
        return self.admin_blocking_stub.command(command_request)

    def shutdown(self):
        """
        关闭gRPC通道
        """
        if hasattr(self, 'channel') and self.channel:
            self.channel.close()


