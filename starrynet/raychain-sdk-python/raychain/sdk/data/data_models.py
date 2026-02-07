# -*- coding: utf-8 -*-
"""
数据模型定义
"""

import json
from typing import Any, Optional, Dict


class ContractID:
    """合约标识"""

    def __init__(self, identity: str, name: str, version: str, language_type: str, type: str = "USER", category: str = ""):
        """
        初始化合约标识

        Args:
            identity (str): 合约标识
            name (str): 合约名称
            version (str): 合约版本
            language_type (str): 合约语言类型
            type (str): 合约类型，USER或SYSTEM
            category (str): 合约分类
        """
        self.identity = identity
        self.name = name
        self.version = version
        self.language_type = language_type
        self.type = type
        self.category = category

    def to_proto(self):
        """
        转换为Proto对象

        Returns:
            contractID_pb2.ContractID: Proto对象
        """
        from raychain.sdk.grpc.generated.common import contractID_pb2 as contract_id_pb2
        return contract_id_pb2.ContractID(
            identity=self.identity,
            name=self.name,
            version=self.version,
            language_type=self.language_type,
            type=self.type,
            category=self.category
        )

    @classmethod
    def from_proto(cls, proto_obj):
        """
        从Proto对象创建ContractID

        Args:
            proto_obj: Proto对象

        Returns:
            ContractID: 合约标识
        """
        return cls(
            identity=proto_obj.identity,
            name=proto_obj.name,
            version=proto_obj.version,
            language_type=proto_obj.language_type,
            type=proto_obj.type,
            category=proto_obj.category
        )


class SdkInvokeRequest:
    """SDK调用请求"""

    def __init__(self, contract_id: ContractID, method: str, payload: str, channel_identifier: str,
                 app_id: str, app_type: str = "", sign: str = ""):
        """
        初始化SDK调用请求

        Args:
            contract_id (ContractID): 合约标识
            method (str): 方法名
            payload (str): 方法参数
            channel_identifier (str): 通道标识符
            app_id (str): 应用ID
            app_type (str): 应用类型
            sign (str): 签名
        """
        self.contract_id = contract_id
        self.method = method
        self.payload = payload
        self.channel_identifier = channel_identifier
        self.app_id = app_id
        self.app_type = app_type
        self.sign = sign

    def to_proto(self):
        """
        转换为Proto对象

        Returns:
            sdk_pb2.SdkInvokeRequest: Proto对象
        """
        from raychain.sdk.grpc.generated.node import service_for_sdk_pb2 as sdk_pb2
        return sdk_pb2.SdkInvokeRequest(
            contract_id=self.contract_id.to_proto(),
            method=self.method,
            payload=self.payload,
            channel_identifier=self.channel_identifier,
            app_id=self.app_id,
            app_type=self.app_type,
            sign=self.sign
        )

    @classmethod
    def from_proto(cls, proto_obj):
        """
        从Proto对象创建SdkInvokeRequest

        Args:
            proto_obj: Proto对象

        Returns:
            SdkInvokeRequest: SDK调用请求
        """
        return cls(
            contract_id=ContractID.from_proto(proto_obj.contract_id),
            method=proto_obj.method,
            payload=proto_obj.payload,
            channel_identifier=proto_obj.channel_identifier,
            app_id=proto_obj.app_id,
            app_type=proto_obj.app_type,
            sign=proto_obj.sign
        )


class RpcReply:
    """RPC响应"""

    def __init__(self, code: int, message: str, payload: str, tx_hash: str = ""):
        """
        初始化RPC响应

        Args:
            code (int): 响应码，1为成功，0为失败
            message (str): 响应消息
            payload (str): 响应数据
            tx_hash (str): 交易哈希
        """
        self.code = code
        self.message = message
        self.payload = payload
        self.tx_hash = tx_hash

    def to_proto(self):
        """
        转换为Proto对象

        Returns:
            common_pb2.RpcReply: Proto对象
        """
        from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2
        return common_pb2.RpcReply(
            code=self.code,
            message=self.message,
            payload=self.payload,
            tx_hash=self.tx_hash
        )

    @classmethod
    def from_proto(cls, proto_obj):
        """
        从Proto对象创建RpcReply

        Args:
            proto_obj: Proto对象

        Returns:
            RpcReply: RPC响应
        """
        return cls(
            code=proto_obj.code,
            message=proto_obj.message,
            payload=proto_obj.payload,
            tx_hash=proto_obj.tx_hash
        )


class ResponseWrapper:
    """响应包装器"""

    def __init__(self, contract_result: Any = None, transaction: Optional[Dict] = None):
        """
        初始化响应包装器

        Args:
            contract_result (Any): 合约执行结果
            transaction (Optional[Dict]): 交易信息
        """
        self.contract_result = contract_result
        self.transaction = transaction

    @classmethod
    def from_json(cls, json_str: str):
        """
        从JSON字符串创建ResponseWrapper

        Args:
            json_str (str): JSON字符串

        Returns:
            ResponseWrapper: 响应包装器
        """
        if not json_str:
            return cls()

        data = json.loads(json_str)
        return cls(
            contract_result=data.get("contractResult"),
            transaction=data.get("transaction")
        )

    def to_json(self) -> str:
        """
        转换为JSON字符串

        Returns:
            str: JSON字符串
        """
        return json.dumps({
            "contractResult": self.contract_result,
            "transaction": self.transaction
        }, ensure_ascii=False)


class CommonResponse:
    """通用响应"""

    def __init__(self, success: bool = True, message: str = "", data: Any = None, tx_hash: str = ""):
        """
        初始化通用响应

        Args:
            success (bool): 是否成功
            message (str): 响应消息
            data (Any): 响应数据
            tx_hash (str): 交易哈希
        """
        self.success = success
        self.message = message
        self.data = data
        self.tx_hash = tx_hash

    def to_json(self) -> str:
        """
        转换为JSON字符串

        Returns:
            str: JSON字符串
        """
        return json.dumps({
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "txHash": self.tx_hash
        }, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str):
        """
        从JSON字符串创建CommonResponse

        Args:
            json_str (str): JSON字符串

        Returns:
            CommonResponse: 通用响应
        """
        data = json.loads(json_str)
        return cls(
            success=data.get("success", True),
            message=data.get("message", ""),
            data=data.get("data"),
            tx_hash=data.get("txHash", "")
        )
