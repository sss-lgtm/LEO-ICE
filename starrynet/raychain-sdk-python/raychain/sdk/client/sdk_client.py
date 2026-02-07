# -*- coding: utf-8 -*-
"""
SDK客户端实现，提供合约调用和查询的高级接口
"""

import json
import concurrent.futures
from typing import Dict, List, Any, Optional

from raychain.sdk.grpc.grpc_client import GrpcClient
from raychain.sdk.grpc.generated.common import rpc_common_pb2 as common_pb2
from raychain.sdk.grpc.generated.common import contractID_pb2 as contract_id_pb2
from raychain.sdk.grpc.generated.node import service_for_sdk_pb2 as sdk_pb2
from raychain.sdk.data.data_models import CommonResponse, ResponseWrapper, ContractID, SdkInvokeRequest
from raychain.sdk.utils.utils import get_signature, build_contract_id


class SdkClient:
    """SDK客户端类，提供合约调用和查询的高级接口"""

    PARAM_IS_NULL = "参数非空校验失败"
    UNKNOWN_CHANNEL = "通道未初始化"
    QUERY_ERROR = "查询异常，错误码为：%s，%s"
    PAGE_SIZE = "pageSize"
    PAGE_SIZE_COUNT = 1000  # 分页条数限制
    CONTRACT_IDENTITY = "contractIdentity"
    QUERY_PARAM_ERROR = "查询参数错误,contractIdentity=%s，condition=%s"

    # 查询方法定义
    SDK_QUERY_METHODS = {
        "FIND_BLOCK_BY_HEIGHT": "findBlockByHeight",
        "FIND_BLOCK_BY_TX_HASH": "findBlockByTxHash",
        "FIND_BLOCK_LATEST": "findBlockLatest",
        "FIND_BLOCK_LIST": "findBlockList",
        "FIND_BLOCK_HEIGHT": "findBlockHeight",
        "FIND_TRANSACTION_BY_HASH": "findTransactionByHash",
        "FIND_TRANSACTION_LIST": "findTransactionList",
        "FIND_TRANSACTION_TOTAL": "findTransactionTotal",
        "FIND_MERKLE_ROUTE_BY_TX_HASH": "findMerkleRouteByTxHash",
        "FIND_RECORD_BY_PREFIX": "findRecordByPrefix",
        "FIND_STATE_BY_KEY": "findStateByKey",
        "FIND_HISTORY_QUERY": "findHistoryQuery",
        "FIND_KEY_RECORD_BY_CONDITION": "findKeyRecordByCondition",
        "AGGREGATE_KEY_RECORD_BY_CONDITION": "aggregateKeyRecordByCondition",
        "COUNT_KEY_RECORD_BY_CONDITION": "countKeyRecordByCondition",
        "FIND_TOP_TPS": "findTopTps",
        "FIND_BLOCK_TX_STATS": "findBlockTxStats"
    }

    def __init__(self, channel):
        """
        初始化SDK客户端

        Args:
            channel: 通道对象，用于管理gRPC客户端
        """
        self.channel = channel
        # 缓存所有通道
        self.channel_map = {channel.get_channel_identifier(): channel}
        # 上链限制，默认1500笔/秒
        self.semaphore = concurrent.futures.ThreadPoolExecutor(max_workers=1500)

    def invoke_system_contract(self, contract_identity, version, method_name, method_param):
        """
        调用系统合约

        Args:
            contract_identity (str): 合约标识
            version (str): 合约版本
            method_name (str): 方法名
            method_param (str): 方法参数

        Returns:
            CommonResponse: 调用结果
        """
        if not all([self.channel, method_name, method_param, contract_identity, version]):
            return CommonResponse(success=False, message=self.PARAM_IS_NULL)

        # 生成签名
        sign = get_signature(method_param, self.channel.get_sdk_properties())

        # 构建合约ID
        contract_id = build_contract_id(
            contract_identity, version, "JAVA", True  # 系统合约
        )

        # 构建调用请求
        request = SdkInvokeRequest(
            contract_id=contract_id,
            method=method_name,
            payload=method_param,
            channel_identifier=self.channel.get_channel_identifier(),
            app_id=self.channel.get_sdk_properties().get('app', {}).get('appId', ''),
            sign=sign
        )

        # 执行调用
        reply = self.channel.invoke(request)
        return self._build_reply(reply)

    def find_block_by_height(self, height):
        """
        根据高度查询区块

        Args:
            height (int): 区块高度

        Returns:
            dict: 区块信息
        """
        if not self.channel or height < 0:
            return None

        params = {"height": height}
        payload = json.dumps(params)
        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_BLOCK_BY_HEIGHT"], payload)
        return self._build_query_reply(reply, dict)

    def find_block_by_tx_hash(self, tx_hash):
        """
        根据交易哈希查询区块

        Args:
            tx_hash (str): 交易哈希

        Returns:
            dict: 区块信息
        """
        if not self.channel or not tx_hash:
            return None

        params = {"txHash": tx_hash}
        payload = json.dumps(params)
        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_BLOCK_BY_TX_HASH"], payload)
        return self._build_query_reply(reply, dict)

    def find_block_latest(self):
        """
        查询最新区块

        Returns:
            dict: 最新区块信息
        """
        if not self.channel:
            return None

        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_BLOCK_LATEST"], "")
        return self._build_query_reply(reply, dict)

    def find_block_height(self):
        """
        查询区块高度

        Returns:
            int: 区块高度
        """
        if not self.channel:
            return 0

        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_BLOCK_HEIGHT"], "")
        return self._build_query_reply(reply, int)

    def find_transaction_by_hash(self, hash_val):
        """
        根据哈希查询交易

        Args:
            hash_val (str): 交易哈希

        Returns:
            dict: 交易信息
        """
        if not self.channel or not hash_val:
            return None

        params = {"hash": hash_val}
        payload = json.dumps(params)
        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_TRANSACTION_BY_HASH"], payload)
        return self._build_query_reply(reply, dict)

    def find_state_by_key(self, contract_identity, key):
        """
        查询状态库数据

        Args:
            contract_identity (str): 合约标识
            key (str): 查询键

        Returns:
            str: 查询结果
        """
        params = {
            "key": key,
            self.CONTRACT_IDENTITY: contract_identity
        }
        payload = json.dumps(params)
        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_STATE_BY_KEY"], payload)
        return self._build_query_reply(reply, str)

    def find_history_record_by_key(self, contract_identity, key):
        """
        查询历史记录

        Args:
            contract_identity (str): 合约标识
            key (str): 查询键

        Returns:
            list: 历史记录列表
        """
        params = {
            "key": key,
            self.CONTRACT_IDENTITY: contract_identity
        }
        payload = json.dumps(params)
        reply = self.channel.query(self.SDK_QUERY_METHODS["FIND_HISTORY_QUERY"], payload)
        self._assert_resp_successfully(reply)
        return json.loads(reply.payload)

    def _build_reply(self, reply):
        """
        构建通用响应

        Args:
            reply (RpcReply): RPC响应

        Returns:
            CommonResponse: 通用响应
        """
        response_wrapper = ResponseWrapper.from_json(reply.payload)
        return CommonResponse(
            success=reply.code == 1,
            message=reply.message,
            data=response_wrapper.contract_result if response_wrapper else None,
            tx_hash=reply.tx_hash
        )

    def _build_query_reply(self, reply, result_type):
        """
        构建查询响应

        Args:
            reply (RpcReply): RPC响应
            result_type (type): 结果类型

        Returns:
            Any: 查询结果
        """
        self._assert_resp_successfully(reply)
        if result_type == dict:
            return json.loads(reply.payload)
        elif result_type == int:
            return int(reply.payload)
        elif result_type == str:
            return reply.payload
        else:
            return reply.payload

    def _assert_resp_successfully(self, reply):
        """
        断言响应成功

        Args:
            reply (RpcReply): RPC响应

        Raises:
            RuntimeError: 如果响应失败
        """
        if reply.code != 1:
            raise RuntimeError(self.QUERY_ERROR % (reply.message, reply.payload))

    def _illegal_page_param(self, page_from, page_size):
        """
        检查分页参数是否合法

        Args:
            page_from (int): 起始页码
            page_size (int): 每页条数

        Returns:
            bool: 是否合法
        """
        if not self.channel or page_from <= 0 or page_size <= 0:
            return True
        if page_size > self.PAGE_SIZE_COUNT:
            raise RuntimeError(f"分页数据一次不能超过【{self.PAGE_SIZE_COUNT}】条数据")
        return False

    def _build_page_param(self, page_from, page_size):
        """
        构建分页参数

        Args:
            page_from (int): 起始页码
            page_size (int): 每页条数

        Returns:
            str: 分页参数JSON字符串
        """
        params = {
            "pageFrom": page_from,
            self.PAGE_SIZE: page_size
        }
        return json.dumps(params)
