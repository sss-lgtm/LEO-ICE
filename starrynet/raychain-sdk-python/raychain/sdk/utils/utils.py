# -*- coding: utf-8 -*-
"""
工具类，提供签名、序列化等功能
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from raychain.sdk.data.data_models import ContractID


def get_signature(payload: str, sdk_properties: Dict[str, Any]) -> str:
    """
    生成签名

    Args:
        payload (str): 待签名数据
        sdk_properties (Dict[str, Any]): SDK配置属性

    Returns:
        str: 签名字符串
    """
    if not payload:
        raise ValueError("待生成签名的参数为空")

    # 获取私钥路径和签名算法
    private_key_path = sdk_properties.get('app', {}).get('privateKeyPath', '')
    signature_algorithm = sdk_properties.get('cryptology', {}).get('signatureAlgorithm', 'SHA256withRSA')

    if not private_key_path:
        raise ValueError("私钥路径为空")

    # 读取私钥
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # 生成签名
    if signature_algorithm == 'SHA256withRSA':
        signature = private_key.sign(
            payload.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif signature_algorithm == 'SHA1withRSA':
        signature = private_key.sign(
            payload.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA1()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA1()
        )
    else:
        raise ValueError(f"不支持的签名算法: {signature_algorithm}")

    return signature.hex()


def build_contract_id(name: str, version: str, lang_type: str, is_system_contract: bool) -> ContractID:
    """
    构建合约ID

    Args:
        name (str): 合约名称
        version (str): 合约版本
        lang_type (str): 合约语言类型
        is_system_contract (bool): 是否为系统合约

    Returns:
        ContractID: 合约ID
    """
    contract_type = "USER"
    if is_system_contract:
        contract_type = "SYSTEM"

    return ContractID(
        identity=name,
        name=name,
        version=version,
        language_type=lang_type,
        type=contract_type
    )


class JsonUtils:
    """JSON工具类"""

    @staticmethod
    def to_json(obj: Any) -> str:
        """
        将对象转换为JSON字符串

        Args:
            obj (Any): 待转换对象

        Returns:
            str: JSON字符串
        """
        return json.dumps(obj, ensure_ascii=False, default=str)

    @staticmethod
    def parse_json(json_str: str, cls: type = None) -> Any:
        """
        将JSON字符串转换为对象

        Args:
            json_str (str): JSON字符串
            cls (type): 目标类，可选

        Returns:
            Any: 转换后的对象
        """
        if not json_str:
            return None

        data = json.loads(json_str)
        if cls and hasattr(cls, 'from_json'):
            return cls.from_json(json_str)
        return data


class SignHandler:
    """签名处理器"""

    @staticmethod
    def sign(private_key_path: str, signature_algorithm: str, payload: str) -> str:
        """
        生成签名

        Args:
            private_key_path (str): 私钥路径
            signature_algorithm (str): 签名算法
            payload (str): 待签名数据

        Returns:
            str: 签名字符串
        """
        if not private_key_path:
            raise ValueError("私钥路径为空")
        if not payload:
            payload = "nothing"

        # 读取私钥
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # 生成签名
        if signature_algorithm == 'SHA256withRSA':
            signature = private_key.sign(
                payload.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif signature_algorithm == 'SHA1withRSA':
            signature = private_key.sign(
                payload.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA1()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
        else:
            raise ValueError(f"不支持的签名算法: {signature_algorithm}")

        return signature.hex()
