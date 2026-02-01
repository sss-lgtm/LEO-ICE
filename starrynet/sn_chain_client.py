import grpc
import json
import time
import sys
import os
import yaml
import base64
import binascii
import ssl
import socket
import random

# 引入加密相关库
from gmssl import sm2, func
from asn1crypto import keys, pem, x509

# 导入 Protobuf
try:
    import service_for_sdk_pb2
    import service_for_sdk_pb2_grpc
    import contractID_pb2
except ImportError:
    from starrynet import service_for_sdk_pb2
    from starrynet import service_for_sdk_pb2_grpc
    from starrynet import contractID_pb2

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
    """自动获取证书并解析 Common Name"""
    print(f"[Auto-Fetch] Downloading certificate from {host}:{port}...")
    try:
        cert_pem = ssl.get_server_certificate((host, port))
        cert_bytes = cert_pem.encode('utf-8')
        
        if pem.detect(cert_bytes):
            _, _, der_bytes = pem.unarmor(cert_bytes)
        else:
            der_bytes = cert_bytes
            
        cert_obj = x509.Certificate.load(der_bytes)
        subject = cert_obj['tbs_certificate']['subject'].native
        common_name = subject.get('common_name')
        
        if not common_name:
            print("[Auto-Fetch] Warning: No Common Name found, using host as default.")
            common_name = host
            
        print(f"[Auto-Fetch] Parsed CN: {common_name}")
        return cert_bytes, common_name
    except Exception as e:
        print(f"[Auto-Fetch Error] Failed: {e}")
        return None, None

def load_config(yaml_path="application.yml"):
    search_paths = [yaml_path, os.path.join(os.path.dirname(__file__), yaml_path)]
    final_path = None
    for p in search_paths:
        if os.path.exists(p):
            final_path = p
            break
    if not final_path:
        raise FileNotFoundError(f"Config file {yaml_path} not found.")
    with open(final_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    return config, final_path

def load_sm2_private_key_hex(key_path):
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
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
    r_hex = signature_hex[0:len_hex//2]
    s_hex = signature_hex[len_hex//2:]
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

# ================= 主业务逻辑 =================

def upload_consensus_data(result, vote_records):
    try:
        # 1. 配置加载
        conf, conf_path = load_config("application.yml")
        app_conf = conf['raybaas']['app']
        channel_conf = conf['raybaas']['channels']['channel[0]']
        
        APP_ID = str(app_conf['appId'])
        CHANNEL_NAME = channel_conf['name']
        
        # 密钥路径
        KEY_FILE_NAME = "sm2_private_7bff4c20c76e0a74be3fbdec6cde8dc036433996.key"
        base_dir = os.path.dirname(os.path.abspath(__file__))
        KEY_PATH = "/root/StarryNet/starrynet/chain-net/data/cert/org-1/30199da1daa94f1bb201821dae4d7d4b/sign_private_key.key"
        if not os.path.exists(KEY_PATH):
             yml_key_path = app_conf['privateKeyPath']
             KEY_PATH = os.path.join(os.path.dirname(conf_path), yml_key_path)

        # 目标地址
        TARGET_IP = "192.168.110.243"
        TARGET_PORT = 51051
        BLOCKCHAIN_SERVER = f"{TARGET_IP}:{TARGET_PORT}"

        print(f"[Config] Key: {KEY_PATH}")
        print(f"[Config] Target: {BLOCKCHAIN_SERVER}")
        
        # 2. SSL 连接 (自动抓取证书)
        server_cert_bytes, server_cn = get_server_certificate_and_cn(TARGET_IP, TARGET_PORT)
        if not server_cert_bytes:
            return False, "Cert fetch failed"

        options = [('grpc.max_send_message_length', 50 * 1024 * 1024),
                   ('grpc.max_receive_message_length', 50 * 1024 * 1024)]
        creds = grpc.ssl_channel_credentials(root_certificates=server_cert_bytes)
        
        # 覆盖域名
        print(f"[ChainClient] Overriding SSL target name to: {server_cn}")
        options.append(('grpc.ssl_target_name_override', server_cn))
        
        channel_ctx = grpc.secure_channel(BLOCKCHAIN_SERVER, creds, options=options)
        private_key_hex = load_sm2_private_key_hex(KEY_PATH)

        with channel_ctx as channel:
            stub = service_for_sdk_pb2_grpc.SdkInvokeServiceStub(channel)

            # 3. 构造请求
            # 使用随机 Key 避免 Code 1 (重复主键错误)
            rand_key = int(time.time() * 1000) % 1000000
            
            # 构造 Payload (与 C 代码结构类似但使用动态 Key)
            real_payload_dict = {
                "key": rand_key,
                "value": "success_test",
                "info": str(result)
            }
            real_payload_json = json.dumps(real_payload_dict, ensure_ascii=False)
            
            print(f"[ChainClient] Signing payload: {real_payload_json}")
            signature = sm2_sign_data(private_key_hex, real_payload_json)

            # 构造 ContractID (修正后的参数)
            contract_id_obj = contractID_pb2.ContractID(
                name="test1",
                version="1.3.5",
                type="2",                     # 对应 USER_CONTRACT
                language_type="4",            # 对应 JAVA
                identity="test1"    # 修正：必须填这个
            )

            request = service_for_sdk_pb2.SdkInvokeRequest(
                contract_id=contract_id_obj,
                method="create",
                payload=real_payload_json,
                channel_name="a3d1aef760d4469ab8f907d10f3169fe",
                app_id="zero_node",
                sign=signature
            )

            print("[ChainClient] Invoking 'create'...")
            response = stub.invoke(request)
            
            # 4. 处理响应
            if response.code == 200 or response.message == "SUCCESS" or response.txHash:
                print(f"[Success] TxHash: {response.txHash}")
                return True, response.txHash
            else:
                # 打印详细 Payload 以便排查
                err_detail = response.payload.decode('utf-8', errors='ignore') if response.payload else ""
                print(f"[Fail] Code: {response.code}, Msg: {response.message}")
                if err_detail:
                    print(f"[Fail Detail] {err_detail}")
                return False, response.message

    except Exception as e:
        import traceback
        traceback.print_exc()
        return False, str(e)

if __name__ == "__main__":
    upload_consensus_data("Test_Final_Pass", {"status": "ok"})