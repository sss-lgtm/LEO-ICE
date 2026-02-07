import sys
import os
# 添加项目根目录到搜索路径
sys.path.insert(0, os.path.abspath('.'))

# 测试导入
from raychain.sdk.grpc.grpc_client import GrpcClient
from raychain.sdk.data.data_models import ContractID

print("导入成功!")
print(f"GrpcClient: {GrpcClient}")
print(f"ContractID: {ContractID}")
