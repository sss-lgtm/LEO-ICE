# skycastle/node_agent.py
import socket
import threading
import json
import os
import subprocess
import time
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

ANCHOR_PORT = 9999
BUFFER_SIZE = 1024

class SkyCastleAgent:
    def __init__(self, my_id, role, anchor_ip=None):
        self.my_id = my_id
        self.role = role  # 'ANCHOR' or 'NORMAL'
        self.anchor_ip = anchor_ip
        self.user_table = {}  # {user_ip: ingress_sat_ip} (仅 Anchor 用)

    def run(self):
        logging.info(f"Agent started. ID: {self.my_id}, Role: {self.role}")
           # === [新增] 自动配置 SRv6 Loopback 地址 ===
        # 格式: 2001:db8:0:<sat_id>::1
        # 例如 1号卫星: 2001:db8:0:1::1
        my_srv6_ip = f"2001:db8:0:{self.my_id}::1/128"
        
        # 添加到 lo 接口 (Loopback)
        # 这样无论物理接口怎么变，这个 IP 永远代表这颗卫星
        os.system(f"ip -6 addr add {my_srv6_ip} dev lo")
        logging.info(f" assigned SRv6 SID: {my_srv6_ip}")
        # ========================================
            
        # 启动 API 监听服务器 (用于接收 Orchestrater 的指令)
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()

        if self.role == 'ANCHOR':
            logging.info("Running in ANCHOR mode")
            # Anchor 需要维护 DHCP 或类似逻辑，这里简化为 SRv6 规则下发
        
        # 保持主线程运行
        while True:
            time.sleep(10)

    def start_server(self):
        """监听控制信令"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', ANCHOR_PORT))
        s.listen(5)
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle_message, args=(conn,)).start()

    def handle_message(self, conn):
        try:
            data = conn.recv(BUFFER_SIZE).decode('utf-8')
            if not data: return
            msg = json.loads(data)
            
            msg_type = msg.get('type')
            
            if msg_type == 'UPDATE_LOCATION':
                # Ingress Sat 告诉 Anchor: "用户 X 在我这"
                self.handle_location_update(msg)
            
            elif msg_type == 'APPLY_SRV6':
                # Orchestrater 强制下发 SRv6 策略
                self.apply_srv6_policy(msg)

        except Exception as e:
            logging.error(f"Error handling msg: {e}")
        finally:
            conn.close()

    def handle_location_update(self, msg):
        """Anchor 逻辑: 更新位置表"""
        user_ip = msg['user_ip']
        ingress_ip = msg['ingress_ip']
        self.user_table[user_ip] = ingress_ip
        logging.info(f"Updated location: User {user_ip} -> Sat {ingress_ip}")
        # 在这里可以触发 SRv6 路由更新
        # self.inject_srv6_route(...)

    def apply_srv6_policy(self, msg):
        """核心：调用 iproute2 下发 SRv6 规则"""
        # 这里的命令对应论文中的 Segment Routing 实现
        # 格式示例: ip -6 route add <dst> encap seg6 mode encap segs <anchor> dev eth0
        target_subnet = msg['target']
        segment_list = msg['segments'] # list of IPs
        
        segs_str = ",".join(segment_list)
        
        # 1. 清理旧路由 (简单粗暴)
        os.system(f"ip -6 route del {target_subnet} 2>/dev/null")
        
        # 2. 添加 SRv6 封装路由
        cmd = f"ip -6 route add {target_subnet} encap seg6 mode encap segs {segs_str} dev eth0"
        logging.info(f"Executing: {cmd}")
        ret = os.system(cmd)
        if ret != 0:
            logging.error("Failed to apply SRv6 route")

if __name__ == "__main__":
    # 该脚本由 Orchestrater 启动时传入参数
    # 用法: python3 node_agent.py --id 1 --role ANCHOR
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', required=True)
    parser.add_argument('--role', default='NORMAL')
    parser.add_argument('--anchor_ip', default=None)
    args = parser.parse_args()

    agent = SkyCastleAgent(args.id, args.role, args.anchor_ip)
    agent.run()
