# -*- coding: utf-8 -*-
import json
import networkx as nx
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='[SkyCastle] %(message)s')

class SkyCastleController:
    def __init__(self, config_path="./config.json"):
        self.load_config(config_path)
        
        # 存储分簇结果
        # satellite_id -> cluster_id
        self.sat_to_cluster = {}
        # cluster_id -> anchor_id
        self.cluster_anchors = {}
        
        # 论文中的延迟约束 H (跳数阈值)
        # 这里根据星座规模动态设定，通常为直径的 1/4 或固定值
        # Starlink 规模很大，但你的 config 只有 5x5，所以我们设小一点
        self.H_radius = max(2, (self.orbit_num + self.sat_num) // 4)
        
        logging.info(f"Initialized SkyCastle Controller. Topology: {self.orbit_num}x{self.sat_num}, H_radius: {self.H_radius}")

    def load_config(self, path):
        try:
            with open(path, 'r') as f:
                conf = json.load(f)
            # 适配你的 config.json 键名
            self.sat_num = int(conf.get("# of satellites", 11))  # 每轨道卫星数
            self.orbit_num = int(conf.get("# of orbit", 66))     # 轨道数
            self.total_sats = self.sat_num * self.orbit_num
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            # 默认回退值，防止报错
            self.sat_num = 5
            self.orbit_num = 5
            self.total_sats = 25

    def get_hop_distance(self, sat1, sat2):
        """
        计算 Grid 拓扑下的曼哈顿距离 (Manhattan Distance)
        考虑了极地跨轨道连接和轨道内环形连接
        """
        # 计算轨道编号 (orbit) 和 轨道内编号 (idx)
        # 假设编号方式是：0 ~ sat_num-1 是轨道0，sat_num ~ 2*sat_num-1 是轨道1...
        o1, s1 = divmod(sat1, self.sat_num)
        o2, s2 = divmod(sat2, self.sat_num)

        # 1. 轨道间距离 (左右相邻，注意圆柱体拓扑通常左右不相连，但 StarryNet Grid 视情况而定)
        # 这里假设左右不循环 (0 和 orbit_num-1 不连)，只计算绝对差值
        # 如果是圆柱体(Starlink)，可以用 min(abs(o1-o2), self.orbit_num - abs(o1-o2))
        dist_orbit = min(abs(o1 - o2), self.orbit_num - abs(o1 - o2))
        
        # 2. 轨道内距离 (上下相邻，通常是环形)
        dist_sat = min(abs(s1 - s2), self.sat_num - abs(s1 - s2))

        return dist_orbit + dist_sat

    def compute_clusters(self):
        """
        核心算法：贪心策略进行分簇
        对应论文 Algorithm 2: Anchor Deployment and Cluster Division
        """
        self.sat_to_cluster = {}
        self.cluster_anchors = {}
        
        # 标记数组
        assigned = [False] * self.total_sats
        cluster_id_counter = 0

        # 遍历所有卫星，优先为未分配的卫星建立 Cluster
        for sat_id in range(self.total_sats):
            if assigned[sat_id]:
                continue

            # --- 步骤 1: 选举 Anchor ---
            # 在未覆盖区域选一个点作为 Anchor (这里简单选当前点，优化算法可以选择中心度最高的点)
            current_anchor = sat_id
            current_cluster_id = cluster_id_counter
            
            # 记录 Anchor 信息
            self.cluster_anchors[current_cluster_id] = current_anchor
            
            # Anchor 自己首先加入 Cluster
            self.sat_to_cluster[current_anchor] = current_cluster_id
            assigned[current_anchor] = True
            
            cluster_members = [current_anchor]

            # --- 步骤 2: 扫描成员 ---
            # 找到所有距离 Anchor <= H 的未分配卫星加入该 Cluster
            for candidate in range(self.total_sats):
                if assigned[candidate]:
                    continue
                
                dist = self.get_hop_distance(current_anchor, candidate)
                if dist <= self.H_radius:
                    self.sat_to_cluster[candidate] = current_cluster_id
                    assigned[candidate] = True
                    cluster_members.append(candidate)
            
            logging.info(f"Created Cluster {current_cluster_id}: Anchor={current_anchor}, Members={len(cluster_members)}")
            cluster_id_counter += 1

        logging.info(f"Clustering Complete. Total Clusters: {len(self.cluster_anchors)}")
        return self.sat_to_cluster, self.cluster_anchors

    def get_anchor_for_sat(self, sat_id):
        """
        查询接口：给定一个卫星 ID，返回它所属的 Anchor ID
        """
        # 1. 找到它属于哪个 Cluster
        c_id = self.sat_to_cluster.get(sat_id)
        if c_id is None:
            # 兜底：如果没覆盖到，自己做自己的 Anchor
            return sat_id
            
        # 2. 返回该 Cluster 的 Anchor
        return self.cluster_anchors[c_id]

    def id_to_ip(self, sat_id):
        """
        辅助工具：将卫星 ID 转换为 StarryNet 风格的 IP
        假设 StarryNet IP 规则: 10.x.y.z
        你需要根据 orchestrater 中的规则修改这里
        """
        # 示例转换，实际需配合 sn_orchestrater 的 IP 分配逻辑
        return f"10.0.{sat_id}.1"

# === 本地测试代码 ===
if __name__ == "__main__":
    # 模拟运行
    ctrl = SkyCastleController("./config.json")
    clusters, anchors = ctrl.compute_clusters()
    
    # 打印前 5 个卫星的归属
    for i in range(min(5, ctrl.total_sats)):
        anchor = ctrl.get_anchor_for_sat(i)
        print(f"Sat {i} -> Cluster {clusters.get(i)} -> Anchor {anchor}")
