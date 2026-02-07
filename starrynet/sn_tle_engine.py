from sgp4.api import Satrec, jday, WGS84
import numpy as np
import math

class TLEEngine:
    def __init__(self, tle_file_path):
        self.satellites = []
        with open(tle_file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        # 解析 TLE
        for i in range(0, len(lines), 3):
            if i+2 >= len(lines): break
            name = lines[i]
            l1, l2 = lines[i+1], lines[i+2]
            
            # 提取轨道参数用于分组
            raan = float(l2[17:25])
            ma = float(l2[43:51]) # 平近点角，用于同轨排序
            
            self.satellites.append({
                'satrec': Satrec.twoline2rv(l1, l2),
                'name': name,
                'id': i // 3 + 1, # StarryNet ID 从 1 开始
                'raan': raan,
                'ma': ma
            })
            
        print(f"[TLEEngine] Loaded {len(self.satellites)} satellites.")

    def get_all_positions(self, time_index):
        """返回 time_index 时刻所有卫星的 (x, y, z) 坐标 (km)"""
        # 设定基准时间 (例如 2025-01-01 12:00:00)
        jd_base, fr_base = jday(2025, 1, 1, 12, 0, 0)
        fr_current = fr_base + time_index / 86400.0
        
        positions_xyz = []
        for sat in self.satellites:
            e, r, v = sat['satrec'].sgp4(jd_base, fr_current)
            if e != 0: r = (0,0,0)
            positions_xyz.append(r)
            
        return positions_xyz
