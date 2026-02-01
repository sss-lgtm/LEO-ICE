#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
按显式映射把链网节点文件注入 StarryNet 容器并启动 Java 进程。
"""

import argparse
import json
import os
import posixpath
import sys
from typing import Dict, List, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from starrynet.sn_utils import sn_init_remote_machine


def read_json(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_remote_cmd(ssh, cmd: str) -> Tuple[int, str, str]:
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    return exit_code, out.strip(), err.strip()


def shell_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


def remote_exists(ssh, path: str) -> bool:
    code, _, _ = run_remote_cmd(ssh, f"test -e {shell_quote(path)}")
    return code == 0


def ensure_container_exists(ssh, container_name: str) -> bool:
    code, _, _ = run_remote_cmd(
        ssh,
        f"docker inspect {shell_quote(container_name)} >/dev/null 2>&1"
    )
    return code == 0


def copy_if_exists(
    ssh,
    host_path: str,
    container_name: str,
    container_path: str,
    required: bool
) -> Tuple[bool, str]:
    if not remote_exists(ssh, host_path):
        if required:
            return False, f"必需路径不存在: {host_path}"
        return True, f"可选路径不存在，已跳过: {host_path}"

    # 目录复制时使用 "/."，避免在容器内多嵌套一层目录
    source_expr = host_path
    is_dir_code, _, _ = run_remote_cmd(ssh, f"test -d {shell_quote(host_path)}")
    if is_dir_code == 0:
        source_expr = host_path.rstrip("/") + "/."

    code, _, err = run_remote_cmd(
        ssh,
        f"docker cp {shell_quote(source_expr)} {shell_quote(container_name + ':' + container_path)}"
    )
    if code != 0:
        return False, f"复制失败: {host_path} -> {container_name}:{container_path}，错误: {err}"
    return True, f"复制成功: {host_path} -> {container_name}:{container_path}"


def check_java_running(ssh, container_name: str, jar_name: str) -> bool:
    inner = "pgrep -f " + shell_quote(jar_name) + " >/dev/null"
    code, _, _ = run_remote_cmd(
        ssh,
        "docker exec " + shell_quote(container_name) +
        " sh -lc " + shell_quote(inner)
    )
    return code == 0


def stop_java_if_running(ssh, container_name: str, jar_name: str) -> Tuple[bool, str]:
    inner = "pkill -f " + shell_quote(jar_name) + " || true"
    code, _, err = run_remote_cmd(
        ssh,
        "docker exec " + shell_quote(container_name) +
        " sh -lc " + shell_quote(inner)
    )
    if code != 0:
        return False, f"停止旧进程失败: {err}"
    return True, "已尝试停止旧进程"


def start_java(
    ssh,
    container_name: str,
    jar_name: str,
    java_opts: str
) -> Tuple[bool, str]:
    run_cmd = (
        "cd /opt/app && "
        "mkdir -p /opt/app/logs /opt/app/dump && "
        f"nohup java {java_opts} -jar ./bin/{jar_name} "
        ">/opt/app/logs/chain-node.log 2>&1 &"
    )
    code, _, err = run_remote_cmd(
        ssh,
        "docker exec -d " + shell_quote(container_name) +
        " sh -lc " + shell_quote(run_cmd)
    )
    if code != 0:
        return False, f"启动命令执行失败: {err}"

    if not check_java_running(ssh, container_name, jar_name):
        return False, "启动命令已执行，但未检测到 Java 进程"

    return True, "Java 进程已启动"


def resolve_targets(config: Dict) -> List[str]:
    container_map = config.get("container_map", {})
    targets = config.get("start_targets", [])
    if not targets:
        return list(container_map.keys())
    return [name for name in targets if name in container_map]


def build_node_path(host_nodes_root: str, node_id: str, rel_path: str) -> str:
    rel = rel_path.strip().strip("/")
    if not rel:
        return posixpath.join(host_nodes_root, node_id)
    return posixpath.join(host_nodes_root, node_id, rel)


def load_remote_auth(project_root: str) -> Dict:
    cfg_path = os.path.join(project_root, "config.json")
    cfg = read_json(cfg_path)
    return {
        "ip": cfg["remote_machine_IP"],
        "username": cfg["remote_machine_username"],
        "password": cfg["remote_machine_password"],
    }


def process_container(ssh, config: Dict, container_name: str) -> Tuple[bool, List[str]]:
    logs: List[str] = []
    container_map = config["container_map"]
    node_id = container_map[container_name]
    host_nodes_root = config["host_nodes_root"]
    paths = config.get("paths", {})
    java_opts = config.get("java_opts", "")
    jar_name = config.get("jar_name", "raychain-node-5.0.jar")
    restart_if_running = bool(config.get("restart_if_running", False))

    if not ensure_container_exists(ssh, container_name):
        return False, [f"容器不存在: {container_name}"]

    code, _, err = run_remote_cmd(
        ssh,
        "docker exec " + shell_quote(container_name) +
        " sh -lc " + shell_quote("mkdir -p /opt/app/bin /opt/app/cfg /opt/app/cert /opt/app/data /opt/app/logs /opt/app/dump")
    )
    if code != 0:
        return False, [f"容器目录初始化失败: {err}"]

    cfg_src = build_node_path(host_nodes_root, node_id, paths.get("cfg", "cfg"))
    cert_src = build_node_path(host_nodes_root, node_id, paths.get("cert", "cert"))
    data_src = build_node_path(host_nodes_root, node_id, paths.get("data", "data"))
    jar_src = build_node_path(host_nodes_root, node_id, paths.get("jar", "env/node/raychain-node-5.0.jar"))

    ok, msg = copy_if_exists(ssh, cfg_src, container_name, "/opt/app/cfg", required=True)
    logs.append(msg)
    if not ok:
        return False, logs

    ok, msg = copy_if_exists(ssh, cert_src, container_name, "/opt/app/cert", required=True)
    logs.append(msg)
    if not ok:
        return False, logs

    ok, msg = copy_if_exists(ssh, data_src, container_name, "/opt/app/data", required=False)
    logs.append(msg)
    if not ok:
        return False, logs

    ok, msg = copy_if_exists(ssh, jar_src, container_name, f"/opt/app/bin/{jar_name}", required=False)
    logs.append(msg)
    if not ok:
        return False, logs

    already_running = check_java_running(ssh, container_name, jar_name)
    if already_running and not restart_if_running:
        logs.append("检测到 Java 已在运行，按配置跳过重启")
        return True, logs

    if already_running and restart_if_running:
        ok, msg = stop_java_if_running(ssh, container_name, jar_name)
        logs.append(msg)
        if not ok:
            return False, logs

    ok, msg = start_java(ssh, container_name, jar_name, java_opts)
    logs.append(msg)
    return ok, logs


def main() -> int:
    parser = argparse.ArgumentParser(description="按映射注入并启动链网节点")
    parser.add_argument(
        "--config",
        default=os.path.join(PROJECT_ROOT, "starrynet", "blockchain_deploy_config.json"),
        help="部署映射配置文件路径"
    )
    args = parser.parse_args()

    config = read_json(args.config)
    for key in ["host_nodes_root", "container_map"]:
        if key not in config:
            print(f"配置缺少必填字段: {key}")
            return 2

    targets = resolve_targets(config)
    if not targets:
        print("未找到可启动容器，请检查 start_targets 或 container_map")
        return 2

    auth = load_remote_auth(PROJECT_ROOT)
    ssh, transport = sn_init_remote_machine(auth["ip"], auth["username"], auth["password"])

    success_count = 0
    fail_count = 0

    try:
        for container_name in targets:
            print(f"\n[处理容器] {container_name}")
            ok, logs = process_container(ssh, config, container_name)
            for line in logs:
                print(f"  - {line}")
            if ok:
                success_count += 1
                print("  - 状态: 成功")
            else:
                fail_count += 1
                print("  - 状态: 失败")
    finally:
        try:
            transport.close()
        except Exception:
            pass
        try:
            ssh.close()
        except Exception:
            pass

    print("\n[汇总]")
    print(f"成功容器数: {success_count}")
    print(f"失败容器数: {fail_count}")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
