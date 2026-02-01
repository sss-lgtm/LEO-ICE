# 基础镜像
FROM ubuntu:20.04

# 非交互安装
ENV DEBIAN_FRONTEND=noninteractive

# 修复部分环境下 dpkg 排除配置导致的安装异常
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes

# 切换系统源并安装仿真与区块链运行依赖
RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    echo '#!/bin/sh' > /usr/sbin/policy-rc.d && \
    echo 'exit 101' >> /usr/sbin/policy-rc.d && \
    chmod +x /usr/sbin/policy-rc.d && \
    apt-get update && apt-get install -y \
    bird2 \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    iperf \
    iperf3 \
    traceroute \
    curl \
    vim \
    nano \
    python3 \
    python3-pip \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
RUN pip3 install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ \
    flask \
    requests \
    numpy \
    networkx

# 预创建运行目录
RUN mkdir -p /run/bird /opt/app/bin /opt/app/cfg /opt/app/cert /opt/app/data /opt/app/dump /opt/app/logs

# 内置默认链节点 jar，支持后续按节点覆盖
COPY /data/chain-net/zero_node/env/node/raychain-node-5.0.jar /opt/app/bin/raychain-node-5.0.jar

# 保持容器常驻，链节点由外部脚本按需拉起
CMD ["tail", "-f", "/dev/null"]
