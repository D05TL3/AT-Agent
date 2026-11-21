# 攻击 Agent 评测镜像
#
# 关键约束：靶场侧**不出网**。所以：
#   - 所有工具必须在这一步装好，运行时无法补装
#   - 只用标准库，不 pip install 任何东西
#   - 知识索引随镜像分发，运行时不再建库
#
# 构建：  docker build -t ctf-agent:latest .
# 自检：  docker run --rm --env-file .env ctf-agent:latest python3 agent_main.py --check

FROM python:3.11-slim-bookworm

# ---------- 基础工具 ----------
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl wget ca-certificates \
      netcat-openbsd dnsutils iputils-ping \
      nmap \
      git \
      file xxd binutils \
      gcc g++ make \
      gdb strace \
      python3-dev \
      unzip zip p7zip-full tar \
      jq \
      vim-tiny less \
      openssl \
      socat \
      vim-common \
      bc \
      perl \
      ruby \
    && rm -rf /var/lib/apt/lists/*

# ---------- 可选 CTF 工具 ----------
# 失败不阻塞构建：这些是加分项，缺了也能跑（自检会报出来）
RUN apt-get update && ( \
      apt-get install -y --no-install-recommends sqlmap ltrace || \
      echo "sqlmap/ltrace 不可用，跳过" ) \
    && rm -rf /var/lib/apt/lists/* || true

# Python 包只能在构建期装（运行期无网）。
# pexpect 是交互式题（pwn 的 canary 泄漏、自定义协议）的关键依赖，
# 缺了会让那类题整题跑不动，所以单独列出来并要求装成功。
RUN pip install --no-cache-dir \
      pwntools==4.13.1 \
      pycryptodome==3.21.0 \
      requests==2.32.3 \
      pexpect==4.9.0 \
    || echo "部分 Python 包未安装，自检会提示"

# pexpect 装不上就直接失败：它不像 pwntools 有降级路径
RUN python3 -c "import pexpect" || (echo "pexpect 缺失，交互式题无法运行" && exit 1)

# 交互式题真正能用的前提是 pty 可用；容器里若没有 /dev/pts 会退化成降级路径
RUN python3 -c "import ptyprocess; print('pty backends ok')"

# ---------- 应用 ----------
WORKDIR /app
COPY harness/ /app/harness/
COPY agent_main.py /app/
COPY knowledge/ /app/knowledge/

# 非 root 运行
RUN useradd -m -u 1000 -s /bin/bash agent \
    && mkdir -p /out /workspace \
    && chown -R agent:agent /app /out /workspace

USER agent
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OUTPUT_DIR=/out \
    BLACKBOARD_PATH=/out/blackboard.sqlite

# 健康检查用自检的退出码，但不在容器启动时自动执行——
# 评测平台拉起容器后要直接开跑，自检由人工/CI 事先触发
ENTRYPOINT ["python3", "/app/agent_main.py"]
CMD []
