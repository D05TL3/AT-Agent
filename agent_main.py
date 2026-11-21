#!/usr/bin/env python3
"""容器入口。

两种模式：

    python3 agent_main.py --check     # 自检：网关连通性、工具清单、索引、任务发现
    python3 agent_main.py             # 正式运行

自检必须在评测前跑一次。靶场侧不出网，工具装漏了 / 网关不通，
只有在启动那一刻才有机会发现——跑起来之后失败就白费一次配额。

退出码：0 成功；2 自检失败；3 任务发现失败。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import knowledge, stages
from harness.blackboard import Blackboard
from harness.controller import Controller
from harness.executor import ExecutorAdapter, ShellRunner
from harness.llm_client import MODEL as DEFAULT_MODEL
from harness.llm_client import LLMClient, LLMError
from harness.loop import Harness
from harness.platform import Platform, PlatformError
from harness.scheduler import Scheduler

# 期望存在的工具。缺哪个就报哪个，不静默。
EXPECTED_TOOLS = [
    "curl", "wget", "nc", "nmap", "python3", "gcc", "gdb",
    "strings", "file", "xxd", "tar", "unzip", "grep", "sed", "awk",
]
OPTIONAL_TOOLS = ["objdump", "readelf", "checksec", "sqlmap", "jq", "7z", "openssl"]


# ---------------------------------------------------------------- 自检
def check() -> int:
    problems: list[str] = []
    print("=" * 60)
    print("自检开始")
    print("=" * 60)

    # 1) 环境变量
    print("\n[1/5] 环境变量")
    base = os.environ.get("LLM_BASE_URL", "")
    key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)
    print(f"  LLM_BASE_URL = {base or '(未设置)'}")
    print(f"  LLM_MODEL    = {model}")
    print(f"  LLM_API_KEY  = {'已设置（' + str(len(key)) + ' 字符）' if key else '(未设置)'}")
    print(f"  BENCHMARK_BASE_URL = {'已注入' if os.environ.get('BENCHMARK_BASE_URL') else '(未注入)'}")
    print(f"  BENCHMARK_TOKEN    = {'已注入' if os.environ.get('BENCHMARK_TOKEN') else '(未注入)'}")
    if not base:
        problems.append("LLM_BASE_URL 未设置")
    if not key:
        problems.append("LLM_API_KEY 未设置")

    # 2) 网关连通性：真发一次最小请求
    print("\n[2/5] 网关连通性")
    if base and key:
        try:
            llm = LLMClient(base_url=base, max_retries=1, max_tokens=64, temperature=0.0)
            t0 = time.time()
            out = llm.complete(
                role="healthcheck",
                system="只回复 OK 两个字母。",
                prompt="ping",
            )
            print(f"  连通，延迟 {time.time() - t0:.1f}s，返回 {len(out)} 字符")
            print(f"  {llm.report()}")
        except LLMError as e:
            print(f"  失败：{e}")
            problems.append(f"网关不可用：{e}")
    else:
        print("  跳过（缺少 base_url 或 key）")

    # 3) 工具清单
    print("\n[3/5] 工具清单")
    missing = [t for t in EXPECTED_TOOLS if shutil.which(t) is None]
    absent_opt = [t for t in OPTIONAL_TOOLS if shutil.which(t) is None]
    print(f"  必需：{len(EXPECTED_TOOLS) - len(missing)}/{len(EXPECTED_TOOLS)} 就绪")
    if missing:
        print(f"  缺失必需工具：{', '.join(missing)}")
        problems.append(f"缺少必需工具：{', '.join(missing)}")
    if absent_opt:
        print(f"  缺少可选工具（不影响启动）：{', '.join(absent_opt)}")

    # pexpect 是交互式题（pwn 的 canary 泄漏、自定义协议）的关键依赖，
    # 缺了不影响大部分题，但会让那类题整题跑不动，所以要显式报出来。
    try:
        import pexpect  # noqa: F401

        print("  交互式执行：pexpect 可用")
    except ImportError:
        print("  交互式执行：pexpect 缺失（pwn/协议类题会退化，建议补装）")

    # 4) 知识索引
    print("\n[4/5] 知识索引")
    idx = knowledge._index()
    if idx is None:
        print("  未找到索引，将只使用手写条目（kb.json）")
    else:
        print(f"  已加载 {idx.size} 块")
    print(f"  must 格子数：{len(knowledge.MUST)}")

    # 5) 任务发现
    print("\n[5/5] 任务发现")
    try:
        pf = Platform()
        if pf.output_error:
            print(f"  注意：{pf.output_error}")
            print(f"  已回退到 {pf.output_dir}（容器内不会发生，主机调试时才这样）")
        tasks = pf.load_tasks()
        print(f"  发现 {len(tasks)} 道题：")
        for t in tasks[:20]:
            print(
                f"    - {t.id:<20} 类型={t.category:<9} 时限={t.budget:.0f}s"
                f" 目标={t.target or '(启动时获取)'}"
            )
        if len(tasks) > 20:
            print(f"    … 另有 {len(tasks) - 20} 道")
        print(f"  答题 API：已连接  活动靶场上限：{pf.MAX_ACTIVE_CHALLENGES}  输出目录：{pf.output_dir}")
    except PlatformError as e:
        print(f"  失败：{e}")
        problems.append(str(e))

    print("\n" + "=" * 60)
    if problems:
        print(f"自检失败，{len(problems)} 个问题：")
        for p in problems:
            print(f"  ✗ {p}")
        return 2
    print("自检通过")
    return 0


# ---------------------------------------------------------------- 缓存探测
def probe_cache() -> int:
    """探测网关是否透传前缀缓存字段。

    为什么单独做这一步：fork 多分支的收益完全建立在「分支共享前缀、缓存命中近免费」
    上（参考实现在 deepseek-flash 实测首请求 99.2% 命中）。如果网关不透传
    prompt_cache_hit_tokens，那条收益就无从验证，fork 的性价比要重新评估。

    做法：发两次**完全相同**的长前缀请求，第二次理论上前缀应全部命中。
    """
    base = os.environ.get("LLM_BASE_URL", "")
    key = os.environ.get("LLM_API_KEY", "")
    if not base or not key:
        print("[FATAL] 需要 LLM_BASE_URL 与 LLM_API_KEY", file=sys.stderr)
        return 2

    llm = LLMClient(
        base_url=base,
        model=os.environ.get("LLM_MODEL", DEFAULT_MODEL),
        max_tokens=32,
        temperature=0.0,
        verbose=True,
    )
    filler = (
        "你是渗透测试规划器。以下是操作规范：" + "不要重复已证伪的假设；" * 300
    )
    print("第一次请求（建立缓存）…")
    llm.complete(role="cache_probe_1", system=filler, prompt="回复 OK")
    time.sleep(2.0)  # 缓存构建是秒级
    print("第二次请求（同前缀，应命中）…")
    llm.complete(role="cache_probe_2", system=filler, prompt="回复 OK")

    print("\n" + llm.report())
    rate = llm.stats.cache_rate
    if rate is None:
        print("\n结论：网关**未透传**缓存字段。fork 多分支的收益无法确认，先别开。")
        return 1
    print(f"\n结论：缓存字段可用，第二次请求命中率 {rate:.1%}。")
    if rate < 0.5:
        print("命中率偏低：网关可能改写了前缀（例如注入了时间戳/请求 id），fork 前要先查清。")
        return 1
    return 0


# ---------------------------------------------------------------- 正式运行
def run() -> int:
    base = os.environ.get("LLM_BASE_URL", "")
    key = os.environ.get("LLM_API_KEY", "")
    if not base or not key:
        print("[FATAL] 缺少 LLM_BASE_URL 或 LLM_API_KEY", file=sys.stderr)
        return 2

    pf = Platform()
    try:
        specs = pf.load_tasks()
    except PlatformError as e:
        print(f"[FATAL] 任务发现失败：{e}", file=sys.stderr)
        return 3

    llm = LLMClient(
        base_url=base,
        model=os.environ.get("LLM_MODEL", DEFAULT_MODEL),
        max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "4096")),
        temperature=float(os.environ.get("LLM_TEMPERATURE", "0.6")),
        verbose=os.environ.get("AGENT_VERBOSE", "0") == "1",
    )

    bb = Blackboard(os.environ.get("BLACKBOARD_PATH", "/out/blackboard.sqlite"))
    for s in specs:
        bb.add_task(
            s.id,
            s.category,
            budget=s.budget,
            points=s.points,
            solves=s.solves,
            target=s.target,
            brief=s.description,
        )
        if s.is_completed:
            bb.set_task(s.id, status="solved", note="平台已显示本题全部 flag 完成")

    # ---- 活动靶场名额：LRU 释放，而不是"一停就关" ----
    # 平台的限制是"同时最多 3 个存活容器"，不是"只能在 3 道题上花时间"。
    # 所以名额由 LRU 管理：开新的之前先关掉最久没碰的那道，parked 题保留容器。
    last_touch: dict[str, float] = {}
    _slot_lock = threading.Lock()

    def _touch(task_id: str) -> None:
        last_touch[task_id] = time.time()

    def _evict_for_slot(task_id: str) -> None:
        """腾一个名额给 task_id。

        释放顺序（这条顺序是踩过大坑的）：

          1. **绝不释放正在推进的题**（PROBING）——它们占着名额是应该的，
             挤掉它们等于把已经投入的侦察成本扔掉，而且下一波又会被重新选中，
             表现为「一直开关容器、不做题」。
          2. 优先释放 `parked`（打不动、被放下）——它们本来就没在跑。
          3. 其次是 `open`（还没探测过、只是挂了名）。

        如果没有任何可释放的题，就**不释放**，让调用方拿到名额不足的错误
        并在日志里说明——这比默默把正在推进的题踢掉要好。
        """
        with _slot_lock:
            while len(pf.active_tasks()) >= pf.MAX_ACTIVE_CHALLENGES:
                if task_id in pf.active_tasks():
                    return  # 它自己已经占着名额，不需要腾位
                holders = [x for x in pf.active_tasks() if x != task_id]

                def rank(x: str) -> tuple[int, float]:
                    st = bb.task(x).status
                    # parked=0 最先释放；open=1；PROBING/solved/expired 不释放（给 99）
                    pri = {"parked": 0, "open": 1}.get(st, 99)
                    return (pri, last_touch.get(x, 0.0))

                holders.sort(key=rank)
                victims = [x for x in holders if rank(x)[0] < 99]
                if not victims:
                    print(
                        f"[SLOT] 名额已满且无 parked/open 题可释放，{task_id} 本轮跳过",
                        flush=True,
                    )
                    return
                victim = victims[0]
                print(
                    f"[SLOT] 名额已满，释放 {bb.task(victim).status} 题目 {victim}"
                    f"（{len(pf.active_tasks())}/{pf.MAX_ACTIVE_CHALLENGES}）",
                    flush=True,
                )
                pf.close_task(victim)
                last_touch.pop(victim, None)

    def start_task(task_id: str) -> None:
        _evict_for_slot(task_id)
        addresses = pf.start_task(task_id)
        _touch(task_id)
        if addresses:
            bb.set_task(task_id, target=", ".join(addresses))

    def verifier(task_id: str, flag: str):
        return pf.submit_flag(task_id, flag)

    runner = ShellRunner(
        timeout=int(os.environ.get("TOOL_TIMEOUT", "120")),
        max_jobs=int(os.environ.get("AGENT_MAX_JOBS", "8")),
        job_timeout=float(os.environ.get("AGENT_JOB_TIMEOUT", "1800")),
    )

    harness = Harness(
        bb,
        llm=llm,
        runner=runner,
        verifier=verifier,
        scheduler=Scheduler(bb, min_stage_seconds=float(os.environ.get("MIN_STAGE_SECONDS", "90"))),
        controller=Controller(
            bb,
            verifier,
            flag_stall_sec=float(os.environ.get("AGENT_FLAG_STALL_SEC", "900")),
            nudge_max=int(os.environ.get("AGENT_NUDGE_MAX", "2")),
        ),
        executor=ExecutorAdapter(
            bb, llm, runner, max_actions=int(os.environ.get("AGENT_MAX_ACTIONS", "4"))
        ),
        task_starter=start_task,
        task_closer=pf.close_task,
        max_active=pf.MAX_ACTIVE_CHALLENGES,
    )

    configured_width = int(os.environ.get("AGENT_WIDTH", "3"))
    width = max(1, min(configured_width, pf.MAX_ACTIVE_CHALLENGES))
    max_waves = int(os.environ.get("AGENT_MAX_WAVES", "400"))
    if width != configured_width:
        print(
            f"[RUN] AGENT_WIDTH 从 {configured_width} 限制为 {width}（平台活动靶场上限）",
            flush=True,
        )
    print(f"[RUN] {len(specs)} 道题，宽度 {width}，最多 {max_waves} 波", flush=True)
    t0 = time.time()
    try:
        harness.wave(width=width, max_waves=max_waves)
    except Exception:
        print("[FATAL] 运行异常：", file=sys.stderr)
        traceback.print_exc()
    finally:
        pf.close_active_tasks()

    elapsed = time.time() - t0
    solved = [t.id for t in bb.tasks() if t.status == "solved"]

    print("\n" + "=" * 60, flush=True)
    print(f"[DONE] 用时 {elapsed:.0f}s，解出 {len(solved)}/{len(specs)}：{solved}", flush=True)
    print(llm.report(), flush=True)

    pf.write_summary(
        {
            "elapsed_s": elapsed,
            "total": len(specs),
            "solved": solved,
            "tasks": [
                {
                    "id": t.id,
                    "status": t.status,
                    "stage": t.stage,
                    "points": t.points,
                    "facts": bb.facts(t.id),
                }
                for t in bb.tasks()
            ],
            "llm": {
                "calls": llm.stats.calls,
                "failures": llm.stats.failures,
                "prompt_tokens": llm.stats.prompt_tokens,
                "completion_tokens": llm.stats.completion_tokens,
                "reasoning_tokens": llm.stats.reasoning_tokens,
                "credit": llm.stats.credit,
            },
        }
    )
    for t in bb.tasks():
        pf.write_trajectory(t.id, _trajectory(bb, t.id))
    return 0


def _trajectory(bb: Blackboard, task_id: str) -> list[dict]:
    """导出该题的动作序列，供赛后核对预期解。"""
    rows = bb.db.execute(
        "SELECT a_hash, action, ok, result, ts FROM attempts WHERE task_id=? ORDER BY id",
        (task_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只做自检，不跑题")
    ap.add_argument(
        "--probe-cache",
        action="store_true",
        help="探测网关是否透传前缀缓存（决定是否值得上 fork 多分支）",
    )
    args = ap.parse_args()
    if args.check:
        return check()
    if args.probe_cache:
        return probe_cache()
    return run()


if __name__ == "__main__":
    sys.exit(main())
