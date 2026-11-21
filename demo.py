"""离线 demo：不连任何模型、不碰任何网络，验证 harness 的四个关键行为。

  1. 正常路径：web 题在证据满足时逐阶段推进并最终解出
  2. 循环检测：pwn 题反复给同一动作 -> 路线被杀、假设进证伪表
  3. 停滞停放：crypto 题一直拿不到里程碑 -> 被 park，把算力让出去
  4. 跨题调度：UCB 把预算从停滞题挪到推进中的题

运行：python demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from harness.blackboard import Blackboard
from harness.executor import RawResult
from harness.loop import Harness


class FakeLLM:
    """脚本化 LLM：按 role 返回固定结构，行为由 task 与阶段决定。"""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def complete(self, *, role: str, system: str, prompt: str) -> str:
        self.calls.append(role)
        if role == "route_planner":
            if "crypto" in prompt:
                return json.dumps(
                    {"routes": [{"hypothesis": "用格基约化攻击小私钥", "why": "题面给了短私钥"}]},
                    ensure_ascii=False,
                )
            if "pwn" in prompt:
                return json.dumps(
                    {"routes": [{"hypothesis": "stack smash 覆盖返回地址", "why": "无 canary"}]},
                    ensure_ascii=False,
                )
            return json.dumps(
                {"routes": [
                    {"hypothesis": "如果 login 存在布尔盲注，注入 admin'-- 会返回 200", "why": "参数直连 SQL"},
                    {"hypothesis": "如果上传只查扩展名，传 .php 会被解析", "why": "黑名单式校验"},
                ]},
                ensure_ascii=False,
            )
        if role == "task_planner":
            if "crypto" in prompt:
                return json.dumps({"subgoals": ["sagemath 建方程", "跑 LLL"]}, ensure_ascii=False)
            if "pwn" in prompt:
                return json.dumps({"subgoals": ["算偏移", "找 pop rdi  gadget"]}, ensure_ascii=False)
            return json.dumps(
                {"subgoals": ["试探注入点确认回显", "读 /etc/passwd 验证文件读取"]},
                ensure_ascii=False,
            )
        if role == "executor":
            return json.dumps(self._action_for(prompt), ensure_ascii=False)
        return "{}"

    _n = 0

    # 按阶段名给动作，而不是按关键词——prompt 里同时出现 fact key 和阶段名，
    # 靠关键词匹配会在相邻阶段之间串味。真实 LLM 不会这么脆，但桩必须确定。
    STAGE_ACTIONS = {
        "web": {
            "recon": ("curl -s -I 'http://t/'", "web_surface"),
            "vuln_localize": (
                "curl -s -w '%{http_code}' 'http://t/login?u=admin%27--'", "web_vuln"),
            "exploit": ("curl -s 'http://t/../../etc/passwd'", "web_foothold"),
            "flag": ("curl -s 'http://t/flag'", "flag"),
        },
        "pwn": {
            "reproduce": ("python3 -c 'print(0x41*64)'", "pwn_crash"),
            # 第二阶段起永远给同一个动作：验证循环检测
            "primitive": ("python3 -c 'print(0x41*64)'", "pwn_primitive"),
            "chain": ("python3 -c 'print(0x41*64)'", "pwn_chain"),
            "flag": ("python3 -c 'print(0x41*64)'", "flag"),
        },
        "crypto": {
            "model": ("sage -c 'print(1)'", "crypto_model"),
            # 同上：停在原地打转
            "attack": ("sage -c 'print(1)'", "crypto_attack"),
            "solve": ("sage -c 'print(1)'", "crypto_plaintext"),
            "flag": ("sage -c 'print(1)'", "flag"),
        },
        # misc 每题动作不同 -> 绕过循环检测（不同哈希），用来验证"空转"判据
        "misc": {
            "recon": ("file ./chal.bin", "misc_surface"),
            "hypothesis": ("strings ./chal.bin | head", "misc_hypothesis"),
            "solve": ("python3 -c 'print(2)'", "misc_solved"),
            "flag": ("python3 -c 'print(3)'", "flag"),
        },
    }

    def _action_for(self, prompt: str) -> dict:
        cat = next((c for c in self.STAGE_ACTIONS if c in prompt), "web")
        table = self.STAGE_ACTIONS[cat]
        name = next((s for s in table if f"阶段 {s}" in prompt), None)
        if name is None:
            return {"action": "", "claim": ""}
        self._n += 1
        action, claim = table[name]
        if cat == "misc":
            # 每次动作都不同（哈希不同 -> 绕过循环检测），但 claim 永远对不上当前阶段
            return {"action": f"{action} # try{self._n}", "claim": claim}
        return {"action": action, "claim": claim}


class FakeRunner:
    """假 runner：按动作返回可控结果。pwn 的动作永远"成功"但没有新证据。"""

    def __init__(self) -> None:
        self.count = 0

    def run(self, action: str, timeout: float = 120) -> RawResult:
        self.count += 1
        if "login" in action:
            return RawResult(True, "200 OK id=1 admin")
        if "/" in action and "passwd" in action:
            return RawResult(True, "root:x:0:0:root:/root:/bin/bash")
        if "flag" in action:
            return RawResult(True, "CTF{demo_flag_ok}")
        if action.startswith("curl -s -I"):
            return RawResult(True, "HTTP/1.1 200 OK\nServer: nginx\nSet-Cookie: sid=abc")
        if "sage" in action:
            return RawResult(True, "1")
        return RawResult(True, "ok")


def verifier(task_id: str, flag: str) -> bool:
    """真实比赛里换成平台判题接口。这里按格式+固定值校验。"""
    return flag.startswith("CTF{")


def _check_batch_actions() -> bool:
    """ExecutorAdapter 应把 `actions` 数组解析成多条命令，并走批量执行。"""
    from harness.executor import ExecutorAdapter

    bb = Blackboard(":memory:")
    bb.add_task("t1", "web", target="http://x/")

    class MultiLLM:
        def complete(self, *, role, system, prompt):
            if role == "executor":
                return json.dumps(
                    {
                        "actions": [{"cmd": "echo one"}, {"cmd": "echo two"}],
                        "claim": "web_surface",
                    }
                )
            return "{}"

    class BatchRunner:
        def __init__(self):
            self.batches = []

        def run_batch(self, actions, **kw):
            self.batches.append(list(actions))
            return RawResult(True, "\n".join(f"=== $ {a}\nok" for a in actions))

        def run(self, action, timeout=120):
            raise AssertionError("有 run_batch 时不应回退到串行 run()")

    runner = BatchRunner()
    ex = ExecutorAdapter(bb, MultiLLM(), runner)
    step = ex.step("t1", "摸清入口", "recon")
    return len(runner.batches) == 1 and len(runner.batches[0]) == 2 and len(step.sub_actions) == 2


def _check_async_shell() -> bool:
    """后台 job：分页可续读，长任务不在一个轮次里等死。"""
    import tempfile
    import time

    from harness.shell_bg import BackgroundShell

    sh = BackgroundShell(max_jobs=4, out_dir=tempfile.mkdtemp(prefix="demokb-"))
    try:
        # 分页
        job = sh.start("seq 1 500")
        time.sleep(0.4)
        job.refresh()
        page1, nxt = job.read(0, 5)
        page2, _ = job.read(nxt, 3)
        paged = page1.startswith("1\n2\n3") and "续读" in page1 and page2.startswith("6\n7\n8")

        # 批量并发的墙钟应远小于串行和
        t0 = time.time()
        res = sh.run_batch(
            ["sleep 0.5; echo A", "sleep 0.5; echo B", "sleep 0.5; echo C"], max_wait=10
        )
        concurrent = (time.time() - t0) < 1.2 and all(r.ok for r in res)

        # 长任务：等窗口到点就返回，不杀进程、给出可续读信号
        t0 = time.time()
        res = sh.run_batch(["sleep 30; echo late"], max_wait=0.8)
        nonblocking = (time.time() - t0) < 3.0 and (not res[0].ok) and "仍在运行" in res[0].output
        return paged and concurrent and nonblocking
    finally:
        sh.kill_all()


def _check_replenish() -> bool:
    """子目标耗尽 -> 按最新事实重拆一批（旧版会判路线枯竭）。"""
    bb = Blackboard(":memory:")
    bb.add_task("r1", "pwn", budget=600)
    rid = bb.add_route("r1", "stack smash 覆盖返回地址", stage=1)
    assert rid

    class CountLLM:
        """每次拆出的子目标都不一样，模拟真实模型看到新事实后的调整。"""

        def __init__(self):
            self.n = 0

        def complete(self, *, role, system, prompt):
            self.n += 1
            return json.dumps({"subgoals": [f"step-{self.n}-a", f"step-{self.n}-b"]})

    from harness.loop import REPLENISH_MAX
    from harness.planner import TaskPlanner

    task = bb.task("r1")
    tp = TaskPlanner(bb, CountLLM())
    # 第一批发完后立刻耗尽
    for sg in tp.decompose("r1", "stack smash 覆盖返回地址"):
        bb.add_subgoal(rid, sg)
    for r in bb.db.execute("SELECT id FROM subgoals WHERE route_id=?", (rid,)).fetchall():
        bb.close_subgoal(r["id"], True)

    h = Harness(bb, llm=CountLLM(), runner=FakeRunner(), verifier=verifier)
    h.tp = tp
    route = bb.route(rid)
    ok = h._replenish(task, route)
    todo = bb.subgoal_stats(rid)[1]

    # 封顶：连续重拆到上限后不再续命
    for _ in range(REPLENISH_MAX + 2):
        for r in bb.db.execute("SELECT id FROM subgoals WHERE route_id=?", (rid,)).fetchall():
            bb.close_subgoal(r["id"], True)
        h._replenish(task, route)
    capped = bb.replenish_count(rid) <= REPLENISH_MAX
    return ok and todo > 0 and capped


def _check_park_keeps_target() -> bool:
    """parked 状态不应触发 task_closer（靶场释放）。"""
    bb = Blackboard(":memory:")
    bb.add_task("w1", "web", budget=600)
    bb.add_task("w2", "web", budget=600)
    closed: list[str] = []

    h = Harness(
        bb,
        llm=FakeLLM(),
        runner=FakeRunner(),
        verifier=verifier,
        task_closer=closed.append,
    )
    bb.set_task("w1", status="parked")   # 停放但没结束
    bb.set_task("w2", status="expired")  # 计时耗尽，真结束
    h._close_terminal_tasks()
    return closed == ["w2"], f"parked 不应被释放，实际关闭了 {closed}"


def main() -> None:
    bb = Blackboard(":memory:")
    bb.add_task("web-01", "web", budget=600)
    bb.add_task("pwn-01", "pwn", budget=600)
    bb.add_task("crypto-01", "crypto", budget=600)
    bb.add_task("misc-01", "misc", budget=600)

    h = Harness(bb, llm=FakeLLM(), runner=FakeRunner(), verifier=verifier)
    reports = h.run(max_ticks=60)

    print(f"总共 {len(reports)} 个 tick\n")
    for r in reports:
        flag = ""
        if r.solved:
            flag = "  <<< SOLVED"
        elif r.loop:
            flag = "  <<< LOOP-KILLED"
        print(
            f"[{r.task or '-':<9}] {r.stage:<14} accepted={int(r.accepted)} "
            f"advanced={int(r.advanced)} {r.note[:48]}{flag}"
        )

    print("\n--- 终态 ---")
    for t in bb.tasks():
        print(f"{t.id:<10} status={t.status:<7} stage={t.stage} "
              f"pulls={t.pulls:<2} reward={t.reward_sum:.1f} spent={t.spent:.1f}s")

    print("\n--- 证伪表（pwn 的死路已被记住）---")
    for hyp in bb.falsified("pwn-01"):
        print("  x", hyp)

    print("\n--- 事实表（web 的推进证据）---")
    print(" ", bb.facts("web-01"))

    assert "web-01" in h.solved, "正常路径应当解出 web-01"
    assert bb.falsified("pwn-01"), "pwn-01 应当记录被证伪路线"
    # 新语义：反复打不动的题会被彻底结束（expired），而不是无限停放重试
    assert bb.task("misc-01").status == "expired", "misc-01 应被彻底结束"
    assert "放下" in bb.task("misc-01").note or "放下" in (
        bb.task("misc-01").note or ""
    ), "misc-01 的终止原因应记录放下次数"

    # ---- 新增行为：先提醒、后退役 ----
    nudged = [r for r in reports if "已提醒" in r.note]
    assert nudged, "卡塞时应先产生提醒，而不是直接退役"
    assert any("提醒已用尽" in r.note for r in reports), "提醒额度用尽后应改为放下"

    # ---- 新增行为：子目标可重拆，不因一次性 5 条用完就判枯竭 ----
    # 用专门的桩：每次拆出的子目标都不同，模拟"按最新事实重新拆"。
    # 假 LLM 全返回同一批词的话，会把重拆过滤掉（那是正确行为，不是 bug）。
    assert _check_replenish(), "子目标耗尽时应按最新事实重拆，而不是判路线枯竭"

    # ---- 新增行为：一轮可下发多条动作（批量） ----
    assert _check_batch_actions(), "ExecutorAdapter 应当解析出多条 action 并批量执行"

    # ---- 新增行为：异步 shell 分页与长任务不阻塞 ----
    assert _check_async_shell(), "后台 job 应当支持分页读与不阻塞长任务"

    # ---- 新增行为：parked 不再释放靶场 ----
    assert _check_park_keeps_target(), "park 不应触发靶场释放"

    print("\n全部断言通过。")


if __name__ == "__main__":
    main()
