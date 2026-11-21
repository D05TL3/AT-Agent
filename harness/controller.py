"""Controller：证据闸门 + 阶段推进 + 循环/停滞检测。

对应论文的 controller（只接受有运行时证据的进展），并按改动 4 加严：
flag 必须是验证器确认过的，模型自称成功一律不算。
这些判断全部在 Python 里做，不依赖模型自觉——这是本文档里最不该交给 LLM 的部分。
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from . import stages
from .blackboard import Blackboard, action_hash

FLAG_RE = re.compile(r"[A-Za-z0-9_]{1,16}\{[^}\s]{4,}\}")

# 证据强度：数值越高越可信。text 是最弱的一档，只有带工件才行。
STRENGTH = {"exit_code": 1, "stdout_excerpt": 2, "artifact": 3, "verifier": 4}


@dataclass
class Evidence:
    claim: str                      # 模型主张达成的里程碑 fact key
    kind: str                       # exit_code|stdout_excerpt|artifact|verifier
    detail: str = ""                # 摘录 / 路径 / 说明
    exit_ok: bool = True
    flag: str | None = None
    facts: dict[str, str] = field(default_factory=dict)


@dataclass
class Decision:
    accepted: bool
    advanced: bool
    reason: str
    solved: bool = False
    loop: bool = False


@dataclass
class StallSignals:
    """卡塞信号集合。`count` 是题级四信号的成立数，`flag_stall` 单独一票。"""

    flag_stall: bool = False
    stall: bool = False
    repeat: bool = False
    hard_fail: bool = False
    wrong_submit: bool = False
    count: int = 0
    idle_sec: float = 0.0


@dataclass(frozen=True)
class FlagResult:
    accepted: bool
    completed: bool
    correct_flag_count: int = 0
    total_flag_count: int = 0
    message: str = ""


class Controller:
    def __init__(
        self,
        bb: Blackboard,
        verifier: Callable[[str, str], bool | FlagResult] | None = None,
        loop_limit: int = 3,
        *,
        window: int = 4,
        flag_stall_sec: float = 900.0,
        nudge_max: int = 2,
    ) -> None:
        self.bb = bb
        self.verifier = verifier
        self.loop_limit = loop_limit
        self.window = window
        self.flag_stall_sec = flag_stall_sec
        self.nudge_max = nudge_max
        self._nudges: dict[str, int] = {}

    # ---------- 证据闸门 ----------
    def judge(self, task_id: str, ev: Evidence) -> Decision:
        t = self.bb.task(task_id)
        stage = stages.stage(t.category, t.stage)

        if ev.kind not in STRENGTH:
            return Decision(False, False, f"未知证据类型 {ev.kind}")
        if ev.kind == "exit_code" and not ev.exit_ok:
            return Decision(False, False, "命令非零退出，不构成进展")
        if ev.kind == "exit_code":
            return Decision(False, False, "进展需要 stdout 摘录或工件，不能只靠退出码")

        # 情形 A：模型直接给出了当前阶段的 milestone 键 -> 推进
        if ev.claim == stage.requires and stage.requires != "flag":
            return self._record_and_maybe_advance(task_id, ev)

        # 情形 B：flag 阶段只认验证过的 flag
        if stage.requires == "flag":
            if ev.claim == "flag" or ev.flag:
                return self._judge_flag(task_id, ev)
            return Decision(False, False, "flag 阶段只接受经验证器确认的 flag")

        # 情形 C：模型自造了一个中间事实名（实测中这是最常见的情况）。
        # 允许它作为"过程事实"入库，但**不推进阶段**；同时检查该阶段已有的
        # 过程事实里是否已经有人拿到了 milestone。
        return self._record_process_fact(task_id, ev, stage)

    def _record_process_fact(self, task_id: str, ev: Evidence, stage) -> Decision:
        """记录过程事实。

        模型不一定会用我们规定的 milestone 名字，硬要求精确匹配会把大量
        有效侦察判成失败（实测 4/4 全拒，然后误判停滞）。所以这里放宽两步：

          1. 凡是带 stdout 摘录的事实都当作真实进展入库，收益照算；
          2. 若该事实名恰好是别的阶段的 milestone 键，视为"答非所问"但仍记录，
             不推进——防止模型用错名字骗推进。
        """
        name = (ev.claim or "").strip()
        if not name:
            return Decision(False, False, "证据未标注 claim，无法入库")

        milestones = stages.milestone_keys()
        if name in milestones:
            # 用了 milestone 名字但不对应当前阶段：记录但不推进
            self.bb.add_fact(task_id, name, ev.detail or "1", ev.detail, verified=False)
            return Decision(
                False, False, f"{name} 是别的阶段的里程碑，已记录但不推进"
            )

        changed = self.bb.add_fact(task_id, name, ev.detail or "1", ev.detail, verified=True)
        for k, v in ev.facts.items():
            changed |= self.bb.add_fact(task_id, k, v, verified=True)
        if not changed:
            return Decision(False, False, f"过程事实 {name} 无变化，不算新进展")
        # 过程事实算"接受"（有收益），但阶段不动
        return Decision(True, False, f"过程事实 {name} 已记录")

    def _record_and_maybe_advance(self, task_id: str, ev: Evidence) -> Decision:
        changed = self.bb.add_fact(
            task_id, ev.claim, ev.detail or "1", evidence=ev.detail, verified=True
        )
        for k, v in ev.facts.items():
            changed |= self.bb.add_fact(task_id, k, v, verified=True)
        if not changed:
            return Decision(False, False, "事实已存在且未变化，不算新进展")
        return self._advance(task_id, f"milestone {ev.claim} 满足")

    def _judge_flag(self, task_id: str, ev: Evidence) -> Decision:
        if not ev.flag or not FLAG_RE.search(ev.flag):
            return Decision(False, False, "未提供格式合法的 flag")
        flag = FLAG_RE.search(ev.flag).group(0)
        if self.verifier is None:
            return Decision(False, False, "没有配置验证器，flag 不可提交")
        try:
            result = self.verifier(task_id, flag)
        except Exception as e:
            return Decision(False, False, f"验证器异常：{type(e).__name__}: {e}")

        if isinstance(result, FlagResult):
            accepted = result.accepted
            completed = result.completed
            message = result.message or "平台已返回 flag 判定"
            count = result.correct_flag_count
            total = result.total_flag_count
        else:
            # Keep compatibility with simple boolean verifiers used by the offline demo.
            accepted = bool(result)
            completed = accepted
            message = "flag 已验证"
            count = total = 0

        if not accepted:
            return Decision(False, False, message or "验证器拒绝该 flag")

        key = "flag_" + hashlib.sha256(flag.encode("utf-8")).hexdigest()[:12]
        changed = self.bb.add_fact(task_id, key, flag, evidence="verifier", verified=True)
        if completed:
            self.bb.set_task(task_id, status="solved")
            self.bb.add_fact(task_id, "flag", flag, evidence="verifier", verified=True)
            return Decision(True, True, f"{message}；本题所有 flag 已完成", solved=True)
        if not changed:
            return Decision(False, False, f"flag 已验收但未增加新进度（{count}/{total}）")
        progress = f"（{count}/{total}）" if total else ""
        return Decision(True, False, f"{message}{progress}")

    def _advance(self, task_id: str, why: str) -> Decision:
        t = self.bb.task(task_id)
        if stages.is_last(t.category, t.stage):
            return Decision(True, False, why)
        self.bb.set_task(task_id, stage=t.stage + 1)
        return Decision(True, True, why)

    # ---------- 循环与停滞 ----------
    def check_loop(self, task_id: str, a_hash: str, route_id: int | None) -> bool:
        """同一动作重复超过阈值：杀掉这条路线并把假设记进证伪表。"""
        if not self.bb.repeated(task_id, a_hash, self.loop_limit):
            return False
        if route_id is not None:
            row = self.bb.route(route_id)
            if row and row["status"] == "live":
                self.bb.set_route(route_id, "dead")
                self.bb.add_falsified(
                    task_id, row["hypothesis"], f"动作重复 {self.loop_limit} 次无进展"
                )
        return True

    # ---------- 停滞：五信号 + 分级干预 ----------
    def signals(self, task_id: str, last_accepted: bool) -> StallSignals:
        """程序侧卡塞信号，零 LLM 成本。

        参考实现在线上跑出来的一条教训很值得记：一道题连续 28 轮里反复使用同一个
        凭据 146 处、却 0 次写黑板——工具链没坏，是模型压根没想到要记录。这类
        "看起来在干活、实际原地打转"的情况，单一"连续 N 次没进展"判据会误杀，
        因为中间确实有成功的命令。所以这里用多信号组合。
        """
        t = self.bb.task(task_id)
        rows = self.bb.db.execute(
            "SELECT a_hash, action, ok, result, ts FROM attempts "
            "WHERE task_id=? ORDER BY id DESC LIMIT ?",
            (task_id, self.window),
        ).fetchall()

        # ① 题级主时钟：很久没有新的 flag（一票触发，且与是否"看起来有进展"无关）。
        # 基准取 max(开工时刻, 最后一次拿到 flag 的时刻)；不能用 t.spent——
        # 它只在 charge() 里累加，主循环并不会调用，永远是 0。
        last_flag_ts = self._last_flag_ts(task_id)
        anchor = max(t.started_at or 0.0, last_flag_ts or 0.0) or time.time()
        flag_since = time.time() - anchor
        flag_stall = flag_since >= self.flag_stall_sec

        # ② 停滞：最近 window 次动作都没换来接受
        stall = (not last_accepted) and len(rows) >= self.window

        # ③ 命令重复：同一规范化动作近期出现 ≥3 次
        seen: dict[str, int] = {}
        for r in rows:
            seen[r["a_hash"]] = seen.get(r["a_hash"], 0) + 1
        repeat = any(c >= 3 for c in seen.values())

        # ④ 硬失败：连接/解析/命令缺失类失败反复出现
        hard = sum(1 for r in rows if self._looks_hard_fail(r["result"] or ""))
        hard_fail = hard >= 3

        # ⑤ 连续错提交：flag 被验证器拒绝且没有新进展
        wrong_submit = self._recently_rejected_flags(task_id) >= 2 and not last_accepted

        count = sum([stall, repeat, hard_fail, wrong_submit])
        return StallSignals(
            flag_stall=flag_stall,
            stall=stall,
            repeat=repeat,
            hard_fail=hard_fail,
            wrong_submit=wrong_submit,
            count=count,
            idle_sec=flag_since,
        )

    def stalled(self, task_id: str, last_accepted: bool, window: int | None = None) -> bool:
        """兼容旧签名的二值判定。内部走五信号。"""
        if window is not None:
            self.window = window
        return self.should_intervene(self.signals(task_id, last_accepted))

    def should_intervene(self, sig: StallSignals) -> bool:
        """综合触发：flag 主时钟一票，或题级四信号任二。

        另外 `stall`（连续 window 次动作都没换来接受）本身单独也算数——
        这是"完全推进不动"，而不是"在推进但方法单一"。四信号任二的组合判据
        是为了抓那类**每步看起来都成功、但整体在打转**的情况（重复命令、
        硬失败刷屏），不能拿它去放宽彻底的停滞。
        """
        return sig.flag_stall or sig.stall or sig.count >= 2

    def nudge_text(self, task_id: str, sig: StallSignals) -> str:
        """给模型的提醒文本。程序生成，不花 LLM 调用，尾部追加以保缓存。"""
        t = self.bb.task(task_id)
        st = stages.stage(t.category, t.stage)
        reasons = []
        if sig.idle_sec > 0 and sig.flag_stall:
            reasons.append(f"{sig.idle_sec:.0f}s 没有新 flag")
        if sig.stall:
            reasons.append(f"最近 {self.window} 次动作没有带来任何新事实")
        if sig.repeat:
            reasons.append("同一命令反复执行")
        if sig.hard_fail:
            reasons.append("连接/解析类硬失败反复出现")
        if sig.wrong_submit:
            reasons.append("连续提交被拒")
        why = "、".join(reasons) or "进展停滞"
        facts = list(self.bb.facts(task_id).items())[-4:]
        known = "; ".join(f"{k}={v[:40]}" for k, v in facts) or "（黑板是空的）"
        return (
            f"[停滞提醒] 当前阶段 {st.name}（目标：{st.goal}）出现卡塞：{why}。\n"
            f"已知事实：{known}\n"
            f"请二选一：① 先把当前掌握的证据写进黑板（哪怕很短），再换方法/换攻击面/缩小目标；"
            f"② 如果这条方向已经走死，明确说明它为什么死，让系统换路线。\n"
            f"不要重复已证伪的命令。"
        )

    def nudge(self, task_id: str) -> str | None:
        """给一次提醒，返回提醒文本；额度用完或无资格时返回 None。

        为什么先提醒而不是直接杀：错杀一条正在推进的路线，损失的是已经投入的
        全部侦察成本（我们的靶场一 park 就要重开容器，目标状态归零）。
        提醒是零成本的，先提醒、提醒无效再退役。
        """
        used = self._nudges.get(task_id, 0)
        if used >= self.nudge_max:
            return None
        self._nudges[task_id] = used + 1
        self.bb.add_nudge(task_id, self.nudge_text(task_id, self.signals(task_id, False)))
        return "已提醒"

    # ---------- 五信号的辅助查询 ----------
    def _last_flag_ts(self, task_id: str) -> float | None:
        row = self.bb.db.execute(
            "SELECT MAX(ts) t FROM attempts WHERE task_id=? AND result LIKE '%验%flag%'",
            (task_id,),
        ).fetchone()
        return row["t"] if row and row["t"] else None

    def _recently_rejected_flags(self, task_id: str) -> int:
        rows = self.bb.db.execute(
            "SELECT result FROM attempts WHERE task_id=? ORDER BY id DESC LIMIT 6",
            (task_id,),
        ).fetchall()
        return sum(
            1
            for r in rows
            if "拒绝" in (r["result"] or "") or "未提供格式合法的 flag" in (r["result"] or "")
        )

    @staticmethod
    def _looks_hard_fail(result: str) -> bool:
        blob = (result or "").lower()
        markers = (
            "could not resolve",
            "name or service not known",
            "connection refused",
            "connection timed out",
            "no route to host",
            "command not found",
        )
        return any(m in blob for m in markers)

    # ---------- 状态胶囊 ----------
    def capsule(self, task_id: str) -> str:
        t = self.bb.task(task_id)
        st = stages.stage(t.category, t.stage)
        facts = self.bb.facts(task_id)
        body = "; ".join(f"{k}={v[:60]}" for k, v in list(facts.items())[:8]) or "无"
        dead = self.bb.falsified(task_id)
        line = (
            f"阶段 {t.stage}（{st.name}）目标：{st.goal} | 已知：{body}"
            f" | 已证伪 {len(dead)} 条路线"
            f" | 剩余 {t.remaining:.0f}s"
        )
        self.bb.set_capsule(task_id, t.stage, line)
        return line
