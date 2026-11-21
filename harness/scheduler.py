"""每题独立计时的调度器。

赛制事实（会推翻旧设计的地方）：

1. **只按 flag 计分**，预期解额外 +40。所以"新事实""阶段推进"都不是分，
   它们只是过程信号，**不能**拿来当奖励——旧版的 UCB 奖励函数在这里是错的。
2. **每题独立倒计时**。一题超时就是彻底结束，不存在"停放后复活"。
3. **先易后难，打完简单的再回头**。所以需要显式的难度先验，而不是 UCB。

于是调度变成三件事：

  难度先验  -> 决定顺序
  可行域判断 -> 决定现在能不能打（时间够不够推进到 flag）
  时间隔离   -> 每题只能用自己的预算，不许互相借用

UCB 被删掉了。它适合"总预算固定、题目同质、可反复抽样"的场景，三条都不成立。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .blackboard import Blackboard, Task

# 任务状态机（与 blackboard.tasks.status 对齐）
OPEN = "open"          # 还没探测过，难度未知
PROBING = "active"     # 探测中，正在估难度
PARKED = "parked"      # 打过但没解出，等"简单题做完"再回头
EXPIRED = "expired"    # 自己的时间用完了，彻底结束
SOLVED = "solved"      # 已解出

# 一次探测分给每题的预算比例（相对该题总预算）
PROBE_FRACTION = 0.15

# 判断"还值得打"的最低要求：至少够推进剩余阶段的 N 倍单阶段耗时
MIN_STAGE_SECONDS = 90.0


@dataclass
class Slot:
    """一次调度决策的结果。"""

    task: Task
    mode: str          # "probe" | "push"
    fanout: int        # 题内并行路线数
    deadline: float    # 这次分配的绝对截止时刻（monotonic）
    reason: str = ""


class Scheduler:
    def __init__(
        self,
        bb: Blackboard,
        *,
        min_stage_seconds: float = MIN_STAGE_SECONDS,
        max_stalls: int = 3,
    ) -> None:
        self.bb = bb
        self.min_stage_seconds = min_stage_seconds
        self.max_stalls = max_stalls        # 反复打不动的容忍次数
        self._started: dict[str, float] = {}   # 每题首次开工的 monotonic 时刻
        self._stalls: dict[str, int] = {}      # 每题被判停滞的次数

    # ---------- 生命周期 ----------
    def start(self) -> None:
        """整体开工：给每道题打上独立倒计时的起点。"""
        now = time.monotonic()
        for t in self.bb.tasks(("open", "active", "parked")):
            self._started.setdefault(t.id, now)

    def expired_ids(self) -> list[str]:
        """自己的时间耗尽、且还没解出的题：彻底结束。"""
        out: list[str] = []
        now = time.monotonic()
        for t in self.bb.tasks(("open", "active", "parked")):
            if now - self._started.get(t.id, now) >= t.budget:
                self.bb.set_task(t.id, status=EXPIRED, note="独立计时耗尽")
                out.append(t.id)
        return out

    def remaining(self, task_id: str) -> float:
        t = self.bb.task(task_id)
        return t.budget - (time.monotonic() - self._started.get(task_id, time.monotonic()))

    # ---------- 难度先验 ----------
    def difficulty(self, t: Task) -> float:
        """越小越简单。三个信号，按可靠性排序：

        1. 题目自带分值/解出数（最可靠，平台通常给）——存在 note 里的 hint 字段
        2. 探测期推进的阶段数（解得越深越可能是能做出来的）
        3. 已消耗时间与产出的比值（打不动就抬难度）
        """
        priors: list[float] = []

        # 1) 平台给的分值：分越低越简单（CTF 惯例）
        if t.points > 0:
            priors.append(min(t.points / 500.0, 2.0))
        # 解出人数越多越简单
        if t.solves > 0:
            priors.append(1.0 / (1.0 + t.solves / 50.0))

        # 2) 探测深度：推进过的阶段数
        total = max(t.stage_count, 1)
        priors.append(1.0 - min(t.stage / total, 1.0))

        # 3) 效率：有事实却卡在原地，说明难度高于预期
        if t.spent > 60 and t.stage == 0:
            priors.append(1.5)

        return sum(priors) / len(priors) if priors else 0.5

    # ---------- 可行性 ----------
    def feasible(self, t: Task) -> tuple[bool, str]:
        """现在还能不能在这道题上取得进展。

        核心判据：剩余时间是否够把剩下的阶段走完。不够就别开始，
        把时间留给别的题——这是"先易后难"能生效的前提。
        """
        rem = self.remaining(t.id)
        if rem <= 0:
            return False, "时间耗尽"
        stages_left = max(t.stage_count - t.stage, 0)
        need = stages_left * self.min_stage_seconds
        if rem < need:
            return False, f"剩余 {rem:.0f}s 不足走完 {stages_left} 个阶段（需约 {need:.0f}s）"
        return True, ""

    # ---------- 决策 ----------
    def pick(self, width: int = 3, capacity: int | None = None) -> list[Slot]:
        """选出本轮要推进的题。

        **推进优先于探测。** 这里是踩过的坑：原实现只要还有 open 题就
        `return [self._probe(t) for t in unseen[:width]]`，**已探测的题一个都不给**。
        在没有活动容器上限时看不出问题，但配上"同时最多 3 个容器"就变成灾难：

          每波挑 3 道全新题 -> 占满名额 -> 把正在做的 3 道挤掉 -> 下一波再挑新的

        40 道题时会先空烧十几波只做探测、一道题都没真正推进，日志表现为
        「一直在开容器关容器」。所以现在的顺序是：

          1. 已探测且在推进中的题（PROBING）——先保它们
          2. 还有空余名额时才探测新题（OPEN）
          3. 最后才是放下过的题（PARKED）

        `capacity` 是活动容器上限。给了就只在"名额还有剩"时探测新题，
        避免刚探测就被名额挤出去、白白消耗一次 target 启动。
        """
        self.expired_ids()

        cands = [t for t in self.bb.tasks((OPEN, PROBING, PARKED))]
        if not cands:
            return []

        ok: list[Task] = []
        for t in cands:
            good, _ = self.feasible(t)
            if good:
                ok.append(t)
        if not ok:
            return []

        active = [t for t in ok if t.status == PROBING]
        parked = [t for t in ok if t.status == PARKED]
        unseen = [t for t in ok if t.status == OPEN]

        # 难度先验：越小越简单。每组内部仍按"先易后难"，但组间顺序固定，
        # 否则一道简单的新题会把正在推进的题挤出去。
        active.sort(key=self.difficulty)
        parked.sort(key=self.difficulty)
        unseen.sort(key=self.difficulty)

        # ① 正在推进的题先保（它们已经占着容器、已经有投入）
        picks: list[Task] = active[:width]
        left = width - len(picks)

        # ② 其次是放下过的题——它们**已经投入过**侦察成本，重新捞回来做比
        #    开一道全新的题更划算（重新开新题要启动容器、从头侦察）。
        #    这也是"先易后难"的本意：parked 只是暂时放下，不是放弃。
        if left > 0:
            picks += parked[:left]
            left = width - len(picks)

        # ③ 最后才是探测新题，而且必须确认名额真有富余。
        if left > 0:
            free = left if capacity is None else max(0, capacity - len(active) - len(
                [t for t in picks if t.status == PARKED]
            ))
            n_probe = min(left, free, len(unseen))
            picks += unseen[:n_probe]

        slots: list[Slot] = []
        for t in picks:
            s = self._probe(t) if t.status == OPEN else self._push(t)
            if s is not None:
                slots.append(s)
        return slots

    def _probe(self, t: Task) -> Slot:
        budget = t.budget * PROBE_FRACTION
        self.bb.set_task(t.id, status=PROBING)
        return Slot(
            task=t,
            mode="probe",
            fanout=1,                      # 探测只用一条线，省算力
            deadline=time.monotonic() + budget,
            reason="浅探测估难度",
        )

    def _push(self, t: Task) -> Slot:
        now = time.monotonic()
        rem = self.remaining(t.id)
        # 题内并行度按剩余时间给：时间紧就单线，宽裕才开分支
        fanout = 1 if rem < self.min_stage_seconds * 2 else 2
        return Slot(
            task=t,
            mode="push",
            fanout=fanout,
            deadline=now + min(rem, self.min_stage_seconds * 3),
            reason="推进",
        )

    def pump(self, task_id: str) -> None:
        """把放下/待办的题重新置为可推进。

        没有这一步，一题被 park 之后 `pick` 只会给它 probe 或 push，
        但状态一直是 PARKED，`_push` 不会把它改回 PROBING，
        导致每轮都在同一状态上重复决策。
        """
        t = self.bb.task(task_id)
        if t.status in (PARKED, OPEN):
            self.bb.set_task(task_id, status=PROBING)

    # ---------- 记录 ----------
    def note_result(self, task_id: str, solved: bool, reward: float = 0.0) -> None:
        """记一次结果。奖励只用于日志——分数只来自 flag，不进决策。"""
        if solved:
            self.bb.set_task(task_id, status=SOLVED)
        self.bb.charge(task_id, 0.0, reward=reward)

    def park(self, task_id: str, why: str = "") -> None:
        """这一轮打不动，先放下。

        累计放下次数超过阈值就彻底结束：一题反复打不动，继续捞回来只是空转。
        这是"先易后难"的必要配套——放下要有代价，否则调度器会无限重试同一题。
        """
        n = self._stalls.get(task_id, 0) + 1
        self._stalls[task_id] = n
        if n >= self.max_stalls:
            self.bb.set_task(task_id, status=EXPIRED, note=f"{why}（已放下 {n} 次）")
        else:
            self.bb.set_task(task_id, status=PARKED, note=f"{why}（第 {n} 次）")

    def summary(self) -> str:
        rows = []
        for t in self.bb.tasks():
            rows.append(
                f"{t.id:<14} {t.status:<8} stage={t.stage}/{t.stage_count} "
                f"diff={self.difficulty(t):.2f} rem={self.remaining(t.id):.0f}s"
            )
        return "\n".join(rows)
