"""主循环：把黑板、规划、执行、证据闸门、调度串起来。

调度语义（每题独立计时）：
- `sched.pick()` 返回本轮要推进的若干 Slot，每个带自己的 deadline 与并行度。
- 一题只能花自己的预算；到点就 EXPIRED，不会再有"复活"。
- 只按 flag 计分，所以 `note_result` 的奖励仅用于日志，不参与决策。

两种执行粒度：
- `tick()` 串行，适合调试与成本敏感场景。
- `wave()` 并发，规划并行 / 执行并行 / 判定串行。真实模型 9~15s 一次调用，
  串行跑不动，比赛用 wave。
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import stages
from .blackboard import Blackboard, action_hash
from .controller import Controller
from .executor import ExecutorAdapter
from .planner import RoutePlanner, TaskPlanner
from .scheduler import Scheduler, Slot

# 同一条路线的子目标最多重拆几次。不封顶的话，一条已经被证伪一半的方向会被
# 无限续命，把预算耗在死路上——这是"放开额度"必须配的闸。
REPLENISH_MAX = 3


@dataclass
class TickReport:
    task: str | None = None
    stage: str = ""
    route: int | None = None
    action: str = ""
    accepted: bool = False
    advanced: bool = False
    solved: bool = False
    loop: bool = False
    note: str = ""
    elapsed: float = 0.0


class Harness:
    def __init__(
        self,
        bb: Blackboard,
        *,
        llm,
        runner,
        verifier=None,
        scheduler: Scheduler | None = None,
        route_planner: RoutePlanner | None = None,
        task_planner: TaskPlanner | None = None,
        executor: ExecutorAdapter | None = None,
        controller: Controller | None = None,
        task_starter=None,
        task_closer=None,
        max_active: int | None = None,
    ) -> None:
        self.bb = bb
        self.sched = scheduler or Scheduler(bb)
        self.rp = route_planner or RoutePlanner(bb, llm)
        self.tp = task_planner or TaskPlanner(bb, llm)
        self.ex = executor or ExecutorAdapter(bb, llm, runner)
        self.ctl = controller or Controller(bb, verifier)
        self.task_starter = task_starter
        self.task_closer = task_closer
        # 平台允许同时存活的靶场数。调度器用它决定"还有没有余量去探测新题"——
        # 不知道这个上限，就会不停地挑新题、把正在做的题挤掉（只开关容器不做题）。
        self.max_active = max_active
        self.solved: list[str] = []
        self.sched.start()

    # ---------- 串行批量 ----------
    def run(self, max_ticks: int = 200) -> list[TickReport]:
        reports: list[TickReport] = []
        for _ in range(max_ticks):
            rep = self.tick()
            reports.append(rep)
            if rep.note == "无可用题目":
                break
        return reports

    # ---------- 串行单步 ----------
    def tick(self) -> TickReport:
        t0 = time.time()
        slots = self.sched.pick(width=1, capacity=self.max_active)
        if not slots:
            self._close_terminal_tasks()
            return TickReport(note="无可用题目")

        slot = slots[0]
        task = slot.task
        start_error = self._start_task(task.id)
        if start_error:
            self.sched.park(task.id, "平台靶场启动失败")
            self._close_terminal_tasks()
            return TickReport(task=task.id, note=start_error)
        st = stages.stage(task.category, task.stage)
        rep = TickReport(task=task.id, stage=st.name)

        self.sched.pump(task.id)
        self._ensure_routes_for(task, slot.fanout)
        route, subgoal = self._pick_subgoal(task)
        if route is None:
            self.sched.park(task.id, "路线枯竭")
            rep.note = "路线枯竭，放下"
            self._close_terminal_tasks()
            return rep

        rep.route = route["id"]
        step = self.ex.step(task.id, subgoal["text"], st.name, hint=route["hypothesis"])
        rep.action = step.action
        if not step.action:
            self.bb.close_subgoal(subgoal["id"], done=False)
            rep.note = "执行器未给出动作"
            return rep

        rep = self._settle(rep, task, route, subgoal, step, None)
        self._close_terminal_tasks()
        rep.elapsed = time.time() - t0
        return rep

    # ---------- 并发批量 ----------
    def wave(self, width: int = 3, max_waves: int = 40) -> list[TickReport]:
        """三段式并发：规划并行 → 执行并行 → 判定串行。"""
        reports: list[TickReport] = []
        for _ in range(max_waves):
            slots = self.sched.pick(width=width, capacity=self.max_active)
            if not slots:
                self._close_terminal_tasks()
                break

            self._close_terminal_tasks()
            ready = []
            for slot in slots:
                start_error = self._start_task(slot.task.id)
                if start_error:
                    self.sched.park(slot.task.id, "平台靶场启动失败")
                    reports.append(TickReport(task=slot.task.id, note=start_error))
                else:
                    ready.append(slot)
            slots = ready
            if not slots:
                self._close_terminal_tasks()
                continue

            # 1) 规划：各题互不相干，可并发
            for s in slots:
                self.sched.pump(s.task.id)
            with ThreadPoolExecutor(max_workers=len(slots)) as ex:
                list(ex.map(lambda s: self._ensure_routes_for(s.task, s.fanout), slots))

            # 2) 执行：唯一耗时阶段，并发
            work = self._work_items(slots)
            if not work:
                for s in slots:
                    self.sched.park(s.task.id, "子目标耗尽")
                self._close_terminal_tasks()
                continue
            with ThreadPoolExecutor(max_workers=len(work)) as ex:
                futs = {ex.submit(self._run_slot, w): w for w in work}
                results = []
                for fut in as_completed(futs):
                    w = futs[fut]
                    try:
                        results.append((w, fut.result(), None))
                    except Exception as e:      # 单路线崩掉不该拖垮整轮
                        results.append((w, None, e))

            # 3) 判定：串行（复合读写语义，并发会重复推进同一里程碑）
            for w, step, err in results:
                task, route, subgoal = w
                st = stages.stage(task.category, task.stage)
                rep = TickReport(task=task.id, stage=st.name, route=route["id"])
                reports.append(self._settle(rep, task, route, subgoal, step, err))
            self._close_terminal_tasks()
        return reports

    def _start_task(self, task_id: str) -> str:
        if self.task_starter is None:
            return ""
        try:
            self.task_starter(task_id)
            return ""
        except Exception as e:
            return f"靶场启动失败：{type(e).__name__}: {e}"

    def _close_terminal_tasks(self) -> None:
        """只释放**真正结束**的靶场：解出或计时耗尽。

        `parked` 刻意不在这里。旧版把 parked 也算终态，于是一停滞就
        `POST /close`，下次捞回来得重新起容器——上传的 webshell、跑起来的监听、
        解压好的附件全部归零，只剩黑板里的文字事实。对 web 勉强能忍，对 pwn/redblue
        等于每次回去都从第一条命令重来。

        腾出活动靶场名额靠调度器的 LRU（见 `agent_main.run()` 里的 slot guard），
        而不是靠"一停就关"。
        """
        if self.task_closer is None:
            return
        for task in self.bb.tasks(("solved", "expired")):
            try:
                self.task_closer(task.id)
            except Exception as e:
                print(f"[PLATFORM] {task.id} 释放异常：{type(e).__name__}: {e}", flush=True)

    # ---------- 内部 ----------
    def _ensure_routes_for(self, task, fanout: int) -> None:
        """保证当前阶段有足够**带待办子目标**的存活路线。

        三个容易写错的地方：
        1. 只看 live 数量不够——路线活着但子目标已全部关闭时，它产不出工作项，
           会表现为"路线枯竭"。所以按"可用工作项数"判断。
        2. 提案失败（被证伪表挡掉）时不能死循环，所以限制补提轮数。
        3. **子目标用完了不等于路线死了。** 旧版一次性拆 5 条子目标用到底，耗尽就
           判枯竭——一道题在整条生命周期里只能拿到十几到几十个动作，pwn/crypto 这种
           需要几十上百次试错的题根本走不完。这里改成：同一条路线在子目标耗尽时，
           按**当前最新事实**重新拆一批（`REPLENISH_MAX` 次封顶），只有连新子目标都
           拆不出来才算枯竭。
        """
        for _ in range(2):
            usable = 0
            for r in self.bb.live_routes_at(task.id, task.stage):
                if self.bb.next_subgoal(r["id"]) is not None:
                    usable += 1
                elif self._replenish(task, r):
                    usable += 1
            if usable >= fanout:
                return
            props = self.rp.propose(task.id, n=max(fanout - usable, 1))
            if not props:
                return          # 提不出新路线了，交给上层判定枯竭
            for p in props:
                rid = self.bb.add_route(task.id, p.hypothesis, stage=task.stage)
                if rid:
                    for sg in self.tp.decompose(task.id, p.hypothesis):
                        self.bb.add_subgoal(rid, sg)

    def _replenish(self, task, route) -> bool:
        """子目标耗尽时按最新事实重拆一批。返回是否成功补上。"""
        used = self.bb.replenish_count(route["id"])
        if used >= REPLENISH_MAX:
            return False
        done, todo = self.bb.subgoal_stats(route["id"])
        if todo > 0:
            return False
        new = self.tp.decompose(task.id, route["hypothesis"])
        # 新子目标必须与旧的实质不同，否则就是原地打转（拆出来的还是那几条）
        old = {
            r["text"]
            for r in self.bb.db.execute(
                "SELECT text FROM subgoals WHERE route_id=?", (route["id"],)
            ).fetchall()
        }
        fresh = [sg for sg in new if sg not in old]
        if not fresh:
            return False
        self.bb.bump_replenish(route["id"])
        for sg in fresh:
            self.bb.add_subgoal(route["id"], sg)
        return True

    def _pick_subgoal(self, task):
        for r in self.bb.live_routes_at(task.id, task.stage):
            sg = self.bb.next_subgoal(r["id"])
            if sg is not None:
                return r, sg
        return None, None

    def _work_items(self, slots: list[Slot]) -> list[tuple]:
        work = []
        for s in slots:
            routes = self.bb.live_routes_at(s.task.id, s.task.stage)
            used = 0
            for r in routes:
                if used >= s.fanout:
                    break
                sg = self.bb.next_subgoal(r["id"])
                if sg is None:
                    continue
                work.append((s.task, r, sg))
                used += 1
        return work

    def _run_slot(self, work: tuple):
        """worker：只做慢活（LLM + 工具），不写任何状态。"""
        task, route, subgoal = work
        st = stages.stage(task.category, task.stage)
        return self.ex.step(task.id, subgoal["text"], st.name, hint=route["hypothesis"])

    def _settle(self, rep: TickReport, task, route, subgoal, step, err) -> TickReport:
        """主线程：证据判定 + 状态变更，全部串行。"""
        if err is not None or step is None:
            self.bb.close_subgoal(subgoal["id"], done=False)
            rep.note = f"执行异常: {type(err).__name__ if err else 'None'}"
            return rep

        rep.action = step.action
        if not step.action:
            self.bb.close_subgoal(subgoal["id"], done=False)
            rep.note = "执行器未给出动作"
            return rep

        ev = self.ex.to_evidence(step, task.id)
        self.bb.record_attempt(
            task.id, route["id"], step.action, bool(step.raw and step.raw.ok), ev.detail
        )

        rep.loop = self.ctl.check_loop(task.id, action_hash(step.action), route["id"])
        if rep.loop:
            self.bb.close_subgoal(subgoal["id"], done=False)
            rep.note = "同一动作重复触发循环检测，路线已杀"
            return rep

        decision = self.ctl.judge(task.id, ev)
        rep.accepted = decision.accepted
        rep.advanced = decision.advanced
        rep.solved = decision.solved
        rep.note = decision.reason
        self.bb.close_subgoal(subgoal["id"], done=decision.accepted)

        if decision.solved:
            self.solved.append(task.id)
            self.bb.set_route(route["id"], "won")
            self.sched.note_result(task.id, solved=True, reward=1.0)
        elif decision.advanced:
            self.bb.set_route(route["id"], "merged")
            self.ctl.capsule(task.id)

        # 卡塞处理：先提醒，提醒无效才退役。
        # 直接杀一条正在推进的路线代价很高——靶场会被释放，目标状态归零，
        # 已经投入的侦察成本全白费。提醒是零 LLM 成本的，先提醒更划算。
        if not decision.accepted:
            sig = self.ctl.signals(task.id, decision.accepted)
            if self.ctl.should_intervene(sig):
                if self.ctl.nudge(task.id):
                    rep.note += " | 判定卡塞，已提醒"
                else:
                    self.sched.park(task.id, "提醒无效后仍卡塞")
                    rep.note += " | 提醒已用尽，放下"
        return rep
