"""两级规划：route planner（链级）与 task planner（动作级）。

论文的关键洞察：上层只需要"已验证的结论 + 简短证据"，不需要底层交互序列。
所以这里所有 prompt 都只吃 blackboard.snapshot()，从不吃原始工具输出。
替换成 π / OpenHands 时，只需要提供同签名的 LLM 实现。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Protocol

from . import knowledge, stages
from .blackboard import Blackboard

ROUTE_SYS = """你是攻击链路线规划器。你的职责是维护全局方向，不是执行。
规则：
1. 只提出彼此真正异构的路线（不同攻击面/不同数学结构），不要同一路线的参数变体。
2. 输出严格 JSON：{"routes":[{"hypothesis":"...","why":"..."}]}
3. hypothesis 必须能被一次实验证伪——写成"如果 X 成立，那么做 Y 会看到 Z"。
4. 不要重复已证伪列表里的假设。
"""

TASK_SYS = """你是任务拆解器。把一条路线拆成可验证的子目标。
规则：
1. 输出严格 JSON：{"subgoals":["...","..."]}，最多 5 条。
2. 每条子目标必须是一条命令或一次请求就能判定成败的具体动作。
3. 不要写"分析一下""研究一下"这类不可判定的目标。
"""


class LLM(Protocol):
    def complete(self, *, role: str, system: str, prompt: str) -> str: ...


def _json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}


@dataclass
class Proposal:
    hypothesis: str
    why: str = ""


class RoutePlanner:
    def __init__(self, bb: Blackboard, llm: LLM) -> None:
        self.bb = bb
        self.llm = llm

    def propose(self, task_id: str, n: int = 3) -> list[Proposal]:
        t = self.bb.task(task_id)
        st = stages.stage(t.category, t.stage)
        snap = self.bb.snapshot(task_id)

        # 静态前缀：只依赖 (题型, 阶段, 角色)，与状态无关 —— 保证 KV 缓存可命中
        prefix = (
            f"题型 {t.category}，阶段 {t.stage}/{st.name}：{st.goal}\n"
            f"本阶段需要的里程碑证据：{st.requires}\n"
            f"策略知识：\n{knowledge.must_block(t.category, st.name, 'route_planner')}\n"
        )
        # 动态段：状态 + 按状态检索的参考
        ref = knowledge.ref_block(
            t.category, st.name, json.dumps(snap, ensure_ascii=False), "route_planner"
        )
        prompt = (
            prefix
            + f"\n当前状态：{json.dumps(snap, ensure_ascii=False)}\n"
            + (f"\n参考：\n{ref}\n" if ref else "")
            + f"\n请给出最多 {n} 条异构路线。"
        )
        out = _json(self.llm.complete(role="route_planner", system=ROUTE_SYS, prompt=prompt))
        props: list[Proposal] = []
        for r in out.get("routes", [])[:n]:
            hyp = str(r.get("hypothesis", "")).strip()
            if not hyp or self.bb.is_falsified(task_id, hyp):
                continue
            props.append(Proposal(hyp, str(r.get("why", ""))))
        return props


class TaskPlanner:
    def __init__(self, bb: Blackboard, llm: LLM) -> None:
        self.bb = bb
        self.llm = llm

    def decompose(self, task_id: str, hypothesis: str) -> list[str]:
        t = self.bb.task(task_id)
        st = stages.stage(t.category, t.stage)
        facts = self.bb.facts(task_id)
        prefix = (
            f"题型 {t.category}，阶段 {st.name}：{st.goal}\n"
            f"策略知识：\n{knowledge.must_block(t.category, st.name, 'task_planner')}\n"
        )
        ref = knowledge.ref_block(
            t.category, st.name, hypothesis + json.dumps(facts, ensure_ascii=False), "task_planner"
        )
        prompt = (
            prefix
            + f"\n路线假设：{hypothesis}\n"
            + f"已知事实：{json.dumps(facts, ensure_ascii=False)}\n"
            + (f"\n参考：\n{ref}\n" if ref else "")
            + "\n拆成可验证子目标。"
        )
        out = _json(self.llm.complete(role="task_planner", system=TASK_SYS, prompt=prompt))
        return [str(s).strip() for s in out.get("subgoals", [])[:5] if str(s).strip()]
