"""分级专家知识库。

两级结构，对应两种完全不同的使用方式：

- **must**：每个 (题型, 阶段, 角色) 格子里的必读条目。拼进 prompt 的**静态前缀**，
  所以同一阶段内的多次调用前缀完全一致，KV 缓存可以命中。
  有字符预算上限——它每一轮都在付费。
- **ref**：检索型语料。按当前状态做关键词匹配后拼进**动态段**，不进前缀。
  体积可以大，命中才付费。

为什么不直接把所有知识拼进 prompt：实测这个模型一次推理要 9~15 秒，
推理 token 占总产出三分之一；知识块每轮重复传输，不设预算会线性放大成本。

语料来源：`knowledge/` 目录下的 JSON 文件（存在则加载，覆盖代码内置示例），
这样填内容不需要改代码。格式见 `knowledge/CONTRIBUTING.md`。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

KB_DIR = Path(__file__).resolve().parent.parent / "knowledge"

# must 的单格子字符预算。超过就截断并告警——这是成本闸门，不是建议值。
MUST_BUDGET = 900

# ---------------------------------------------------------------- 内置示例
# 只放"决策判据"，不放操作细节：模型本来就会敲命令，缺的是知道何时放弃。
_INTERNAL_MUST: dict[tuple[str, str, str], list[str]] = {
    ("*", "*", "route_planner"): [
        "路线之间必须真正异构：换攻击面（认证/上传/依赖/协议/数学结构），不是换 payload 参数。",
        "已证伪的假设不要重提；要么改前提，要么换路线。",
        "同一类证据重复两次仍未推进，说明该阶段饱和：考虑推进、换路或放弃。",
    ],
    ("*", "*", "task_planner"): [
        "子目标必须是可判定的动作结果，不能是'研究一下 X'。",
        "一条子目标尽量对应一次请求或一条命令，成败明确。",
    ],
    ("*", "*", "executor"): [
        "先读后写：动手前确认目标当前状态，别破坏可复现性。",
        "长命令加超时；输出进黑板前只保留判据相关部分。",
        "命令失败先看是不是环境问题（DNS/超时/连接拒绝），别当成攻击失败。",
    ],
    ("*", "*", "controller"): [
        "只接受带运行时证据的进展；模型自称成功一律视为未验证。",
    ],
    ("web", "recon", "executor"): [
        "先列端点再谈漏洞：目录、参数名、报错页、响应头里的框架线索。",
        "同一功能在匿名/普通/管理员三种身份下各试一次，权限边界常常就是漏洞点。",
    ],
    ("web", "vuln_localize", "executor"): [
        "注入类先确认回显位置与过滤层级，再决定盲注还是联合查询。",
        "文件操作优先测路径穿越与扩展名白名单的实际判定顺序。",
    ],
    ("web", "vuln_localize", "route_planner"): [
        "按攻击面分路线：注入 / 认证绕过 / 文件操作 / 反序列化 / SSRF，别按 payload 分。",
    ],
    ("pwn", "reproduce", "executor"): [
        "先确认保护：canary/NX/PIE/RELRO，再判断是不是纯栈溢出。",
        "崩溃偏移量立刻记为事实，后续所有路线都要用。",
    ],
    ("pwn", "primitive", "route_planner"): [
        "原语路线天然异构：泄漏 / 写 / 控制流，分别由不同分支探索。",
    ],
    ("crypto", "model", "executor"): [
        "把题面还原成（已知, 未知, oracle）三元组，先确认是不是标准困难问题。",
        "小参数先手算验证理解，再上复杂攻击。",
    ],
    ("*", "*", "*"): [
        "记录事实时用简短的蛇形名字；只有真正完成当前阶段里程碑时才使用给定的里程碑键。",
    ],
}

# ---------------------------------------------------------------- 分级语料
MUST: dict[tuple[str, str, str], list[str]] = dict(_INTERNAL_MUST)
REF: list[dict] = []          # {"tags": [..], "stages": [..], "text": "..."}
SKIP: dict[tuple[str, str, str], list[str]] = {}   # 该格子的"不要做"清单

_TOKEN = re.compile(r"[a-zA-Z_]{3,}|[一-鿿]{2,}")


def _norm(items: Iterable[str]) -> list[str]:
    return [x.strip() for x in items if x and x.strip()]


def load(path: str | Path | None = None) -> None:
    """从 JSON 加载外部语料，覆盖/追加到内置示例。

    结构：
      {
        "must":  {"web/recon/executor": ["...", "..."]},
        "skip":  {"web/recon/executor": ["不要一上来就目录爆破"]},
        "ref":   [{"tags": ["sql", "盲注"], "stages": ["vuln_localize"], "text": "..."}]
      }
    """
    p = Path(path) if path else KB_DIR / "kb.json"
    if not p.exists():
        return
    data = json.loads(p.read_text(encoding="utf-8"))

    for key, items in (data.get("must") or {}).items():
        parts = key.split("/")
        if len(parts) != 3:
            raise ValueError(f"must 的键必须是 题型/阶段/角色：{key}")
        MUST[tuple(parts)] = _norm(items)      # 覆盖，方便整格替换

    for key, items in (data.get("skip") or {}).items():
        parts = key.split("/")
        if len(parts) != 3:
            raise ValueError(f"skip 的键必须是 题型/阶段/角色：{key}")
        SKIP[tuple(parts)] = _norm(items)

    for rec in data.get("ref") or []:
        text = (rec.get("text") or "").strip()
        if text:
            REF.append(
                {
                    "tags": _norm(rec.get("tags") or []),
                    "stages": _norm(rec.get("stages") or []),
                    "text": text,
                }
            )


def _pick(table: dict, category: str, stage: str, role: str) -> list[str]:
    """按 (具体 -> 通配) 的顺序回退，越具体越优先，且不重复累加。"""
    for key in (
        (category, stage, role),
        (category, "*", role),
        ("*", stage, role),
        ("*", "*", role),
    ):
        if key in table:
            return table[key]
    return []


def must_block(category: str, stage: str, role: str, budget: int = MUST_BUDGET) -> str:
    """静态前缀用的必读块。输出必须**只**依赖参数，不能含任何动态状态，
    否则缓存会失效（这是先前实测 cache_hit=0 的原因）。"""
    items = _pick(MUST, category, stage, role)[:]
    items += _pick(SKIP, category, stage, role)
    if not items:
        return ""

    out: list[str] = []
    used = 0
    for it in items:
        line = f"- {it}"
        if used + len(line) > budget:
            break
        out.append(line)
        used += len(line) + 1
    return "\n".join(out)


_INDEX = None
_INDEX_TRIED = False


def attach_index(index) -> None:
    """挂载外部知识库索引（harness.kbindex.KBIndex）。"""
    global _INDEX
    _INDEX = index


def _index():
    """惰性打开磁盘索引，只尝试一次——赛场上不存在就直接跳过。"""
    global _INDEX_TRIED
    if _INDEX is None and not _INDEX_TRIED:
        _INDEX_TRIED = True
        try:
            from .kbindex import open_index

            attach_index(open_index())
        except Exception:
            pass
    return _INDEX


def ref_block(
    category: str,
    stage: str,
    state_text: str,
    role: str,
    limit: int = 2,
    external: int = 2,
) -> str:
    """按当前状态检索参考条目。

    两个来源，都只进**动态段**（不影响静态前缀的缓存）：

    1. kb.json 里的手写 ref —— 权重最高，是你们沉淀的判断，优先占位。
    2. 外部资料索引（331MB 公开语料）—— 补漏，用 FTS5 检索。
       手写条目够了就不再查外部，省延迟也省 token。

    打分刻意简单（词面匹配）：可解释、零延迟、不引入依赖。
    """
    want = set(_TOKEN.findall(state_text.lower()))
    lines: list[str] = []

    scored: list[tuple[float, dict]] = []
    for rec in REF:
        if rec["stages"] and stage not in rec["stages"]:
            continue
        hit = sum(1 for t in rec["tags"] if t.lower() in want)
        if hit == 0 and rec["tags"]:
            continue
        scored.append((hit, rec))
    scored.sort(key=lambda x: -x[0])
    for _, rec in scored[:limit]:
        lines.append(f"- {rec['text']}")

    # 手写条目不足时，从外部索引补
    if len(lines) < limit and external > 0:
        idx = _index()
        if idx is not None:
            try:
                for h in idx.search(state_text, limit=external, category=category):
                    lines.append(f"- {h.render(240)}")
            except Exception:
                pass

    return "\n".join(lines)


# 兼容旧接口
def knowledge(category: str, stage: str, role: str, limit: int = 6) -> str:
    blk = must_block(category, stage, role)
    return blk if limit >= 6 else "\n".join(blk.splitlines()[:limit])


def audit() -> dict[str, int]:
    """赛前检查覆盖空洞：哪些格子里一条 must 都没有。"""
    out: dict[str, int] = {}
    for (cat, st, role), items in MUST.items():
        out[f"{cat}/{st}/{role}"] = len(items)
    return out


def gaps(categories: Iterable[str], stage_names: dict[str, list[str]]) -> list[str]:
    """列出**只靠通配兜底**的组合，直接当待办清单用。

    判据比"有内容"更严：一个格子如果只命中 `*/*/role` 或 `*/*/*`，
    运行时照样能跑，但那本质是通用提示，不是这个题型的专业判断。
    这些才是真正需要补人力的地方。
    """
    roles = ("route_planner", "task_planner", "executor")
    missing: list[str] = []
    for cat in categories:
        for st in stage_names.get(cat, []):
            for role in roles:
                specific = (cat, st, role) in MUST or (cat, "*", role) in MUST
                if not specific:
                    missing.append(f"{cat}/{st}/{role}")
    return missing


load()
