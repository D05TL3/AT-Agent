"""结构化共享记忆（黑板）。

对应论文 3.3 的 structured memory + state capsule，但落成关系库而不是对话上下文：
- facts      已验证事实（键值 upsert，跨路线共享）
- falsified  已证伪假设（planner 提案时先过滤，避免重跑死路）
- attempts   每个动作的规范化哈希，循环检测 O(1)
- routes     候选路线（并行分支的状态机，按阶段隔离）
- subgoals   路线拆出来的可验证子目标
- capsules   每个阶段结束时的压缩状态，回喂给 planner

线程安全：所有公开方法由 `@synchronized` 串行化。锁是方法级的，单次黑板操作是
微秒级；真正耗时的 LLM 调用刻意**不**持锁，否则并发就没有意义。
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import functools
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    category    TEXT NOT NULL DEFAULT 'misc',
    status      TEXT NOT NULL DEFAULT 'open',   -- open|active|parked|expired|solved
    stage       INTEGER NOT NULL DEFAULT 0,
    stage_count INTEGER NOT NULL DEFAULT 4,     -- 该题型的阶段总数（调度器估可行性用）
    budget      REAL NOT NULL DEFAULT 1800,     -- 该题独立倒计时（秒）
    spent       REAL NOT NULL DEFAULT 0,
    target      TEXT NOT NULL DEFAULT '',       -- 靶场地址，executor 用它替代占位符
    brief       TEXT NOT NULL DEFAULT '',       -- 题面摘要，进 planner 的观测
    points      REAL NOT NULL DEFAULT 0,        -- 平台给的分值，难度先验
    solves      INTEGER NOT NULL DEFAULT 0,     -- 平台给的解出人数，难度先验
    pulls       INTEGER NOT NULL DEFAULT 0,
    reward_sum  REAL NOT NULL DEFAULT 0,
    note        TEXT DEFAULT '',
    -- 本题开工时刻（unix 秒）。flag 主时钟要用它算"多久没有新进展"。
    -- 不能拿 spent 代替：spent 只在 charge() 里累加，主循环根本没调过它。
    started_at  REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS routes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    stage       INTEGER NOT NULL DEFAULT 0,
    hypothesis  TEXT NOT NULL,
    h_hash      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'live',   -- live|merged|dead|won
    parent      INTEGER,
    UNIQUE (task_id, h_hash, stage)
);
CREATE TABLE IF NOT EXISTS subgoals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id    INTEGER NOT NULL,
    text        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'todo'    -- todo|done|failed
);
CREATE TABLE IF NOT EXISTS attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    route_id    INTEGER,
    a_hash      TEXT NOT NULL,
    action      TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    result      TEXT,
    ts          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts ON attempts (task_id, a_hash);
CREATE TABLE IF NOT EXISTS facts (
    task_id     TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    evidence    TEXT DEFAULT '',
    verified    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (task_id, key)
);
CREATE TABLE IF NOT EXISTS falsified (
    task_id     TEXT NOT NULL,
    h_hash      TEXT NOT NULL,
    hypothesis  TEXT NOT NULL,
    reason      TEXT DEFAULT '',
    PRIMARY KEY (task_id, h_hash)
);
CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,                  -- script|payload|address|primitive
    name        TEXT NOT NULL,
    body        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capsules (
    task_id     TEXT NOT NULL,
    stage       INTEGER NOT NULL,
    summary     TEXT NOT NULL,
    PRIMARY KEY (task_id, stage)
);
-- 停滞提醒队列：控制器写入，executor 下一轮取走并注入 prompts。
-- 单独成表而不是塞进 facts，是因为提醒不是"事实"——它不进 planner 观测，
-- 也不应该被当成进展（否则提醒本身就会让停滞判据失效）。
CREATE TABLE IF NOT EXISTS nudges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    text        TEXT NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    ts          REAL NOT NULL
);
"""

_WS = re.compile(r"\s+")


def synchronized(fn: Callable[..., Any]) -> Callable[..., Any]:
    """给黑板公开方法加锁。RLock：snapshot() 内部会调 facts() 等已加锁方法。"""

    @functools.wraps(fn)
    def wrapper(self: "Blackboard", *a: Any, **kw: Any) -> Any:
        with self._lock:
            return fn(self, *a, **kw)

    return wrapper


def action_hash(action: str) -> str:
    """动作规范化哈希。归一化掉空白差异，否则同一命令换个缩进就算新动作。"""
    return hashlib.sha256(_WS.sub(" ", action).strip().encode()).hexdigest()[:16]


def hyp_hash(hypothesis: str) -> str:
    return hashlib.sha256(_WS.sub(" ", hypothesis).strip().lower().encode()).hexdigest()[:16]


@dataclass
class Task:
    id: str
    category: str
    status: str
    stage: int
    stage_count: int
    budget: float
    spent: float
    points: float
    solves: int
    pulls: int
    reward_sum: float
    note: str
    target: str = ""
    brief: str = ""
    started_at: float = 0.0

    @property
    def remaining(self) -> float:
        return self.budget - self.spent

    @property
    def mean_reward(self) -> float:
        return self.reward_sum / self.pulls if self.pulls else 0.0


class Blackboard:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        if str(path) != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self._migrate()
        self.db.commit()

    def _migrate(self) -> None:
        """给旧库补新增列。比赛现场不会重建库，所以迁移必须幂等且不丢数据。"""
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(tasks)").fetchall()}
        if "started_at" not in cols:
            self.db.execute("ALTER TABLE tasks ADD COLUMN started_at REAL NOT NULL DEFAULT 0")
        # 老库里的题没有开工时刻，按"现在"补，避免一上来就被判成 flag 停滞
        self.db.execute("UPDATE tasks SET started_at=? WHERE started_at=0", (time.time(),))

    # ---------- 任务 ----------
    @synchronized
    def add_task(
        self,
        task_id: str,
        category: str = "misc",
        budget: float = 1800,
        *,
        points: float = 0,
        solves: int = 0,
        stage_count: int | None = None,
        target: str = "",
        brief: str = "",
    ) -> None:
        """登记一道题。stage_count 不给就按题型模板自动取。"""
        if stage_count is None:
            from . import stages as _stages

            stage_count = len(_stages.stages_for(category))
        self.db.execute(
            "INSERT OR IGNORE INTO tasks "
            "(id, category, budget, points, solves, stage_count, target, brief, started_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                task_id,
                category,
                budget,
                points,
                solves,
                stage_count,
                target,
                brief[:2000],
                time.time(),
            ),
        )
        self.db.commit()

    @synchronized
    def task(self, task_id: str) -> Task:
        r = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if r is None:
            raise KeyError(task_id)
        return Task(**{k: r[k] for k in r.keys()})

    @synchronized
    def tasks(self, status: Iterable[str] | None = None) -> list[Task]:
        if status:
            marks = ",".join("?" * len(status))
            rows = self.db.execute(
                f"SELECT * FROM tasks WHERE status IN ({marks}) ORDER BY id", tuple(status)
            ).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM tasks ORDER BY id").fetchall()
        return [Task(**{k: r[k] for k in r.keys()}) for r in rows]

    @synchronized
    def set_task(self, task_id: str, **fields: Any) -> None:
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE tasks SET {sets} WHERE id=?", (*fields.values(), task_id))
        self.db.commit()

    @synchronized
    def charge(self, task_id: str, seconds: float, reward: float = 0.0, pulls: int = 1) -> None:
        """记一次调度抽样的实际开销与收益（UCB 用）。"""
        self.db.execute(
            "UPDATE tasks SET spent=spent+?, reward_sum=reward_sum+?, pulls=pulls+? WHERE id=?",
            (seconds, reward, pulls, task_id),
        )
        self.db.commit()

    # ---------- 路线 ----------
    @synchronized
    def add_route(
        self, task_id: str, hypothesis: str, parent: int | None = None, stage: int = 0
    ) -> int | None:
        """路线按 (hash, stage) 唯一：同一假设在新阶段是新的实验，不复用旧分支。"""
        h = hyp_hash(hypothesis)
        if self._is_falsified(task_id, hypothesis):
            return None
        cur = self.db.execute(
            "INSERT OR IGNORE INTO routes (task_id,stage,hypothesis,h_hash,parent) "
            "VALUES (?,?,?,?,?)",
            (task_id, stage, hypothesis, h, parent),
        )
        self.db.commit()
        if cur.rowcount:
            return int(cur.lastrowid)
        row = self.db.execute(
            "SELECT id FROM routes WHERE task_id=? AND h_hash=? AND stage=?",
            (task_id, h, stage),
        ).fetchone()
        return int(row["id"]) if row else None

    @synchronized
    def live_routes(self, task_id: str) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM routes WHERE task_id=? AND status='live' ORDER BY id", (task_id,)
        ).fetchall()

    @synchronized
    def live_routes_at(self, task_id: str, stage: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM routes WHERE task_id=? AND stage=? AND status='live' ORDER BY id",
            (task_id, stage),
        ).fetchall()

    @synchronized
    def set_route(self, route_id: int, status: str) -> None:
        self.db.execute("UPDATE routes SET status=? WHERE id=?", (status, route_id))
        self.db.commit()

    @synchronized
    def route(self, route_id: int) -> sqlite3.Row:
        return self.db.execute("SELECT * FROM routes WHERE id=?", (route_id,)).fetchone()

    # ---------- 子目标 ----------
    @synchronized
    def add_subgoal(self, route_id: int, text: str) -> None:
        self.db.execute("INSERT INTO subgoals (route_id,text) VALUES (?,?)", (route_id, text))
        self.db.commit()

    @synchronized
    def next_subgoal(self, route_id: int) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM subgoals WHERE route_id=? AND status='todo' ORDER BY id LIMIT 1",
            (route_id,),
        ).fetchone()

    @synchronized
    def close_subgoal(self, subgoal_id: int, done: bool) -> None:
        self.db.execute(
            "UPDATE subgoals SET status=? WHERE id=?", ("done" if done else "failed", subgoal_id)
        )
        self.db.commit()

    @synchronized
    def subgoal_stats(self, route_id: int) -> tuple[int, int]:
        done = self.db.execute(
            "SELECT COUNT(*) c FROM subgoals WHERE route_id=? AND status='done'", (route_id,)
        ).fetchone()["c"]
        todo = self.db.execute(
            "SELECT COUNT(*) c FROM subgoals WHERE route_id=? AND status='todo'", (route_id,)
        ).fetchone()["c"]
        return done, todo

    # ---------- 动作与循环检测 ----------
    @synchronized
    def record_attempt(
        self, task_id: str, route_id: int | None, action: str, ok: bool, result: str = ""
    ) -> str:
        h = action_hash(action)
        self.db.execute(
            "INSERT INTO attempts (task_id,route_id,a_hash,action,ok,result,ts) "
            "VALUES (?,?,?,?,?,?,?)",
            (task_id, route_id, h, action[:2000], int(ok), result[:2000], time.time()),
        )
        self.db.commit()
        return h

    @synchronized
    def count_attempt(self, task_id: str, a_hash: str) -> int:
        return self.db.execute(
            "SELECT COUNT(*) c FROM attempts WHERE task_id=? AND a_hash=?", (task_id, a_hash)
        ).fetchone()["c"]

    @synchronized
    def repeated(self, task_id: str, a_hash: str, limit: int = 3) -> bool:
        return self.count_attempt(task_id, a_hash) >= limit

    @synchronized
    def tried_actions(self, task_id: str, limit: int = 40) -> list[str]:
        rows = self.db.execute(
            "SELECT action, ok FROM attempts WHERE task_id=? ORDER BY id DESC LIMIT ?",
            (task_id, limit),
        ).fetchall()
        return [f"{'ok ' if r['ok'] else 'FAIL'} {r['action']}" for r in rows]

    # ---------- 事实 / 证伪 ----------
    @synchronized
    def add_fact(
        self, task_id: str, key: str, value: str, evidence: str = "", verified: bool = False
    ) -> bool:
        """返回 True 表示这条事实是新的或值有变化（调度器的收益信号之一）。"""
        old = self.db.execute(
            "SELECT value FROM facts WHERE task_id=? AND key=?", (task_id, key)
        ).fetchone()
        changed = old is None or old["value"] != value
        self.db.execute(
            "INSERT INTO facts (task_id,key,value,evidence,verified) VALUES (?,?,?,?,?) "
            "ON CONFLICT(task_id,key) DO UPDATE SET value=excluded.value, "
            "evidence=excluded.evidence, verified=excluded.verified",
            (task_id, key, value, evidence, int(verified)),
        )
        self.db.commit()
        return changed

    @synchronized
    def facts(self, task_id: str) -> dict[str, str]:
        rows = self.db.execute(
            "SELECT key, value FROM facts WHERE task_id=? ORDER BY key", (task_id,)
        ).fetchall()
        return {r["key"]: r["value"] for r in rows}

    @synchronized
    def has_fact(self, task_id: str, key: str) -> bool:
        return bool(
            self.db.execute(
                "SELECT 1 FROM facts WHERE task_id=? AND key=?", (task_id, key)
            ).fetchone()
        )

    @synchronized
    def add_falsified(self, task_id: str, hypothesis: str, reason: str = "") -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO falsified (task_id,h_hash,hypothesis,reason) VALUES (?,?,?,?)",
            (task_id, hyp_hash(hypothesis), hypothesis, reason),
        )
        self.db.commit()

    def _is_falsified(self, task_id: str, hypothesis: str) -> bool:
        """内部无锁版，供已持锁的方法调用（RLock 下也可直接复用 is_falsified）。"""
        return bool(
            self.db.execute(
                "SELECT 1 FROM falsified WHERE task_id=? AND h_hash=?",
                (task_id, hyp_hash(hypothesis)),
            ).fetchone()
        )

    @synchronized
    def is_falsified(self, task_id: str, hypothesis: str) -> bool:
        return self._is_falsified(task_id, hypothesis)

    @synchronized
    def falsified(self, task_id: str) -> list[str]:
        rows = self.db.execute(
            "SELECT hypothesis FROM falsified WHERE task_id=? ORDER BY h_hash", (task_id,)
        ).fetchall()
        return [r["hypothesis"] for r in rows]

    # ---------- 工件 ----------
    @synchronized
    def add_artifact(self, task_id: str, kind: str, name: str, body: str) -> None:
        self.db.execute(
            "INSERT INTO artifacts (task_id,kind,name,body) VALUES (?,?,?,?)",
            (task_id, kind, name, body[:20000]),
        )
        self.db.commit()

    @synchronized
    def artifacts(self, task_id: str) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT kind,name,body FROM artifacts WHERE task_id=? ORDER BY id", (task_id,)
        ).fetchall()

    # ---------- 停滞提醒 ----------
    @synchronized
    def add_nudge(self, task_id: str, text: str) -> None:
        self.db.execute(
            "INSERT INTO nudges (task_id, text, ts) VALUES (?,?,?)",
            (task_id, text[:2000], time.time()),
        )
        self.db.commit()

    @synchronized
    def take_nudges(self, task_id: str) -> list[str]:
        """取出未消费的提醒并标记已消费。注入下一轮 prompt 用。"""
        rows = self.db.execute(
            "SELECT id, text FROM nudges WHERE task_id=? AND consumed=0 ORDER BY id",
            (task_id,),
        ).fetchall()
        if not rows:
            return []
        ids = [r["id"] for r in rows]
        marks = ",".join("?" * len(ids))
        self.db.execute(f"UPDATE nudges SET consumed=1 WHERE id IN ({marks})", ids)
        self.db.commit()
        return [r["text"] for r in rows]

    # ---------- 子目标补充 ----------
    @synchronized
    def replenish_count(self, route_id: int) -> int:
        """该路线已重拆过几次子目标。表可能还没建，返回 0。"""
        try:
            row = self.db.execute(
                "SELECT n FROM replenish WHERE route_id=?", (route_id,)
            ).fetchone()
        except sqlite3.OperationalError:
            return 0
        return int(row["n"]) if row else 0

    @synchronized
    def bump_replenish(self, route_id: int) -> int:
        """记录该路线重拆子目标的次数，返回新值。用于封顶。"""
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS replenish (route_id INTEGER PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)"
        )
        self.db.execute(
            "INSERT INTO replenish (route_id, n) VALUES (?, 1) "
            "ON CONFLICT(route_id) DO UPDATE SET n = n + 1",
            (route_id,),
        )
        self.db.commit()
        row = self.db.execute("SELECT n FROM replenish WHERE route_id=?", (route_id,)).fetchone()
        return int(row["n"]) if row else 1

    # ---------- 状态胶囊 ----------
    @synchronized
    def set_capsule(self, task_id: str, stage: int, summary: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO capsules (task_id,stage,summary) VALUES (?,?,?)",
            (task_id, stage, summary),
        )
        self.db.commit()

    @synchronized
    def capsule(self, task_id: str) -> dict[int, str]:
        rows = self.db.execute(
            "SELECT stage,summary FROM capsules WHERE task_id=? ORDER BY stage", (task_id,)
        ).fetchall()
        return {r["stage"]: r["summary"] for r in rows}

    # ---------- 视图 ----------
    @synchronized
    def snapshot(self, task_id: str, max_routes: int = 6) -> dict[str, Any]:
        """给 planner 的压缩视图。永远不把原始工具输出塞进去。"""
        t = self.task(task_id)
        routes = [
            {
                "id": r["id"],
                "hypothesis": r["hypothesis"],
                "status": r["status"],
                "progress": "%d/%d" % self.subgoal_stats(r["id"]),
            }
            for r in self.db.execute(
                "SELECT * FROM routes WHERE task_id=? ORDER BY id DESC LIMIT ?",
                (task_id, max_routes),
            ).fetchall()
        ]
        return {
            "task": task_id,
            "category": t.category,
            "stage": t.stage,
            "target": t.target,
            "brief": t.brief[:600],
            "remaining_s": round(t.remaining, 1),
            "facts": self.facts(task_id),
            "falsified": self.falsified(task_id)[-10:],
            "routes": routes,
            "capsules": self.capsule(task_id),
            "recent_actions": self.tried_actions(task_id, 12),
            "artifacts": [f"{r['kind']}:{r['name']}" for r in self.artifacts(task_id)][-10:],
        }

    @synchronized
    def dumps(self, task_id: str) -> str:
        return json.dumps(self.snapshot(task_id), ensure_ascii=False, indent=2)
