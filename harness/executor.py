"""执行层：动作生成 + 批量执行 + 输出归一化（准入层）。

三个接缝：
  Runner          —— 跑一条动作。默认是 `ShellRunner`（内部走后台 job），可换 OpenHands。
  InteractiveRunner —— 需要按提示符逐段交互的目标（pwn / 协议题）用这个。
  normalize       —— 把原始输出压成紧凑事实，绝不把整篇 dump 塞回上下文。

与旧版的差别（都是为了吞吐）：

1. **一个子目标可以给多条动作。** 侦察类动作（curl 首页、robots.txt、目录探测、nmap）
   互不依赖，一次给 4 条并发执行，墙钟从 4×15s 降到 max(15s)。有先后依赖的动作由模型
   自己用 `&&` 并进一条命令。
2. **长命令不再堵住轮次。** `ShellRunner` 后台起 job，超过等待窗口就返回半截输出 +
   job_id，下一轮可以 `status` 续读尾部。`| head` 也不再必要，管道缓冲问题一并消失。
3. **归一化保留头尾而不是砍掉尾部。** 侦察输出里最有用的信息常在末尾
   （扫描结束的汇总、最后的错误），而旧版 `[:600]` 正好把它切掉了。
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Protocol, Sequence

from . import knowledge, stages
from .blackboard import Blackboard
from .controller import FLAG_RE, Evidence
from .planner import LLM, _json
from .shell_bg import BackgroundShell, ShellError

EXEC_SYS = """你是攻击执行器。只负责一个明确子目标。

输出严格 JSON：
{"actions": [{"cmd":"<shell 命令>","why":"<这条命令要看什么>"}, ...],
 "claim":"<完成后应满足的 fact key>",
 "expect":"<成功的判据是什么>"}

关于 actions：
- 如果多条命令**互不依赖**，一次全给出来（最多 4 条），它们会并发执行，省一轮时间。
  典型：curl 看首页 + curl robots.txt + nmap 扫端口 + whatweb 指纹，四条一起发。
- 如果命令之间**有先后依赖**（后一条要用前一条的输出），必须并进同一条命令用 `&&` 或 `;`
  串起来，不要在 actions 里分开放——并发执行不保证顺序。
- 长耗时命令（nmap 全端口、gobuster 大字典、sqlmap）**不要加 `| head` 或 `| tail`**：
  输出会落盘，你下一轮用 status 读尾部即可；加管道反而会把边跑边出的输出憋没。

## 当前环境的事实（不要试探，试探就是浪费轮次）
- **靶场侧不出网。** 任何 `pip install`、`git clone`、`curl` 到公网、在线查 CVE 都必然超时，
  绝对不要尝试。漏洞情报只能靠已装工具的离线库和题目自身的版本泄露。
- 工具已预装。**不确定某个工具是否存在时，先 `command -v <tool>`**，
  不要先手搓协议客户端、OCR、转发器或加密实现——现成工具几乎都有。
- 靶机地址在下面的提示里显式给出，不要编 `http://target/` 这类占位符（会 DNS 失败白烧一轮）。

## claim 的写法
- 如果你这一步直接完成了当前阶段的里程碑，claim 必须**逐字**使用我给你的里程碑键。
- 如果只是取得中间线索，用一个你自己取的简短蛇形名字（如 robots_probed）。
  这类记录会被计入进展，但不会推进阶段。

## 什么时候必须写黑板（这是硬要求，不是建议）
每 ≤5 轮至少产出一张证据卡，换方向时也必须先写一张。判据是下面两类之一：
- **证据类**：凭据/密钥/中间产物（如 VM_KEY07）、端口与版本、2xx/302 命中、校验常量、
  路径存在性、文件哈希、报错原文关键行。
- **判断类**：某条路径被证伪（说明为什么）、切换假设（说明从什么换到什么）。
黑板空白会被判定为停滞并回收这条路线，所以宁可写短也要写。

不要解释，不要输出多余字段。"""

# 单轮动作上限：并发数太高会让输出难以归因，4 条是延迟与清晰度的折中
MAX_ACTIONS = 4


@dataclass
class RawResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    artifact: str | None = None  # 文件路径或内容，作为强证据
    job_id: str | None = None    # 后台 job 仍在此 id 上，可续读
    running: bool = False


@dataclass
class Step:
    action: str
    claim: str
    expect: str = ""
    evidence: Evidence | None = None
    raw: RawResult | None = None
    sub_actions: list[str] = field(default_factory=list)


class Runner(Protocol):
    """执行一条动作的接口。接 OpenHands / π 时实现这个即可。"""

    def run(self, action: str, timeout: float = 120) -> RawResult: ...


class InteractiveRunner(Protocol):
    """按提示符逐段交互。pwn / 自定义协议题用。"""

    def interact(self, action: str, exchanges: Sequence[str], timeout: float = 60) -> RawResult: ...


class ShellRunner:
    """容器内执行，内部是后台 job 表。

    `run()` 为了兼容 `Runner` 协议保持阻塞语义（等命令结束或超时），
    但 `run_batch()` 是并发版本——主循环与 `ExecutorAdapter` 都用它。
    """

    def __init__(
        self,
        cwd: str | None = None,
        allow: re.Pattern | None = None,
        timeout: float = 120,
        *,
        max_jobs: int = 8,
        job_timeout: float = 1800.0,
        out_dir: str | None = None,
    ) -> None:
        self.default_timeout = timeout
        self.shell = BackgroundShell(
            cwd=cwd,
            max_jobs=max_jobs,
            default_timeout=job_timeout,
            out_dir=out_dir,
            allow=allow,
        )

    # ---------- Runner 协议 ----------
    def run(self, action: str, timeout: float | None = None) -> RawResult:
        timeout = timeout or self.default_timeout
        try:
            job = self.shell.start(action, timeout=timeout)
        except ShellError as e:
            return RawResult(False, stderr=str(e), exit_code=126)
        res = self.shell.wait(job.job_id, timeout=timeout, lines=None)
        return RawResult(
            ok=res.ok,
            stdout=res.output,
            stderr="",
            exit_code=res.exit_code or 0,
            job_id=res.job_id,
        )

    # ---------- 并发批量 ----------
    def run_batch(
        self,
        actions: Sequence[str],
        *,
        max_wait: float | None = None,
        sync_wait: float = 1.5,
    ) -> RawResult:
        """并发跑一批命令，合并成一条 RawResult。

        超过 `max_wait` 仍未结束的 job 不杀，只把 job_id 带回来供下一轮续读。
        """
        max_wait = max_wait if max_wait is not None else self.default_timeout
        results = self.shell.run_batch(actions, sync_wait=sync_wait, max_wait=max_wait)

        chunks: list[str] = []
        running_ids: list[str] = []
        any_ok = False
        for i, r in enumerate(results, 1):
            any_ok = any_ok or r.ok
            if r.killed:
                state = "已杀"
            elif r.timeout:
                state = "超时"
            elif r.ok:
                state = "ok"
            elif r.job_id in [x.job_id for x in results if x.job_id] and "仍在运行" in r.output:
                state = "运行中"
            else:
                state = f"exit={r.exit_code}"
            if "仍在运行" in r.output:
                running_ids.append(r.job_id)
            body = r.output.strip()
            head = f"=== [{i}] {state} $ {actions[i - 1][:120]}"
            if r.job_id:
                head = f"=== [{i}] {state} job={r.job_id} $ {actions[i - 1][:120]}"
            chunks.append(head + "\n" + (body or "(无输出)"))

        exit_code = 0 if any_ok else 1
        return RawResult(
            ok=any_ok,
            stdout="\n\n".join(chunks),
            exit_code=exit_code,
            job_id=running_ids[0] if running_ids else None,
            running=bool(running_ids),
        )

    # ---------- 续读 ----------
    def status(self, job_id: str, offset: int = 0, lines: int = 200) -> str:
        return self.shell.status(job_id, offset=offset, lines=lines)

    def list_jobs(self) -> str:
        return self.shell.listing()

    def kill(self, job_id: str) -> str:
        return self.shell.kill(job_id)


class PexpectRunner:
    """交互式 runner：适合 pwn 的「先泄 canary 再给 payload」这类多段协议。

    `exchanges` 是逐段发送的字符串（每段后面自动补换行）。实现上优先用 pexpect；
    环境里没有 pexpect 时退化成「把输入拼成 here-doc 喂给命令」的单次模式，
    虽然拿不到中途的提示符，但至少不会整题跑不动。
    """

    def __init__(self, timeout: float = 60.0) -> None:
        self.default_timeout = timeout

    def interact(
        self,
        action: str,
        exchanges: Sequence[str],
        timeout: float | None = None,
        *,
        expect: str | None = None,
    ) -> RawResult:
        timeout = timeout or self.default_timeout
        try:
            import pexpect  # 预装在镜像里
        except ImportError:
            return self._fallback(action, exchanges, timeout)

        try:
            child = pexpect.spawn(action, timeout=timeout, encoding="utf-8", echo=False)
        except Exception as e:  # pexpect 的异常类型随版本变，统一兜住
            return RawResult(False, stderr=f"启动失败：{type(e).__name__}: {e}", exit_code=127)

        transcript: list[str] = []
        timed_out = False
        # 交互式目标的退出码经常不可靠（被 SIGKILL 收尾、或杀在上一个会话里），
        # 所以只要拿到了非空输出且不是超时，就认为这轮交互有产出。
        capture_ok = False
        try:
            for i, payload in enumerate(exchanges):
                if expect:
                    child.expect(expect)
                transcript.append(f"--- 第 {i + 1} 段之前收到 ---")
                transcript.append(child.before or "")
                child.sendline(payload)
                transcript.append(f">>> {payload}")
            if expect:
                child.expect(expect)

            # 交互式目标通常**不会自己退出**（cat、nc、交互式 memu 都是等输入），
            # 所以必须主动送 EOF 让它收尾，否则会一直挂到超时、
            # exitstatus 永远是 None，输出也拿不全。这是最容易忽略的一步。
            try:
                child.sendeof()
            except Exception:
                pass
            try:
                child.expect(pexpect.EOF)
            except Exception:
                pass
            tail = child.before or ""
            transcript.append(tail)
            capture_ok = bool("\n".join(transcript).strip())
        except Exception as e:
            text = type(e).__name__
            if "TIMEOUT" in text.upper():
                timed_out = True
            transcript.append(f"[交互异常] {text}: {e}")
        finally:
            child.close(force=True)
            code = child.exitstatus

        out = "\n".join(transcript)
        # 超时不算成功；但"有输出且正常收尾"必须算成功，
        # 否则 pwn 里那些被 SIGKILL 收尾的利用永远拿不到证据。
        ok = (not timed_out) and (code == 0 or code is None or capture_ok)
        return RawResult(
            ok=ok,
            stdout=out,
            exit_code=code if code is not None else -1,
            job_id=None,
        )

    def _fallback(self, action: str, exchanges: Sequence[str], timeout: float) -> RawResult:
        """没有 pexpect 时：把各段输入用换行拼起来喂给进程。"""
        payload = "\n".join(exchanges) + "\n"
        try:
            p = subprocess.run(
                action, shell=True, input=payload, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return RawResult(False, stderr=f"超时（{timeout}s）", exit_code=124)
        except OSError as e:
            return RawResult(False, stderr=f"执行失败：{e}", exit_code=127)
        return RawResult(p.returncode == 0, p.stdout, p.stderr, p.returncode)


# ---------- 归一化器 ----------
# 头尾都留：侦察输出里最有用的信息常在末尾（扫描汇总、最后一条错误），
# 旧版只留前 600 字符恰好把结论切掉，逼模型重复执行同一条命令。
HEAD_LINES = 60
TAIL_LINES = 40
MAX_CHARS = 6000


def normalize(action: str, r: RawResult, max_lines: int = HEAD_LINES) -> str:
    text = r.stdout or ""
    if r.stderr:
        text += ("\n" if text else "") + r.stderr

    # 带专用抽取器的工具先走专用逻辑：这些工具的原始输出噪声太大
    if re.search(r"\bnmap\b", action):
        ports = re.findall(r"^(\d+/\w+)\s+open\s+(\S+)", text, re.M)
        if ports:
            return "开放端口: " + ", ".join(f"{p}({s})" for p, s in ports)
        return "无开放端口"

    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "(无输出)"
    if len(lines) <= max_lines:
        return "\n".join(lines)[:MAX_CHARS]

    head = lines[:max_lines]
    tail = lines[-TAIL_LINES:]
    skipped = len(lines) - len(head) - len(tail)
    body = (
        "\n".join(head)
        + f"\n…（省略 {skipped} 行，可用 status/offset 或写文件后 sed/grep 查看）…\n"
        + "\n".join(tail)
    )
    return body[:MAX_CHARS]


def hard_fail_signal(r: RawResult) -> bool:
    """连接/解析/命令缺失类硬失败。这类失败重复出现说明方向错了，不只是运气差。"""
    blob = ((r.stdout or "") + (r.stderr or "")).lower()
    markers = (
        "could not resolve",
        "name or service not known",
        "connection refused",
        "connection timed out",
        "no route to host",
        "command not found",
        "permission denied",
        "no such file or directory",
        "ssl error",
    )
    return any(m in blob for m in markers)


class ExecutorAdapter:
    """把「一条子目标」变成「一批动作 + 证据」。"""

    def __init__(
        self,
        bb: Blackboard,
        llm: LLM,
        runner,
        *,
        max_actions: int = MAX_ACTIONS,
    ) -> None:
        self.bb = bb
        self.llm = llm
        self.runner = runner
        self.max_actions = max(1, max_actions)

    def step(self, task_id: str, subgoal: str, stage_name: str, hint: str = "") -> Step:
        t = self.bb.task(task_id)
        st = stages.stage(t.category, t.stage)
        tried = self.bb.tried_actions(task_id, 8)
        facts = self.bb.facts(task_id)

        # 静态前缀在前、动态状态在后 —— 同一阶段的多次调用前缀一致，KV 缓存可命中
        prefix = (
            f"题型 {t.category}，阶段 {st.name}：{st.goal}\n"
            f"当前阶段的里程碑键（完成即用它作 claim）：{st.requires}\n"
            f"操作知识：\n{knowledge.must_block(t.category, st.name, 'executor')}\n"
        )
        ref = knowledge.ref_block(
            t.category, st.name, f"{subgoal} {hint} {facts}", "executor"
        )
        # 目标地址必须显式给出：否则模型会编 http://target/ 这种占位符，
        # 命令必然 DNS 失败，整轮算力白花（实测过）。
        target_line = (
            f"目标地址：{t.target}\n" if t.target
            else "目标地址：未提供（这是一道离线题，只操作本地文件）\n"
        )
        # 停滞提醒放在动态段末尾：只在真有提醒时才出现，不影响缓存前缀，
        # 而且离"给出动作"最近，模型更可能照着改。
        nudges = self.bb.take_nudges(task_id)
        nudge_block = ("\n" + "\n\n".join(nudges) + "\n") if nudges else ""
        prompt = (
            prefix
            + target_line
            + (f"题面：{t.brief[:800]}\n" if t.brief else "")
            + f"\n当前子目标：{subgoal}\n"
            + f"已试动作（含失败）：{tried}\n"
            + f"已知事实：{facts}\n"
            + (f"\n参考：\n{ref}\n" if ref else "")
            + (f"额外提示：{hint}\n" if hint else "")
            + nudge_block
            + "给出动作。"
        )
        out = _json(self.llm.complete(role="executor", system=EXEC_SYS, prompt=prompt))
        actions = self._parse_actions(out)
        claim = str(out.get("claim", st.requires)).strip()
        if not actions:
            return Step("", claim, out.get("expect", ""))

        raw = self._execute(actions)
        joined = "\n&&\n".join(actions)
        return Step(
            joined,
            claim,
            str(out.get("expect", "")),
            raw=raw,
            sub_actions=actions,
        )

    # ---------- 内部 ----------
    def _parse_actions(self, out: dict) -> list[str]:
        """兼容两种输出：`actions` 数组（新）与单个 `action`（旧 / 模型偷懒）。"""
        raw: list[str] = []
        items = out.get("actions")
        if isinstance(items, list):
            for it in items:
                if isinstance(it, str):
                    cmd = it
                elif isinstance(it, dict):
                    cmd = str(it.get("cmd") or it.get("action") or "")
                else:
                    cmd = ""
                cmd = cmd.strip()
                if cmd:
                    raw.append(cmd)
        single = str(out.get("action", "")).strip()
        if single and not raw:
            raw.append(single)

        # 去重：同一批里重复命令没有意义，还会污染循环检测
        seen: set[str] = set()
        uniq: list[str] = []
        for cmd in raw:
            if cmd in seen:
                continue
            seen.add(cmd)
            uniq.append(cmd)
        return uniq[: self.max_actions]

    def _execute(self, actions: list[str]):
        batch = getattr(self.runner, "run_batch", None)
        if batch is not None:
            return batch(actions)
        # 没有批量能力的 runner（如假 runner / 第三方 adapter）：退化成顺序执行
        outs = []
        ok_any = False
        for cmd in actions:
            r = self.runner.run(cmd)
            ok_any = ok_any or r.ok
            outs.append(f"=== $ {cmd[:120]}\n{r.stdout.strip() or r.stderr.strip() or '(无输出)'}")
        return RawResult(ok_any, "\n\n".join(outs), exit_code=0 if ok_any else 1)

    def to_evidence(self, step: Step, task_id: str) -> Evidence:
        """把执行结果转成控制器能审的证据。这是唯一生成证据的地方。

        注意：这里只做归一化，不写 attempts——尝试由主循环记一次，
        否则循环计数会翻倍，阈值 3 实际等于重复 1.5 次。

        flag 从原始输出里正则抽取后附上，但**定级**仍交给控制器与验证器：
        执行层只是搬运候选串，没有判定权。
        """
        raw = step.raw or RawResult(False)
        summary = normalize(step.action, raw)
        flag = None
        m = FLAG_RE.search(raw.stdout or "")
        if m:
            flag = m.group(0)
        # 后台任务还在跑：算"有产出但未定"，交 stdout_excerpt 档，不升级为 artifact
        if raw.running:
            return Evidence(step.claim, "stdout_excerpt", summary, True, flag=flag)
        if raw.artifact:
            return Evidence(step.claim, "artifact", raw.artifact, raw.ok, flag=flag)
        if flag:
            return Evidence(step.claim, "verifier", summary, raw.ok, flag=flag)
        if raw.ok:
            return Evidence(step.claim, "stdout_excerpt", summary, raw.ok)
        return Evidence(step.claim, "exit_code", summary, raw.ok)
