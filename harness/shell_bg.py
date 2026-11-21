"""后台 job 式 shell 执行。

为什么不直接用 `subprocess.run`：

1. **长命令会把整个轮次堵死。** nmap / gobuster / sqlmap 跑几分钟，阻塞执行意味着
   这几分钟里模型什么都不能做，而模型单次调用本身要 9~15s，等于把并发优势全吃掉。
   这里所有命令默认后台启动、立刻返回 job_id，模型继续构造下一条命令，需要时再
   `wait`/`status` 拉输出。
2. **输出只能留在内存里，还被截断。** 阻塞式只能拿到最终 stdout，中途想看一眼不行；
   `| head` 更糟——管道缓冲会让边跑边出的输出一直憋到进程结束。这里每个 job 的
   stdout/stderr 合并落盘到临时文件，按 byte offset 分页读，跑多久都能看尾部。
3. **无法取消。** 方向错了想杀掉正在跑的扫描，阻塞式只能等超时。这里
   `start_new_session=True` 建独立进程组，`kill` 整组，避免 curl/python 子进程残留。

语义与参考实现（VANexus/tsecbench-agent 的 async shell）对齐：
  - `start` 有一个很小的同步等待窗口（默认 1.5s），秒回的命令直接带回完整输出；
  - 多 job 可并发，`wait_any` 一次盯多个；
  - 每个 job 有硬超时，到点被杀但**输出文件仍在**；
  - `reap()` 在所有读操作里顺手清理超时 job，不需要额外线程。
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

# 一次读取的默认上限：既够看足够多的上下文，又不至于把整篇 dump 塞回 prompt
DEFAULT_READ_LINES = 400
# start 时的同步等待窗口：命令若在此窗口内结束，直接带回完整输出
DEFAULT_SYNC_WAIT = 1.5


class ShellError(RuntimeError):
    pass


@dataclass
class JobResult:
    """一条命令跑完之后的可交付结果。"""

    job_id: str
    ok: bool
    exit_code: int | None
    output: str
    killed: bool = False
    timeout: bool = False


@dataclass
class Job:
    job_id: str
    command: str
    label: str
    cwd: str | None
    proc: subprocess.Popen
    out_path: Path
    started_at: float
    timeout: float | None
    branch: int = 0
    exit_code: int | None = None
    killed: bool = False
    timed_out: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ---------- 状态 ----------
    @property
    def finished(self) -> bool:
        return self.exit_code is not None

    def elapsed(self) -> float:
        return time.time() - self.started_at

    def state(self) -> str:
        if self.killed:
            return "killed"
        if self.timed_out:
            return "timeout"
        if self.finished:
            return "ok" if self.exit_code == 0 else f"exit={self.exit_code}"
        return "running"

    def size(self) -> int:
        try:
            return self.out_path.stat().st_size
        except OSError:
            return 0

    # ---------- 输出 ----------
    def read(self, offset: int = 0, lines: int | None = None) -> tuple[str, int]:
        """按 byte offset 分页读输出，返回 (文本, next_offset)。

        分页而不是整篇返回，是因为一次 nmap 全量扫描可能有几十万行；模型真正需要的
        通常只是尾部。调用方带 `offset=next_offset` 就能接着往下读。
        """
        try:
            data = self.out_path.read_bytes()
        except OSError:
            return "", offset
        offset = max(0, min(offset, len(data)))
        text = data[offset:].decode("utf-8", "replace")
        all_lines = text.splitlines()
        if lines is not None and lines > 0:
            taken = all_lines[:lines]
        else:
            taken = all_lines
        consumed = sum(len(ln.encode("utf-8")) + 1 for ln in taken)
        next_offset = offset + min(consumed, len(data) - offset)
        body = "\n".join(taken)
        if len(taken) < len(all_lines):
            body += f"\n…（还有 {len(all_lines) - len(taken)} 行，用 offset={next_offset} 续读）"
        return body, next_offset

    # ---------- 控制 ----------
    def refresh(self) -> None:
        """同步进程状态；顺带执行超时收割。"""
        with self._lock:
            if self.finished:
                return
            rc = self.proc.poll()
            if rc is not None:
                self.exit_code = rc
                return
            if self.timeout is not None and self.elapsed() >= self.timeout:
                self.timed_out = True
                self._kill_group()

    def _kill_group(self) -> None:
        self.killed = True
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                self.proc.kill()
            except OSError:
                pass
        rc = self.proc.poll()
        if rc is not None:
            self.exit_code = rc
        else:
            self.exit_code = -9

    def kill(self, reason: str = "user") -> None:
        # 不在这里判 finished：refresh() 可能刚把 exit_code 填上而进程还没被回收，
        # 而 win_quota 场景下我们无论如何都要确保它不再产出。
        with self._lock:
            if reason == "timeout":
                self.timed_out = True
            if not self.finished:
                self._kill_group()
            elif self.killed:
                return

    def result(self, lines: int | None = None) -> JobResult:
        text, _ = self.read(0, lines)
        return JobResult(
            job_id=self.job_id,
            ok=(self.exit_code == 0) and not self.killed,
            exit_code=self.exit_code,
            output=text,
            killed=self.killed,
            timeout=self.timed_out,
        )


class BackgroundShell:
    """一台机器上的 job 表。每题一个实例，互不干扰。"""

    def __init__(
        self,
        *,
        cwd: str | None = None,
        max_jobs: int = 8,
        default_timeout: float = 1800.0,
        out_dir: str | None = None,
        allow: re.Pattern | None = None,
    ) -> None:
        self.cwd = cwd
        self.max_jobs = max_jobs
        self.default_timeout = default_timeout
        self.out_dir = Path(out_dir) if out_dir else Path(tempfile.gettempdir())
        self.allow = allow
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._seq = 0

    # ---------- 内部 ----------
    def _new_id(self) -> str:
        with self._lock:
            self._seq += 1
            return f"j{self._seq:03d}"

    def _open_log(self, job_id: str):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"shell_{job_id}_{os.getpid()}.log"
        fh = open(path, "wb", buffering=0)
        return path, fh

    def _reap(self) -> None:
        for job in list(self._jobs.values()):
            job.refresh()

    def _live(self) -> list[Job]:
        self._reap()
        return [j for j in self._jobs.values() if not j.finished]

    # ---------- 启动 ----------
    def start(
        self,
        command: str,
        *,
        label: str = "",
        cwd: str | None = None,
        timeout: float | None = None,
        branch: int = 0,
    ) -> Job:
        command = (command or "").strip()
        if not command:
            raise ShellError("空命令")
        if self.allow and not self.allow.search(command):
            raise ShellError("被策略拦截")

        # 座位管理：满了先收尸，再不行就杀掉最久的那条，保证新命令总能起来
        live = self._live()
        if len(live) >= self.max_jobs:
            live.sort(key=lambda j: j.started_at)
            live[0].kill("quota")

        job_id = self._new_id()
        path, fh = self._open_log(job_id)
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=cwd or self.cwd,
                stdin=subprocess.DEVNULL,
                stdout=fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # 独立进程组：kill 时整组带走
            )
        except OSError as e:
            fh.close()
            raise ShellError(f"无法启动：{type(e).__name__}: {e}") from e
        finally:
            try:
                fh.close()
            except OSError:
                pass

        job = Job(
            job_id=job_id,
            command=command,
            label=label or "",
            cwd=cwd or self.cwd,
            proc=proc,
            out_path=path,
            started_at=time.time(),
            timeout=timeout if timeout is not None else self.default_timeout,
            branch=branch,
        )
        self._jobs[job_id] = job
        self._order.append(job_id)
        return job

    # ---------- 读取 ----------
    def get(self, key: str) -> Job | None:
        """按 job_id 或 label 找 job。"""
        if key in self._jobs:
            return self._jobs[key]
        hits = [j for j in self._jobs.values() if j.label and j.label == key]
        if len(hits) == 1:
            return hits[0]
        return None

    def wait(
        self, key: str, timeout: float = 60.0, lines: int | None = DEFAULT_READ_LINES
    ) -> JobResult:
        job = self.get(key)
        if job is None:
            raise ShellError(f"没有这个 job：{key}")
        deadline = time.time() + max(0.0, timeout)
        while time.time() < deadline:
            job.refresh()
            if job.finished:
                break
            time.sleep(0.15)
        job.refresh()
        return job.result(lines)

    def wait_any(
        self, keys: Sequence[str], timeout: float = 60.0, lines: int | None = DEFAULT_READ_LINES
    ) -> tuple[JobResult, list[str]]:
        """等任意一个结束，返回 (该 job 结果, 仍在跑的 job_id 列表)。"""
        jobs = [self.get(k) for k in keys]
        jobs = [j for j in jobs if j is not None]
        if not jobs:
            raise ShellError("wait_any 没有可用的 job")
        deadline = time.time() + max(0.0, timeout)
        while time.time() < deadline:
            for j in jobs:
                j.refresh()
                if j.finished:
                    running = [x.job_id for x in jobs if not x.finished]
                    return j.result(lines), running
            time.sleep(0.15)
        # 超时：返回进展最多（输出最大）的那条，避免干等
        jobs.sort(key=lambda j: j.size(), reverse=True)
        running = [x.job_id for x in jobs if not x.finished]
        return jobs[0].result(lines), running

    def status(self, key: str, offset: int = 0, lines: int | None = DEFAULT_READ_LINES) -> str:
        job = self.get(key)
        if job is None:
            return f"没有这个 job：{key}"
        job.refresh()
        body, nxt = job.read(offset, lines)
        head = (
            f"[job {job.job_id}{' (' + job.label + ')' if job.label else ''}] "
            f"{job.state()}  {job.elapsed():.0f}s  out={job.size()}B  next_offset={nxt}"
        )
        return head + ("\n" + body if body else "")

    def listing(self) -> str:
        self._reap()
        if not self._jobs:
            return "（没有 job）"
        rows = []
        for job in sorted(self._jobs.values(), key=lambda j: j.started_at):
            label = f" ({job.label})" if job.label else ""
            rows.append(
                f"{job.job_id}{label}  {job.state():<12} {job.elapsed():>6.0f}s "
                f"out={job.size():>8}B  $ {job.command[:70]}"
            )
        return "\n".join(rows)

    def kill(self, key: str) -> str:
        job = self.get(key)
        if job is None:
            return f"没有这个 job：{key}"
        job.kill("user")
        return f"[job {job.job_id}] 已杀，输出仍在 {job.out_path}"

    def kill_all(self) -> None:
        for job in self._jobs.values():
            job.kill("shutdown")

    # ---------- 批量 ----------
    def run_batch(
        self,
        commands: Sequence[str],
        *,
        sync_wait: float = DEFAULT_SYNC_WAIT,
        max_wait: float = 240.0,
        timeout: float | None = None,
        branch: int = 0,
    ) -> list[JobResult]:
        """并发启动一批命令，最多等 `max_wait` 秒。

        这是吞吐的关键：一轮里发 4 条互不依赖的侦察命令，墙钟时间等于最慢那条，
        而不是 4 条之和。有先后依赖的命令必须由模型并进同一条 shell（用 && 或 ;），
        因为并发不保证顺序。

        `max_wait` 到点仍未结束的 job **不杀**，只在结果里标注 `still running` 并给出
        可续读的 job_id —— 长扫描（nmap 全端口、gobuster 大字典）本来就不该在一个轮次
        里等完，模型下一轮再 `status` 读尾部即可。
        """
        jobs: list[Job | ShellError] = []
        for i, cmd in enumerate(commands):
            try:
                jobs.append(self.start(cmd, label=f"b{i + 1}", timeout=timeout, branch=branch))
            except ShellError as e:
                jobs.append(e)
        if not jobs:
            return []

        # 同步窗口是"最多等这么久直到全部结束"，而不是"一律睡满"：
        # 秒回的命令必须立刻返回，否则每条快命令都白等 1.5s，批量就失去意义了。
        window_end = time.time() + min(sync_wait, max(0.0, max_wait))
        while time.time() < window_end:
            pending = [j for j in jobs if isinstance(j, Job)]
            for j in pending:
                j.refresh()
            if all(j.finished for j in pending):
                break
            time.sleep(min(0.05, max(0.0, window_end - time.time())))

        deadline = time.time() + max(0.0, max_wait - sync_wait)
        running = []
        for j in jobs:
            if isinstance(j, Job):
                j.refresh()
                if not j.finished:
                    running.append(j)
        # 窗口内还没结束的，一起等到 deadline（并发而不是串行等，墙钟 = 最慢那条）
        while running:
            if time.time() >= deadline:
                break
            for job in list(running):
                job.refresh()
                if job.finished:
                    running.remove(job)
            if running:
                time.sleep(min(0.15, max(0.0, deadline - time.time())))

        results: list[JobResult] = []
        for job in jobs:
            if isinstance(job, ShellError):
                results.append(JobResult("", False, None, f"启动失败：{job}"))
                continue
            job.refresh()
            res = job.result(lines=None)
            if not job.finished:
                res.ok = False  # 未结束不算成功，避免把半截输出当证据
                res.output += (
                    f"\n[job {job.job_id} 仍在运行 {job.elapsed():.0f}s，"
                    f"下一轮用 status/offset 读尾部]"
                )
            results.append(res)
        return results
