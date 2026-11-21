"""TSecBench Challenges API adapter and run artifact output."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import stages
from .controller import FlagResult


@dataclass
class TaskSpec:
    id: str
    category: str = "misc"
    target: str = ""
    budget: float = 28_800.0
    points: float = 0.0
    solves: int = 0
    description: str = ""
    flag_count: int = 1
    correct_flag_count: int = 0
    is_completed: bool = False
    container_status: str = "stopped"
    container_addr: list[str] = field(default_factory=list)


class PlatformError(RuntimeError):
    pass


class PlatformAPIError(PlatformError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"TSecBench API HTTP {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


class Platform:
    """TSecBench task lifecycle, answer submission, and result output."""

    MAX_ACTIVE_CHALLENGES = 3
    CHALLENGES_PATH = "/openapi/v1/challenges"

    def __init__(self) -> None:
        self.base_url = os.environ.get("BENCHMARK_BASE_URL", "").strip().rstrip("/")
        self.token = os.environ.get("BENCHMARK_TOKEN", "").strip()
        self.timeout = float(os.environ.get("BENCHMARK_API_TIMEOUT", "30"))
        self.retries = int(os.environ.get("BENCHMARK_API_RETRIES", "2"))
        self.task_budget = float(os.environ.get("BENCHMARK_TASK_BUDGET_SECONDS", "28800"))

        self.output_dir = Path(os.environ.get("OUTPUT_DIR", "/out"))
        self.output_error = ""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.output_error = f"输出目录 {self.output_dir} 不可写：{e}"
            self.output_dir = Path(os.environ.get("TMPDIR", "/tmp")) / "agent-out"
            self.output_dir.mkdir(parents=True, exist_ok=True)

        self._tasks: dict[str, TaskSpec] = {}
        self._active: set[str] = set()
        self._submitted: dict[tuple[str, str], FlagResult] = {}
        self._rejected: set[tuple[str, str]] = set()
        self._lock = threading.RLock()

    def _require_config(self) -> None:
        if not self.base_url:
            raise PlatformError("缺少平台自动注入的 BENCHMARK_BASE_URL")
        if not self.token:
            raise PlatformError("缺少平台自动注入的 BENCHMARK_TOKEN")
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise PlatformError("BENCHMARK_BASE_URL 必须是有效的 HTTP(S) 地址")

    # ---------------- 题目发现与生命周期 ----------------
    def load_tasks(self) -> list[TaskSpec]:
        """GET /challenges and normalize the current benchmark task list."""
        payload = self._request("GET", self.CHALLENGES_PATH)
        if isinstance(payload, dict):
            payload = payload.get("data", payload.get("challenges"))
        if not isinstance(payload, list):
            raise PlatformError("Challenges API 返回的题目清单不是数组")

        specs = [self._task_from_api(row) for row in payload if isinstance(row, dict)]
        if not specs:
            raise PlatformError("Challenges API 返回空题目清单")

        with self._lock:
            for spec in specs:
                self._tasks[spec.id] = spec
                if spec.container_status == "available" and spec.container_addr:
                    self._active.add(spec.id)
        return specs

    def _task_from_api(self, row: dict[str, Any]) -> TaskSpec:
        unique_code = str(row.get("unique_code") or "").strip()
        if not unique_code:
            raise PlatformError("Challenges API 题目缺少 unique_code")

        raw_category = unique_code.split("_", 1)[0].lower()
        category = raw_category if raw_category in stages.TEMPLATES else "misc"
        addresses = self._addresses(row.get("container_addr"))
        status = str(row.get("container_status") or "stopped")
        return TaskSpec(
            id=unique_code,
            category=category,
            target=", ".join(addresses),
            budget=self.task_budget,
            points=float(row.get("total_score") or 0),
            description=str(row.get("description") or ""),
            flag_count=int(row.get("flag_count") or 1),
            correct_flag_count=int(row.get("correct_flag_count") or 0),
            is_completed=bool(row.get("is_completed", False)),
            container_status=status,
            container_addr=addresses,
        )

    def start_task(self, task_id: str) -> list[str]:
        """Start a challenge container and return its direct IP:port addresses."""
        self._require_config()
        with self._lock:
            spec = self._task(task_id)
            if spec.is_completed:
                return []
            if task_id in self._active and spec.container_addr:
                return list(spec.container_addr)
            if len(self._active) >= self.MAX_ACTIVE_CHALLENGES:
                raise PlatformError(
                    f"活动靶场已达平台上限 {self.MAX_ACTIVE_CHALLENGES}，先关闭已停放题目"
                )

            if spec.container_status == "available" and spec.container_addr:
                self._active.add(task_id)
                return list(spec.container_addr)

            query = urllib.parse.urlencode({"unique_code": task_id})
            payload = self._request("POST", f"{self.CHALLENGES_PATH}/start?{query}")
            addresses = self._addresses(payload.get("container_addr") if isinstance(payload, dict) else None)
            if not addresses:
                raise PlatformError(f"启动题目 {task_id} 成功但没有返回 container_addr")
            spec.container_addr = addresses
            spec.target = ", ".join(addresses)
            spec.container_status = "available"
            self._active.add(task_id)
            return list(addresses)

    def close_task(self, task_id: str) -> bool:
        """Close an active challenge container to release one of the three slots."""
        spec = self._tasks.get(task_id)
        if spec is None:
            return False
        if task_id not in self._active and spec.container_status != "available":
            return True

        query = urllib.parse.urlencode({"unique_code": task_id})
        try:
            payload = self._request("POST", f"{self.CHALLENGES_PATH}/close?{query}")
            if isinstance(payload, dict) and payload.get("closed") is False:
                print(f"[PLATFORM] {task_id} close 返回 closed=false", flush=True)
                return False
        except PlatformAPIError as e:
            # The task may have expired while the run was shutting down.
            if e.code != "invalid_state":
                print(f"[PLATFORM] {task_id} 关闭失败：{e}", flush=True)
                return False
        except PlatformError as e:
            print(f"[PLATFORM] {task_id} 关闭失败：{e}", flush=True)
            return False

        with self._lock:
            self._active.discard(task_id)
            spec.container_status = "stopped"
            spec.container_addr = []
            spec.target = ""
        return True

    def close_active_tasks(self) -> None:
        for task_id in list(self._active):
            self.close_task(task_id)

    def active_tasks(self) -> list[str]:
        """当前占用活动名额的题目（LRU 腾位时用）。"""
        with self._lock:
            return list(self._active)

    # ---------------- Flag 提交 ----------------
    def submit_flag(self, task_id: str, flag: str) -> FlagResult:
        """Submit one flag using the documented JSON contract."""
        self._require_config()
        key = (task_id, flag)
        if key in self._submitted:
            return self._submitted[key]
        if key in self._rejected:
            spec = self._tasks.get(task_id)
            return FlagResult(
                accepted=False,
                completed=False,
                correct_flag_count=spec.correct_flag_count if spec else 0,
                total_flag_count=spec.flag_count if spec else 0,
                message="此前已被平台拒绝",
            )

        try:
            payload = self._request(
                "POST",
                f"{self.CHALLENGES_PATH}/submit",
                {"unique_code": task_id, "flag": flag},
            )
        except PlatformAPIError as e:
            if e.code == "duplicate":
                try:
                    self._refresh_task(task_id)
                except PlatformError:
                    pass
                spec = self._tasks.get(task_id)
                result = FlagResult(
                    accepted=True,
                    completed=bool(spec and spec.is_completed),
                    correct_flag_count=spec.correct_flag_count if spec else 0,
                    total_flag_count=spec.flag_count if spec else 0,
                    message="该 flag 已由平台确认过",
                )
                self._submitted[key] = result
                return result
            return self._submission_error(task_id, e)
        except PlatformError as e:
            return self._submission_error(task_id, e)

        if not isinstance(payload, dict) or not isinstance(payload.get("correct"), bool):
            return self._submission_error(task_id, "响应缺少布尔字段 correct")

        spec = self._task(task_id)
        correct_count = int(payload.get("correct_flag_count", spec.correct_flag_count))
        total_count = int(payload.get("total_flag_count", spec.flag_count))
        completed = bool(payload.get("is_completed", total_count > 0 and correct_count >= total_count))
        spec.correct_flag_count = correct_count
        spec.flag_count = total_count
        spec.is_completed = completed

        result = FlagResult(
            accepted=payload["correct"],
            completed=completed,
            correct_flag_count=correct_count,
            total_flag_count=total_count,
            message="flag 正确" if payload["correct"] else "flag 错误",
        )
        if result.accepted:
            self._submitted[key] = result
            print(
                f"[FLAG] {task_id} 正确 {correct_count}/{total_count}，"
                f"本次得分={payload.get('awarded', 0)}", flush=True
            )
        else:
            self._rejected.add(key)
            print(f"[FLAG] {task_id} 错误", flush=True)
        return result

    def _submission_error(self, task_id: str, error: PlatformError | str) -> FlagResult:
        spec = self._tasks.get(task_id)
        message = str(error)
        print(f"[FLAG] {task_id} 提交异常：{message}", flush=True)
        return FlagResult(
            accepted=False,
            completed=False,
            correct_flag_count=spec.correct_flag_count if spec else 0,
            total_flag_count=spec.flag_count if spec else 0,
            message=f"平台提交未确认：{message}",
        )

    # ---------------- API helpers ----------------
    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        self._require_config()
        url = self.base_url + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"BENCHMARK_TOKEN": self.token, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"

        last_error: PlatformError | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    raw = response.read()
                if not raw:
                    return {}
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    raise PlatformError(f"{method} {path} 返回非 JSON 响应") from e
            except urllib.error.HTTPError as e:
                raw = e.read(4096).decode("utf-8", "replace")
                details: Any = {}
                try:
                    details = json.loads(raw)
                except json.JSONDecodeError:
                    details = {"message": raw[:300]}
                code = str(details.get("code", "")) if isinstance(details, dict) else ""
                message = str(details.get("message", raw[:300])) if isinstance(details, dict) else raw[:300]
                if (e.code != 429 and not 500 <= e.code < 600) or attempt >= self.retries:
                    raise PlatformAPIError(e.code, code, message) from e
                last_error = PlatformAPIError(e.code, code, message)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_error = PlatformError(f"{method} {path} 网络错误：{type(e).__name__}: {e}")
                if attempt >= self.retries:
                    break
            if attempt < self.retries:
                time.sleep(min(1.5 * (attempt + 1), 5.0))

        raise last_error or PlatformError(f"{method} {path} 请求失败")

    def _refresh_task(self, task_id: str) -> TaskSpec:
        payload = self._request("GET", self.CHALLENGES_PATH)
        if isinstance(payload, dict):
            payload = payload.get("data", payload.get("challenges"))
        if not isinstance(payload, list):
            raise PlatformError("刷新题目状态时返回的清单格式错误")
        for row in payload:
            if isinstance(row, dict) and row.get("unique_code") == task_id:
                spec = self._task_from_api(row)
                self._tasks[task_id] = spec
                if spec.container_status == "available" and spec.container_addr:
                    self._active.add(task_id)
                return spec
        raise PlatformError(f"题目 {task_id} 不在当前 benchmark 清单中")

    def _task(self, task_id: str) -> TaskSpec:
        try:
            return self._tasks[task_id]
        except KeyError as e:
            raise PlatformError(f"未知题目 unique_code：{task_id}") from e

    @staticmethod
    def _addresses(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(address).strip() for address in value if str(address).strip()]

    # ---------------- 结果输出 ----------------
    def write_summary(self, data: dict[str, Any]) -> Path:
        path = self.output_dir / "summary.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def write_trajectory(self, task_id: str, rows: list[dict[str, Any]]) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in task_id)
        path = self.output_dir / f"trajectory-{safe}.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return path
