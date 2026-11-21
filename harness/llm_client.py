"""OpenAI 兼容的 LLM 客户端，实现 planner.LLM 协议。

平台只允许白名单内的模型，所以这里不做角色路由：所有调用同一个模型，
`role` 只用于分类记账。针对「推理模型 + 9~15s 单次延迟」这两个约束设计：

1. **重试与退避**：429 / 5xx / 超时都要退避重试。比赛中一次裸失败会浪费一个 tick。
2. **线程安全记账**：并发跑多条路线时统计必须加锁，否则成本数字会互相覆盖。
   推理模型的 reasoning_tokens 单独记——它既计费又吃延迟，是最容易被低估的一项。
3. **密钥只从环境变量读**，绝不写进代码或提交进仓库。

用法：
    export LLM_API_KEY=sk-...
    llm = LLMClient(base_url="https://esa.ezaigc.cn/v1")
"""
from __future__ import annotations

import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# DeepSeek provider URL converted to the TSecBench gateway form.
DEFAULT_BASE = "http://api.deepseek.com.tsecbench.gw/v1"

# 平台只允许白名单内的模型，这里默认使用 deepseek-flash。
# 可用 LLM_MODEL 覆盖，不要写死在别处。
MODEL = "deepseek-flash"

# DeepSeek public URL, only for local tests outside the hosted sandbox.
PUBLIC_BASE = "https://api.deepseek.com/v1"


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    credit: float = 0.0
    failures: int = 0
    latency: list[float] = field(default_factory=list)
    # 前缀缓存命中。DeepSeek 在 usage 里给 prompt_cache_hit_tokens / _miss_tokens；
    # 网关若不透传这两个字段，这里会一直是 0——那本身就是"fork 多分支没有收益"的信号。
    cache_hit: int = 0
    cache_miss: int = 0
    cache_reported: int = 0  # 有多少次调用真的带了缓存字段

    def add(
        self,
        prompt: int,
        completion: int,
        reasoning: int,
        credit: float,
        dt: float,
        cache_hit: int = 0,
        cache_miss: int = 0,
        cache_reported: bool = False,
    ) -> None:
        self.calls += 1
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.reasoning_tokens += reasoning
        self.credit += credit
        self.latency.append(dt)
        self.cache_hit += cache_hit
        self.cache_miss += cache_miss
        if cache_reported:
            self.cache_reported += 1

    @property
    def p50(self) -> float:
        if not self.latency:
            return 0.0
        s = sorted(self.latency)
        return s[len(s) // 2]

    @property
    def cache_rate(self) -> float | None:
        """前缀缓存命中率。None 表示网关没透传缓存字段（未知，不等于 0）。"""
        total = self.cache_hit + self.cache_miss
        if not total:
            return None
        return self.cache_hit / total

    def line(self, name: str = "total") -> str:
        rate = self.cache_rate
        cache = "cache=未透传" if rate is None else f"cache={rate:.1%}"
        return (
            f"{name}: calls={self.calls} fail={self.failures} "
            f"tok={self.prompt_tokens}+{self.completion_tokens}"
            f"(reasoning {self.reasoning_tokens}) "
            f"credit={self.credit:.4f} {cache} p50={self.p50:.1f}s"
        )


class LLMClient:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE,
        api_key: str | None = None,
        model: str = MODEL,
        timeout: float = 180.0,
        max_retries: int = 3,
        temperature: float = 0.6,
        max_tokens: int = 4096,
        json_mode: bool = True,
        verbose: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        if not self.api_key:
            raise LLMError(
                "缺少 API key：请设置环境变量 LLM_API_KEY，不要把密钥写进代码。"
            )
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.json_mode = json_mode
        self.verbose = verbose
        self._lock = threading.Lock()
        self.stats = Usage()
        self.by_role: dict[str, Usage] = {}

    # ---------- 统计 ----------
    def _record(
        self,
        role: str,
        prompt: int,
        completion: int,
        reasoning: int,
        credit: float,
        dt: float,
        cache_hit: int = 0,
        cache_miss: int = 0,
        cache_reported: bool = False,
    ) -> None:
        with self._lock:
            self.stats.add(
                prompt, completion, reasoning, credit, dt, cache_hit, cache_miss, cache_reported
            )
            self.by_role.setdefault(role, Usage()).add(
                prompt, completion, reasoning, credit, dt, cache_hit, cache_miss, cache_reported
            )

    def _fail(self, role: str) -> None:
        with self._lock:
            self.stats.failures += 1
            self.by_role.setdefault(role, Usage()).failures += 1

    def report(self) -> str:
        with self._lock:
            lines = [self.stats.line("total")]
            for role, u in sorted(self.by_role.items()):
                lines.append("  " + u.line(role))
        return "\n".join(lines)

    # ---------- 主调用 ----------
    def complete(self, *, role: str, system: str, prompt: str) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}

        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            t0 = time.time()
            try:
                raw = self._post(body)
                choice = raw["choices"][0]["message"]
                # 推理模型的正文在 content；个别实现会放在 reasoning_content 里作为补充，
                # 正文为空时才回退（绝不能把思维链当答案用）。
                text = (choice.get("content") or "").strip()
                if not text and choice.get("reasoning_content"):
                    text = str(choice["reasoning_content"]).strip()
                u = raw.get("usage") or {}
                det = u.get("completion_tokens_details") or {}
                # DeepSeek 用 prompt_cache_hit_tokens/_miss；OpenAI 兼容网关可能用
                # prompt_tokens_details.cached_tokens。两种都认，缺失就不算"未命中"。
                pdet = u.get("prompt_tokens_details") or {}
                hit = u.get("prompt_cache_hit_tokens")
                miss = u.get("prompt_cache_miss_tokens")
                reported = hit is not None or miss is not None or pdet.get("cached_tokens") is not None
                cache_hit = int(hit if hit is not None else (pdet.get("cached_tokens") or 0) or 0)
                cache_miss = int(miss if miss is not None else 0)
                self._record(
                    role,
                    int(u.get("prompt_tokens", 0)),
                    int(u.get("completion_tokens", 0)),
                    int(det.get("reasoning_tokens", 0)),
                    float(u.get("credit", 0.0) or 0.0),
                    time.time() - t0,
                    cache_hit,
                    cache_miss,
                    bool(reported),
                )
                if self.verbose:
                    cache_note = f" cache={cache_hit}/{cache_hit + cache_miss}" if reported else ""
                    print(f"    [{role}] {time.time() - t0:.1f}s {len(text)}ch{cache_note}")
                return text
            except urllib.error.HTTPError as e:
                detail = e.read()[:300].decode("utf-8", "replace")
                last_err = LLMError(f"HTTP {e.code}: {detail}")
                # 4xx（除 429）重试无意义：请求本身有问题
                if e.code != 429 and 400 <= e.code < 500:
                    self._fail(role)
                    raise last_err from e
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as e:
                last_err = LLMError(f"{type(e).__name__}: {e}")

            if attempt < self.max_retries:
                backoff = min(2 ** attempt + random.uniform(0, 0.6), 12.0)
                if self.verbose:
                    print(f"    [{role}] 重试 {attempt + 1}: {last_err} -> {backoff:.1f}s")
                time.sleep(backoff)

        self._fail(role)
        raise LLMError(f"{role} 调用失败（{self.max_retries + 1} 次）: {last_err}")

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())


def make_llm(**kw: Any) -> LLMClient:
    """便捷构造。base_url 与 model 都可被环境变量覆盖。"""
    kw.setdefault("base_url", os.environ.get("LLM_BASE_URL", DEFAULT_BASE))
    kw.setdefault("model", os.environ.get("LLM_MODEL", MODEL))
    return LLMClient(**kw)
