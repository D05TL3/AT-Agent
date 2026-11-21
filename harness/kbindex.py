"""外部知识库的分块检索索引。

语料是 331MB / 3.9 万文件的公开安全资料合集。直接全量塞进 prompt 不可能，
所以这里做三件事：

1. **筛选**：不是所有资料都值得进索引。nuclei 模板（2.5 万文件 / 123MB）是
   给扫描器执行的 YAML，模型读了也没法用；fuzzingbook（105MB）是教学材料。
   这两块占了 70% 体积却贡献极低的检索价值，默认排除。
2. **切块**：按标题层级和段落切，块大小控制在几百字。太大会稀释关键词，
   太小会丢上下文。
3. **索引**：SQLite FTS5 + trigram 分词。选它而不是自己写 BM25，是因为
   trigram 对中文天然有效（不需要分词器），而且索引落盘后可以随镜像分发，
   赛场上不需要重建。

只用标准库，不引入依赖——不出网环境里装包不可靠。
"""
from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# 默认排除的目录：体积巨大但对"如何解题"贡献低
EXCLUDE_DIRS: tuple[str, ...] = (
    # 体积巨大、对"如何解题"贡献低
    "02-nuclei-templates",   # 扫描器 YAML，模型无法执行，123MB
    "05-fuzzingbook",        # 教学教材，105MB
    "13-atlas-data",         # AI/ML 对抗威胁框架，对 CTF 无关，占 27% 块数
    "15-genai-corpus",       # LLM 应用安全语料，与赛题不重叠
    "14-genai-llm-top10",    # 同上
    "12-k8s-sec",            # 体量小，命中率低
    "06-owasp-cheatsheets",  # 与 payloadsallthethings 高度重复
    # 仓库元数据
    ".github", ".claude", "tests", "templates", "scripts",
)

TEXT_EXT = {".md", ".markdown", ".txt", ".rst", ".yaml", ".yml"}
MIN_CHUNK = 120      # 少于这个字符的块丢弃（多为标题或空壳）
MAX_CHUNK = 1200

_HEADING = re.compile(r"^(#{1,4})\s+(.*)$")
_JUNK_NAMES = ("._", ".DS_Store")

# 题型提示词：用于把检索结果映射到当前题型，而不是纯词面匹配
CATEGORY_HINTS = {
    "web": ("http", "url", "参数", "注入", "xss", "ssrf", "文件上传", "cookie", "web"),
    "pwn": ("栈", "堆", "溢出", "rop", "shellcode", "libc", "gadget", "pwn", "格式化字符串"),
    "crypto": ("加密", "密文", "rsa", "aes", "格", "lattice", "离散对数", "crypto", "签名"),
    "re": ("反编译", "汇编", "逆向", "ida", "ghidra", "脱壳", "混淆", "reverse"),
    "misc": ("隐写", "流量", "取证", "编码", "压缩包", "pcap", "stego", "forensic"),
    "cloud": ("iam", "s3", "ak", "sk", "容器", "k8s", "kubernetes", "云", "bucket"),
    "redblue": ("域", "kerberos", "横向", "提权", "c2", "ad域", "内网"),
    "exploit": ("cve", "poc", "exp", "漏洞利用", "rce", "反序列化"),
}


@dataclass
class Hit:
    path: str
    heading: str
    text: str
    rank: float

    def render(self, max_chars: int = 280) -> str:
        body = re.sub(r"\s+", " ", self.text).strip()
        if len(body) > max_chars:
            body = body[:max_chars] + "…"
        src = Path(self.path).name
        return f"[{self.heading or src}] {body}"


def _skip(p: Path) -> bool:
    if any(x in p.parts for x in EXCLUDE_DIRS):
        return True
    if p.name.startswith(_JUNK_NAMES) or p.suffix == ".pyc":
        return True
    return p.suffix.lower() not in TEXT_EXT


def _chunks(text: str, path: str) -> Iterator[tuple[str, str]]:
    """按标题切块；没有标题时按空行分段。产出 (heading, chunk)。"""
    heading = ""
    buf: list[str] = []

    def flush() -> Iterator[tuple[str, str]]:
        body = "\n".join(buf).strip()
        buf.clear()
        if len(body) >= MIN_CHUNK:
            yield heading, body[:MAX_CHUNK]

    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            yield from flush()
            heading = m.group(2).strip()
            continue
        if not line.strip():
            if sum(len(x) for x in buf) > MAX_CHUNK * 0.6:
                yield from flush()
            else:
                buf.append(line)
        else:
            buf.append(line)
    yield from flush()


def iter_corpus(root: str | Path) -> Iterator[tuple[Path, str]]:
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if _skip(p):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if text.strip():
                yield p, text


class KBIndex:
    """FTS5 全文索引。持久化到磁盘，赛场上直接打开，不重建。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.db = sqlite3.connect(str(path))
        self.db.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5("
            "path, heading, body, tokenize='trigram')"
        )
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
        self.db.commit()

    # ---------- 建库 ----------
    def build(self, root: str | Path, progress_every: int = 2000) -> dict[str, int]:
        stats = {"files": 0, "chunks": 0}
        batch: list[tuple[str, str, str]] = []
        for p, text in iter_corpus(root):
            stats["files"] += 1
            for heading, body in _chunks(text, str(p)):
                batch.append((str(p), heading, body))
            if len(batch) >= 500:
                self._insert(batch)
                stats["chunks"] += len(batch)
                batch.clear()
            if progress_every and stats["files"] % progress_every == 0:
                print(f"  已处理 {stats['files']} 文件 / {stats['chunks'] + len(batch)} 块")
        if batch:
            self._insert(batch)
            stats["chunks"] += len(batch)
        self.db.commit()
        self._set_meta("chunks", str(stats["chunks"]))
        return stats

    def _insert(self, rows: list[tuple[str, str, str]]) -> None:
        self.db.executemany("INSERT INTO chunks (path, heading, body) VALUES (?,?,?)", rows)

    def _set_meta(self, k: str, v: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)", (k, v))
        self.db.commit()

    def _get_meta(self, k: str) -> str | None:
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None

    @property
    def size(self) -> int:
        r = self.db.execute("SELECT COUNT(*) FROM chunks").fetchone()
        return int(r[0])

    # ---------- 检索 ----------
    def search(
        self, query: str, limit: int = 3, category: str | None = None, min_score: float = 0.0
    ) -> list[Hit]:
        """FTS5 检索 + 题型加权 + 同源去重。

        trigram 分词下查询串必须够长才有效，短词直接跳过。
        同一文件的多块只保留最高分那块——否则一个长小节会把名额外占满。
        """
        terms = [t for t in re.split(r"[\s,，。;；:：()（）\[\]]+", query) if len(t) >= 2]
        if not terms:
            return []
        # 先试 AND（高精度），命中为空再退回 OR（高召回）。
        # 纯 OR 会让"响应长度""判断"这类通用词凑出无关段落——
        # 实测 web/盲注查询因此命中了 NTLM 质询内容。
        quoted = ['"' + t.replace('"', "") + '"' for t in terms[:12]]
        rows = []
        for joiner in (" AND ", " OR "):
            try:
                rows = self.db.execute(
                    "SELECT path, heading, body, bm25(chunks) AS r FROM chunks "
                    "WHERE chunks MATCH ? ORDER BY r LIMIT ?",
                    (joiner.join(quoted), limit * 8),
                ).fetchall()
            except sqlite3.OperationalError:
                rows = []
            if rows:
                break
        if not rows:
            return []

        hints = CATEGORY_HINTS.get(category or "", ())
        by_path: dict[str, Hit] = {}
        for path, heading, body, r in rows:
            score = -float(r)
            blob = (heading + body).lower()
            if hints:
                score += 0.25 * sum(1 for h in hints if h in blob)
            if score < min_score:
                continue
            prev = by_path.get(path)
            if prev is None or score > prev.rank:
                by_path[path] = Hit(path, heading, body, score)

        # 近重复去重。CTF Wiki 有简繁双版本，同一段落会被检索两次而占满名额。
        # 繁简字形不同，字符集重合度算不出来，但**文件名完全相同**——用它做键最可靠。
        ranked = sorted(by_path.values(), key=lambda h: -h.rank)
        out: list[Hit] = []
        seen_names: set[str] = set()
        for h in ranked:
            name = Path(h.path).name
            if name in seen_names:
                continue
            if any(_similar(h.text, o.text) for o in out):
                continue
            seen_names.add(name)
            out.append(h)
            if len(out) >= limit:
                break
        return out


def _similar(a: str, b: str, threshold: float = 0.82) -> bool:
    """同一语言内的近重复判断（标点/换行差异）。"""
    sa = set(re.findall(r"[一-鿿A-Za-z0-9]{2,}", a))
    sb = set(re.findall(r"[一-鿿A-Za-z0-9]{2,}", b))
    if not sa or not sb:
        return False
    inter = len(sa & sb)
    return inter / min(len(sa), len(sb)) >= threshold


def default_path() -> Path:
    return Path(os.environ.get("KB_INDEX", "knowledge/kb-index.sqlite"))


def open_index(path: str | Path | None = None) -> KBIndex | None:
    """打开已有索引；不存在则返回 None（调用方回退到 kb.json 的静态 ref）。"""
    p = Path(path) if path else default_path()
    if not p.exists():
        return None
    idx = KBIndex(p)
    return idx if idx.size > 0 else None
