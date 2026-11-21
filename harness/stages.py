"""题型化的阶段模板（改动 2）。

论文的三阶段（复现 -> 原语 -> 构造链）只在 pwn/web 上自然。这里每个题型给一条
自己的阶段链，每阶段带一个 milestone 判据：只有该判据被运行时证据满足才能进阶段。
`requires` 对应黑板里的 fact key 或 `flag` 特殊标记。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    name: str
    goal: str
    requires: str  # 黑板 fact key；"flag" 表示需要验证过的 flag


TEMPLATES: dict[str, list[Stage]] = {
    "web": [
        Stage("recon", "摸清入口：端点、参数、技术栈、认证方式", "web_surface"),
        Stage("vuln_localize", "定位可疑点：注入、越权、文件读取、反序列化", "web_vuln"),
        Stage("exploit", "构造利用并取得目标效果（读文件/命令执行/拿后台）", "web_foothold"),
        Stage("flag", "从立足点取出 flag 并机器验证", "flag"),
    ],
    "pwn": [
        Stage("reproduce", "复现漏洞：触发条件、崩溃点、受影响组件", "pwn_crash"),
        Stage("primitive", "取得原语：任意读 / 任意写 / 控制流", "pwn_primitive"),
        Stage("chain", "串联原语构造完整利用", "pwn_chain"),
        Stage("flag", "读取 flag 并机器验证", "flag"),
    ],
    "crypto": [
        Stage("model", "形式化：把题面还原成数学结构，确认已知量与目标", "crypto_model"),
        Stage("attack", "选定攻击族并实现（格/相关攻击/oracle 交互）", "crypto_attack"),
        Stage("solve", "解出明文或私钥", "crypto_plaintext"),
        Stage("flag", "提交并机器验证", "flag"),
    ],
    "re": [
        Stage("triage", "静态摸底：格式、架构、关键字符串与导入表", "re_triage"),
        Stage("analyze", "动态/静态分析核心校验逻辑", "re_logic"),
        Stage("extract", "提取密钥、还原算法、构造输入", "re_key"),
        Stage("flag", "提交并机器验证", "flag"),
    ],
    "misc": [
        Stage("recon", "识别题目类型与线索面", "misc_surface"),
        Stage("hypothesis", "形成并验证一个明确假设", "misc_hypothesis"),
        Stage("solve", "取到目标输出", "misc_solved"),
        Stage("flag", "提交并机器验证", "flag"),
    ],
    # ---- 云安全：常规 CTF 流程，但攻击面在云 API / 容器 / 配置面 ----
    "cloud": [
        Stage("recon", "摸清入口：给了什么凭据/端点/角色，能调哪些云 API", "cloud_surface"),
        Stage("enum", "枚举权限边界：这个身份能读写什么，有没有提权路径", "cloud_perms"),
        Stage("exploit", "利用配置错误或权限缺陷取得目标资源", "cloud_foothold"),
        Stage("flag", "从目标资源取出 flag 并机器验证", "flag"),
    ],
    # ---- 红蓝对抗：按纯攻击方向实现（防守侧另需一套系统）----
    "redblue": [
        Stage("recon", "摸清靶标：资产面、开放服务、防护强度", "rb_surface"),
        Stage("breach", "突破边界：拿到第一个立足点", "rb_foothold"),
        Stage("lateral", "横向/提权：向目标资产推进", "rb_pivot"),
        Stage("flag", "取得目标凭据或 flag 并机器验证", "flag"),
    ],
    # ---- 漏洞利用：给定漏洞信息去打特定服务 ----
    "exploit": [
        Stage("analyze", "理解漏洞：受影响组件、触发条件、影响版本", "exp_analysis"),
        Stage("primitives", "确认可用的利用原语", "exp_primitive"),
        Stage("chain", "构造并验证完整利用", "exp_chain"),
        Stage("flag", "取得 flag 并机器验证", "flag"),
    ],
}

DEFAULT = TEMPLATES["misc"]


def stages_for(category: str) -> list[Stage]:
    return TEMPLATES.get(category, DEFAULT)


def stage(category: str, idx: int) -> Stage:
    chain = stages_for(category)
    return chain[min(idx, len(chain) - 1)]


def is_last(category: str, idx: int) -> bool:
    return idx >= len(stages_for(category)) - 1


def milestone_keys() -> set[str]:
    """所有题型的 milestone 键。

    用途：区分"自造的中间事实"和"阶段推进判据"。前者允许模型自由命名，
    后者必须与模板精确匹配——这是防止模型自己发明里程碑来骗推进的关键。
    """
    keys: set[str] = set()
    for chain in TEMPLATES.values():
        for st in chain:
            keys.add(st.requires)
    return keys
