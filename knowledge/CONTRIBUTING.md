# 知识库填写说明

## 为什么是这个结构

模型本来就会用 nmap、会写 SQL 注入、会读汇编。它缺的不是"怎么做"，是两件更难的事：

1. **什么时候该放弃这条路。** 这是比赛里最大的失分来源——死磕一个不可能成功的路子，
   等发现时时间已经花掉了。`skip` 清单就是为这个设的。
2. **这个现象说明什么。** 同一个响应特征，老手看一眼就知道是 WAF、是框架默认页、还是真漏了。

所以下面每一条都应该是**判据**，不是教程。

## 三个层级

| 层 | 进哪里 | 付费时机 | 适合放什么 |
|---|---|---|---|
| `must` | prompt 静态前缀 | 每轮都付 | 该题型的核心判断，≤5 条，整格 ≤900 字符 |
| `skip` | 同上，拼在 must 后面 | 每轮都付 | "别做 X，因为 Y" 这类负向经验 |
| `ref` | 动态段，按状态检索 | 命中才付 | 较长的细节、命令食谱、特定场景的处置 |

`must` 有硬预算，超了会被截断——它是每轮都在烧的钱。
`ref` 可以放很多，写多写少不影响基础成本。

## 填写格式

在 `knowledge/kb.json` 里写，不用改代码：

```json
{
  "must": {
    "web/vuln_localize/executor": [
      "判据一……",
      "判据二……"
    ]
  },
  "skip": {
    "web/vuln_localize/executor": [
      "别做 X，因为 Y"
    ]
  },
  "ref": [
    {"tags": ["sql", "盲注"], "stages": ["vuln_localize"], "text": "较长的细节……"}
  ]
}
```

键固定是 `题型/阶段/角色`。题型：`web pwn crypto re misc`。
角色：`route_planner`（提路线）/ `task_planner`（拆子目标）/ `executor`（出动作）。

`ref` 的 `tags` 会和当前状态文本做词面匹配，`stages` 为空表示所有阶段可用。

## 写一条好判据 vs 一条废话

| 废话（模型本来就会） | 判据（模型不会） |
|---|---|
| 用 sqlmap 测试注入 | 报错被统一成 200 且无回显时，优先试时间盲注而不是继续调 union 的列数 |
| 检查有没有 canary | 有 canary 但能在泄露后重新触发，说明 fork 模型；否则每次崩溃都要重新泄漏 |
| 反编译分析算法 | 校验函数里出现 0x9E3779B9 就是 TEA 家族，直接按 TEA 逆向，别硬读 |

右列的共同点：**带具体的触发条件**。看到什么，就做什么，不用再思考。
"检查 X" 这种右边那句话里没有任何条件，模型每次都懂，写了等于没写。

## 当前空缺

跑 `python3 -c "from harness.knowledge import gaps; ..."` 可以看到完整清单。
现在共有 54 个组合只靠通用提示兜底，按题型分布：

- `web`：recon/route_planner、recon/task_planner、vuln_localize/task_planner、exploit 全部、flag 全部
- `pwn`：reproduce/route_planner、reproduce/task_planner、primitive 的 task_planner+executor、chain 与 flag 全部
- `crypto`：model 的两个 planner、attack/solve/flag 全部
- `re`：全部（4 阶段 × 3 角色，一条都没有）
- `misc`：全部

**优先级建议**：先补 `route_planner` 这一列。路线提得对不对，决定了后面所有 executor
的算力花在哪；executor 的细节模型自己会补，路线错了则全盘皆输。`re` 和 `misc` 整块
为空，这两个题型现在几乎等于没有知识注入。
