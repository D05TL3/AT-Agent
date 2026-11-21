# CTF 攻击 Agent 骨架

自主攻击 agent 的可运行骨架。设计参考 DoGNAVY-Exploit（arXiv:2611.04196）的
「阶段分解 + 分层规划 + 并行探索 + 结构化记忆」，并按比赛场景做了四处改动。

```
harness/
  blackboard.py   黑板：结构化共享记忆（SQLite），动作哈希、事实 upsert、证伪表、
                  状态胶囊、停滞提醒队列、子目标重拆计数
  stages.py       题型化阶段模板 + 每阶段的 milestone 判据
  knowledge.py    三维专家知识索引 (category, stage, role)
  planner.py      route planner（链级）与 task planner（动作级）
  executor.py     执行层 + 批量动作 + 输出归一化（准入层）；附 InteractiveRunner
  shell_bg.py     后台 job 式 shell：并发、落盘、分页续读、整组 kill
  controller.py   证据闸门、阶段推进、循环检测、五信号卡塞判定
  scheduler.py    难度先验 + 可行域判断 + 时间隔离的调度
  loop.py         主循环（tick 串行 / wave 并发）
  llm_client.py   OpenAI 兼容客户端：重试退避、线程安全记账、前缀缓存命中统计
demo.py           离线可跑：不连模型、不碰网络，验证九项关键行为
```

跑：`python3 demo.py`

环境变量:

```bash
export LLM_API_KEY=...          
export LLM_BASE_URL=http://api.deepseek.com.tsecbench.gw/v1
export LLM_MODEL=deepseek-flash
```

## 基于TCH比赛进行的更新

参考 `VANexus/tsecbench-agent` 的实测结论做的四组改动。改动的共同点是：**不是让模型更聪明，
而是别把动作预算浪费在等待和误杀上**。

**1. 异步 shell。** 旧版 `subprocess.run` 阻塞执行 + 输出截断 600 字符，长扫描必须等完、
`| head` 又会被管道缓冲憋住。现在所有命令后台起 job（`detached` 进程组），
输出落盘按 byte offset 分页读，`status/list/wait/kill` 齐备，超时被杀但输出文件仍在。
一个子目标可以给最多 4 条互不依赖的命令并发发出——3 条各 0.5s 的命令墙钟 0.53s，
而旧版是串行的 1.5s 加上 3 次 LLM 调用。

**2. 子目标可重拆。** 旧版一次性拆 5 条用到底，耗尽就判"路线枯竭"，一道题整个生命周期
只有十几到几十个动作，pwn/crypto 这种需要反复试错的题走不完。现在子目标耗尽时按**最新事实**
重拆一批（`REPLENISH_MAX=3` 封顶），只有连新子目标都拆不出来才算真枯竭。

**3. park 不再关靶场。** 旧版 `_close_terminal_tasks` 把 `parked` 也算终态，一停滞就
`POST /close`，下次捞回来得重起容器，webshell、监听、解压好的附件全归零。现在只释放
`solved`/`expired`，腾名额交给 LRU（`agent_main.run()` 的 slot guard 关掉最久未用的那道）。

**4. 卡塞先提醒后退役。** 旧版连续 4 次没进展直接 park。现在五信号判定
（flag 主时钟一票 / 停滞 / 命令重复 / 硬失败 / 连续错提交），命中后先写一条提醒
注入下一轮 prompt（零 LLM 成本、尾部追加保缓存），提醒额度用尽才退役。
参考实现在线上踩过的坑很值得记：一道题连跑 28 轮、同一个凭据用了 146 处，
却 **0 次写黑板**——不是工具坏了，是模型没想到要记录。所以提醒文本里直接给了
"证据类/判断类"的写卡判据，`EXEC_SYS` 里也写死了"每 ≤5 轮至少一张卡"。

**验证 fork 多分支前先跑 `--probe-cache`。** 参考实现实测分支首请求能命中父分支前缀
99.2%（miss 仅 180 token），所以多开一条攻击线在缓存上几乎免费。但那是**本地官方 API**
的数据，托管网关是否透传 `prompt_cache_hit_tokens` 未经验证。`llm_client` 现在会
统计命中率（`report()` 里显示 `cache=xx%` 或 `cache=未透传`），
`python3 agent_main.py --probe-cache` 发两次同前缀请求直接给结论。
**命中率拿不到就别上 fork**——那条收益无从验证。

## 与论文的对应

| 论文 | 这里 |
|---|---|
| stage-aware decomposition | `stages.py`，但按题型给不同阶段链 |
| route planner / task planner | `planner.py`，只吃 `blackboard.snapshot()` |
| controller（只认运行时证据） | `controller.py::judge`，纯代码判定 |
| parallel executors | `loop.py` 每个 tick 覆盖一条路线，`scheduler.fanout_for` 控制并行度 |
| structured memory | `blackboard.py`，关系库而不是对话上下文 |
| state capsule | `controller.py::capsule` + `capsules` 表 |
| progressive knowledge disclosure | `knowledge.py`，三维索引 |

## 赛制约束（决定架构的事实）

| 事实 | 对架构的影响 |
|---|---|
| 只按 flag 计分 | 过程信号不进奖励函数。`note_result` 的 reward 只用于日志。 |
| 预期解额外 +40 | 优化目标从"最快拿 flag"变成"按预期路径拿 flag"。见下节。 |
| 每题独立计时 | 一题超时就是彻底结束，没有复活。`scheduler` 删掉 UCB，改成难度先验 + 可行性判断。 |
| 先易后难 | 需要显式难度先验（分值/解出数/探测深度）与"放下有代价"的终止条件。 |
| executor 不出网 | 工具必须预装，无 pip install、无在线查 CVE。预置知识是唯一参考资料，知识库价值被放大。 |
| orchestrator 可出网 | 模型调用走代理正常发；只有靶场侧受限。 |



## 外部知识库

`harness/kbindex.py` 把上传的资料集切成块、建 SQLite FTS5 索引，供 `ref_block` 检索。
只用标准库，索引落盘后可随镜像分发，赛场上不重建。

**建立知识库索引**：

```bash
python3 -c "
from harness.kbindex import KBIndex
idx = KBIndex('knowledge/kb-index.sqlite')
print(idx.build('/path/to/安全知识库'))
idx.db.execute('VACUUM')"
```

索引不存在时 `ref_block` 自动回退到手写条目.