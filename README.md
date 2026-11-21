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

接真实模型：

```bash
export LLM_API_KEY=...          # 密钥只从环境变量读，代码里没有
export LLM_BASE_URL=http://api.deepseek.com.tsecbench.gw/v1
export LLM_MODEL=deepseek-flash
```

```python
from harness.llm_client import make_llm
from harness.loop import Harness

llm = make_llm(verbose=True)
h = Harness(bb, llm=llm, runner=runner, verifier=judge)
h.wave(width=3, max_waves=20)   # 并发；单次调用 9~15s，串行跑不动
print(llm.report())             # 分角色的调用数/token/推理token/credit/延迟
```

实测数据（`glm-5.3-flash`，换模型前的一次冒烟）：15 次调用、0 失败、0.32 credit，
p50 延迟 9–15 秒。**推理 token 占总产出的三分之一**，它既计费又吃延迟，
是最容易被低估的一项，所以客户端单独记账。

demo 覆盖的四条路径——正常推进到解出、循环检测杀路线并写证伪表、空转被判停滞、
预算从停滞题挪到推进中的题——都是断言，失败会直接报错。

## 吞吐相关的一轮改动（2026-11-17）

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

### 预期解 +40 怎么办

正解度由出题人定义，模型判断的准确率无法保证。所以取两条务实做法：

1. **完整记录解题路径**（黑板里已有每一步的动作与证据），供人事后核对是不是预期解。
2. **多方案时倾向"常规、少取巧"的那条**——这是预期解的一个合理代理，但不是保证。

不要指望 planner 能可靠识别预期解，那是猜。能保证的是路径可追溯。

## 四处改动（为什么不能照抄）

**1. 每题独立计时的调度。** 论文一次打一道题、8 小时独立预算、只看解出数。
这里改成：难度先验（分值 / 解出数 / 探测深度）排序 → 可行性判断（剩余时间够不够
走完剩余阶段）→ 先易后难。UCB 被删掉——它适合"总预算固定、题目同质、可反复抽样"，
三条都不成立。另外 `park()` 有代价：同一题放下 3 次就彻底结束，否则调度器会
无限重试打不动的题。

**2. 知识索引加题型维。** 论文是 `(stage, role)` 两维，而比赛有八类题。
现在是 `(category, stage, role)`，同一时刻只把当前格子里的知识给当前角色。
五个基础题型（web/pwn/crypto/re/misc）加三个方向（cloud/redblue/exploit），
各有自己的阶段链与 milestone 判据。

**3. 并行度按时间重分配。** 论文 3 路分支 × 3 executor，很烧 token。
这里题内并行度按剩余时间给：时间紧就单线，宽裕才开分支。
因为每题独立计时，题与题的预算不能互借，"题间并行"的含义变成了同时推进多道题各一条线。

**4. 证据闸门加严。** 阶段推进必须是当前阶段的 milestone 判据，且需要 stdout 摘录
或工件（只给退出码不算）。flag 一律走验证器，没有验证器就拒绝提交。
另外允许模型自造"过程事实"名字（实测它几乎从不使用规定命名），但自造的事实
只算进展、不推进阶段——拦的是"骗推进"，不是"命名不规范"。

## 外部知识库（331MB 公开语料）

`harness/kbindex.py` 把上传的资料集切成块、建 SQLite FTS5 索引，供 `ref_block` 检索。
只用标准库，索引落盘后可随镜像分发，赛场上不重建。

**筛选**。原始 331MB / 3.9 万文件里，70% 体积对解题几乎无用，默认排除：

| 排除 | 体积/块数 | 原因 |
|---|---|---|
| nuclei-templates | 123MB / 2.5 万文件 | 扫描器 YAML，模型读了也不能执行 |
| fuzzingbook | 105MB | 教学教材 |
| MITRE ATLAS | 占 27% 块数 | AI/ML 对抗框架，与 CTF 无关 |
| GenAI 语料 ×3 | — | LLM 应用安全，与赛题不重叠 |

筛选后：3,347 文件 / 33,964 块 / 索引 137MB，检索 0.2ms。

**建索引**（赛前做一次）：

```bash
python3 -c "
from harness.kbindex import KBIndex
idx = KBIndex('knowledge/kb-index.sqlite')
print(idx.build('/path/to/安全知识库'))
idx.db.execute('VACUUM')"
```

索引不存在时 `ref_block` 自动回退到手写条目，不报错。

**检索质量实测**（八类各一条查询）：

| 题型 | 质量 | 说明 |
|---|---|---|
| pwn / crypto / re / cloud / redblue / exploit | 好 | 专有名词多（canary、格基、Kerberos、OGNL），词面匹配天然精准 |
| misc | 中 | zip 伪加密只出 1 条 |
| **web** | **差** | 词汇太泛，"注入""响应""长度"满篇都是，容易命中无关段落 |

web 是 CTF 里最好拿分的题型，恰恰检索最不可靠。**web 必须靠手写 `kb.json` 的 ref 兜底**，
不能指望自动检索。这是这套语料的固有特性，不是配置问题。

## 八类题型与阶段链

| 题型 | 阶段链 |
|---|---|
| web | recon → vuln_localize → exploit → flag |
| pwn | reproduce → primitive → chain → flag |
| crypto | model → attack → solve → flag |
| re | triage → analyze → extract → flag |
| misc | recon → hypothesis → solve → flag |
| cloud | recon → enum → exploit → flag |
| redblue | recon → breach → lateral → flag |
| exploit | analyze → primitives → chain → flag |

`redblue` 目前只实现攻击侧。若赛制要求防守，需要另加一套检测/加固系统，
`stages.py` 里加一条 `redblue_def` 链即可，其余模块不用动。

## 接 OpenHands / π

三个接缝都是单方法协议，不需要改 harness 内部。

**executor 运行时 = OpenHands。** 实现 `Runner.run(action) -> RawResult` 即可：

```python
from harness.executor import RawResult, ExecutorAdapter

class OpenHandsRunner:
    def __init__(self, workspace: str, agent):
        self.workspace = workspace
        self.agent = agent          # 一个 OpenHands agent，跨子目标复用

    def run(self, action: str, timeout: float = 120) -> RawResult:
        res = self.agent.run_task(action, workspace=self.workspace, timeout=timeout)
        return RawResult(ok=res.exit_code == 0, stdout=res.output,
                         stderr=res.error or "", exit_code=res.exit_code,
                         artifact=res.saved_file)   # 有工件就给，证据强度更高

h = Harness(bb, llm=..., runner=OpenHandsRunner("/tmp/task-web01", oh_agent), verifier=judge)
```

两点经验：同一个 task 的 workspace 要跨子目标复用，否则每次原语探测都从零开始；
`artifact` 尽量填，它是唯一能让控制器接受"强证据"的字段。

**规划/决策 = π。** `LLM.complete(role, system, prompt) -> str` 就一个方法。
把 `snapshot()` 当观测喂进去，把模型输出当动作，控制器的 `Decision` 当奖励，
这条链路天然就是 RL 的 rollout 结构。

**训练信号（这是重点）。** 用 π 做 RL 时不要用 LLM judge 当奖励函数，
用 controller 的判定——它已经在代码里，确定、可复算、不可被模型讨好：

| 事件 | 奖励 | 依据 |
|---|---|---|
| flag 通过验证器 | +5 | `Controller._judge_flag` |
| 阶段推进（milestone 满足） | +2 | `Controller._advance` |
| 新事实 / 值变化 | +1 | `add_fact` 的返回值 |
| 空转判定 | 0（并 park） | `Controller.stalled` |
| 循环被杀 | 0，且假设进证伪表 | `Controller.check_loop` |
| 声称成功但无证据 | 0 | `judge` 的拒绝分支 |

三个设计要点：

一是**黑板必须进观测空间**。如果记忆只存在于 harness 内部、模型看不到自己写过什么，
它永远学不会"写黑板"这个行为。现在 `route_planner` 和 `executor` 的 prompt 都吃
`snapshot()`，写记忆的动机来自"下一轮能看到"。

二是**分组基线天然存在**。同一道题的多条路线是同一状态下的不同分支，
正好满足 GRPO 式的组内相对优势估计，不需要额外构造对照。

三是**课程从短链开始**。用 `stages.py` 的阶段数做难度分层：先把单阶段
（recon→flag）打到高分，再加长链路。一开始就上 pwn 全链，奖励会极度稀疏。

**风险提醒。** 训练出的策略会过拟合到你们题库的 milestone 命名和知识语料上。
留一批不参与训练的题，只用来测"解出数"这个最终指标；一旦训练集上的
milestone 满足率远高于留存集，就是过拟合了——那时该改的是知识语料，不是加训练步数。

## 赛前该做的消融

按对比赛成绩的影响排序，先做前两个：

1. **关掉证据闸门**，看多少"成功"是假的。这是队伍里最常见的隐性失败。
2. **关掉跨题调度**（改成顺序做题），看总得分。如果差异不大，说明题目同质，
   可以把算力全押并行。
3. 关掉并行（fanout=1），验证论文那条 75%→45% 的结论在你们题上是否成立。
4. 关掉知识注入，看 token 成本涨幅——如果涨幅远小于论文的 86%，
   说明语料写得不够具体，还在拖后腿。

## 已知的坑

- `attempts` 只能记一次。执行层和主循环各记一次会让循环阈值翻倍（这个 bug 已经踩过了）。
- 路线唯一键必须带阶段，否则进入新阶段后同名假设会撞上已关闭的旧分支。
- `stalled` 不能只看命令退出码。命令成功但没带来新认知，同样是空转，
  而且这是比赛里最隐蔽的失分方式。
- 归一化器是准入层的核心，不是可选优化。`nmap` 百行输出直接进上下文，
  跑十几轮之后决策质量会整体下滑。
- **不要要求 claim 与 milestone 精确相等。** 实测里模型几乎从不使用你规定的名字
  （第一轮冒烟 4/4 全被拒，然后误判停滞）。现在分成三条路：命中 milestone 则推进、
  自造名字则记为"过程事实"照算收益、用了别的阶段的 milestone 名则记录但不推进。
  拦的是"骗推进"，不是"命名不规范"。
- 并发时判定必须串行。worker 只做 LLM + 工具，证据判定和状态变更全部回主线程，
  否则同一 milestone 会被两条路线重复推进。

## 平台接入与剩余事项

`harness/platform.py` 已对接 TSecBench Challenges API：自动读取平台注入的
`BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN`，取题、启动和关闭靶场，并通过平台 API
提交 flag。多 flag 题目按平台返回的完成计数判定，不会在第一个 flag 正确时提前结束。

## 还没做的

按影响排序：**跨题复盘**还没实现——这是我当时说"比赛中途越打越强"的机制，目前缺失。
其次是执行隔离（`ShellRunner` 直接跑本地 shell，比赛时应确认其权限和工作目录）、
`revive()` 没有任何调用点所以停放题永不复活、路线被杀后其子目标留在 todo 未清理。
