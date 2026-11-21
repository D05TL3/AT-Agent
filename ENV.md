# Runtime configuration

## Model gateway

Set these as runtime environment variables in the TSecBench Agent configuration. Do not bake credentials into the image.

| Variable | Value | Notes |
|---|---|---|
| `LLM_API_KEY` | Your DeepSeek API key | Required by the model client |
| `LLM_BASE_URL` | `http://api.deepseek.com.tsecbench.gw/v1` | TSecBench gateway form of `https://api.deepseek.com/v1` |
| `LLM_MODEL` | `deepseek-flash` | Default; supported by this benchmark |

The hosted sandbox cannot access the public internet. Use the TSecBench gateway URL, not the public DeepSeek URL.

## Benchmark API

TSecBench automatically injects `BENCHMARK_BASE_URL` and `BENCHMARK_TOKEN` when it creates the run. The agent reads both directly; do not add or replace them in the custom environment-variable fields.

The adapter uses the documented Challenges API:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/openapi/v1/challenges` | Load task list and current progress |
| `POST` | `/openapi/v1/challenges/start?unique_code=...` | Start a task container |
| `POST` | `/openapi/v1/challenges/submit` | Submit `{"unique_code":"...","flag":"..."}` |
| `POST` | `/openapi/v1/challenges/close?unique_code=...` | Release the task container |

Every request sends the injected token in the `BENCHMARK_TOKEN` HTTP header, without a `Bearer` prefix. A task may require multiple flags; it is marked solved only when `correct_flag_count` reaches `total_flag_count`. The platform permits at most three active challenge containers, so `AGENT_WIDTH` is capped at three.

Challenge addresses returned by `start` require access to the benchmark target network. For local evaluation, connect to the benchmark VPN before starting the agent. Hosted evaluation must provide the corresponding target-network access.

## Optional tuning

| Variable | Default | Purpose |
|---|---:|---|
| `LLM_MAX_TOKENS` | `4096` | Per-response token limit |
| `LLM_TEMPERATURE` | `0.6` | Sampling temperature |
| `AGENT_WIDTH` | `3` | Concurrent challenge tasks; capped at 3 |
| `AGENT_MAX_WAVES` | `400` | Maximum scheduling rounds |
| `AGENT_MAX_ACTIONS` | `4` | Shell commands the executor may issue per subgoal (run concurrently) |
| `AGENT_MAX_JOBS` | `8` | Background shell jobs per task |
| `AGENT_JOB_TIMEOUT` | `1800` | Hard cap per background job (seconds); output file survives |
| `AGENT_FLAG_STALL_SEC` | `900` | No new flag for this long triggers intervention |
| `AGENT_NUDGE_MAX` | `2` | Stall nudges before a route is parked |
| `BENCHMARK_TASK_BUDGET_SECONDS` | `28800` | Local scheduler budget, matching the benchmark's 8-hour total limit |
| `BENCHMARK_API_TIMEOUT` | `30` | API request timeout in seconds |
| `BENCHMARK_API_RETRIES` | `2` | Retries for transient API failures |
| `TOOL_TIMEOUT` | `120` | Per-command timeout in seconds |
| `AGENT_VERBOSE` | `0` | Set to `1` for per-call model timing |
| `MIN_STAGE_SECONDS` | `90` | Scheduler feasibility estimate |
| `OUTPUT_DIR` | `/out` | Summary and trajectories |
| `BLACKBOARD_PATH` | `/out/blackboard.sqlite` | Persistent harness state |
| `KB_INDEX` | `knowledge/kb-index.sqlite` | Knowledge index path |

## Preflight

Run the offline harness smoke test first:

```bash
python3 demo.py
```

Then run the container self-check with the model environment variables and the platform-injected benchmark variables available:

```bash
docker run --rm --env-file .env ctf-agent:latest python3 agent_main.py --check
```

The self-check sends one small model-gateway health request and reads the task list. It does not start challenge containers or submit flags. Complete TSecBench local evaluation before creating a hosted run.
