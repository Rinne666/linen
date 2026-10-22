# Skill-Driven Audit Mode（CF skill 定方法，linen 做底盘）

状态：设计冻结（2026-10-17）。先并行新增一种运行模式跑对照，不替换 run 4 流程。

## 上游与版本

- vendored 副本：`linen/src/linen/third_party/cloudflare_security_audit_skill/` @ `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`（**入 git，随 wheel 分发**；见其 `PROVENANCE.md` 与 `SHA256SUMS`）。运行时从包内路径解析，不依赖工作目录，也不再需要 `.linen-runtime/` 下的副本。
- 适配产物（入 git）：`linen/src/linen/dispatcher/prompts/skill_audit/`。每个文件头部标注改编自哪个上游文件。
- 上游校验器：包内 `validate-findings.cjs` 与 `validate-coverage-ledger.cjs`。Linux/macOS 直接调用上游 CLI；Windows 走 `run-validator.windows.cjs`（Node 在 win32 不提供 `O_NOFOLLOW`/`O_NONBLOCK`，上游 CLI 会拒绝一切输入）。

## 职责分工

| 部分 | 职责 |
|---|---|
| CF skill（vendored） | 审计方法、角色提示、攻击类块、覆盖规则、findings 契约、校验器 |
| Linen Dispatcher | 阶段推进、任务分配、预算、超时、重试、取消、熔断 |
| Worker（codex gpt-6-luna / pi） | 执行具体角色任务（角色属于任务，不属于 worker） |
| Linen Server | 保存任务、证据、裁定、执行历史 |
| 图与进度界面 | 覆盖范围、调查关系、验证状态、阻塞原因 |

## 六阶段 → linen 映射

| CF 阶段 | linen 实现 | 产物 |
|---|---|---|
| 1 Reconnaissance | `explore` + recon recipes（保留现状） | `architecture` fact + 覆盖单元 facts |
| 2 Hunting waves | **新任务类型 `hunt`**：按覆盖单元派发；wave 后派 `critic` 任务 | 每单元 typed fact（见下） |
| 3 Candidate validation | **新任务类型 `verify_candidate`**：全新会话，输入隔离 | 三裁定 fact |
| 4 Structured output | 裁定 fact 直接序列化为 `findings.json` | findings.json（过上游 schema） |
| 5 Record verification | **新任务类型 `verify_record`**（独立于 3 的会话与输入） | verified/replace 记录 |
| 6 Report | audit-summary recipe 改为消费最终记录 | REPORT.md + 缺口披露 |

## 覆盖单元（coverage unit）fact schema

> **历史设计（已被取代）。** 本节的 `cov-<n>` 确定性 ID 方案是早期设计，已被上游兼容
> schema 取代：现行实现以 `canonical_refs` 派生的 `coverage_id` 作为单元身份
> （见下方 CF-S1-C / CF-S2 段与 D-033）。本节仅保留为设计沿革记录。

取代"每次图变化重跑 Reason"的驱动方式：单元状态机 `planned → in_progress → covered | candidate | blocked | deferred`，每单元绑定 `(entry surface, trust boundary, attack class)` 三元组，确定性 ID `cov-<n>`。

fact 携带：`unit_state`、`owner_run`、`reviewed_paths`、`unresolved_facts[]`、`fingerprints[]`、`deferred_reason`（必填当 state=deferred）。预算到不了 → 显式 `deferred`，禁止静默省略。

## 独立性边界（硬规则）

1. **finder ≠ verifier**：候选验证任务禁止分配给产出该候选 run 的 worker 会话；verifier 拿全新会话。
2. **输入隔离**：verifier/critic 的上下文投影 = 候选 fact + architecture fact + 上游 schema 分支逐字；**不含其他评审结论**。
3. **替换反弹**：`verify_record` 的实质性替换不得直接生效，派生新的 `verify_record` 由未参与会话复核；循环替换→移出 findings 并标 incomplete。
4. 角色→worker 由现有 worker_select 按 priority/负载选择；独立会话由 worker 适配器保证（codex 每次 run 新会话）。

## 三裁定契约（verdict 字段互斥，治 f105 类 FP）

- `confirmed`：`root_cause, conditions, execution, observed_result, severity, confidence`。禁止 `blockers/validation_plan/claimed_root_cause`。
- `needs_validation`：`claimed_root_cause, trace, blockers[], validation_plan{local|deployment}`。**禁止 severity**。
- `rejected`：`claimed_root_cause, trace, evidence, reason`。
- 落到 linen contract 层：按 verdict 拆 Pydantic 模型（`additionalProperties: false`）。
- 条件性可利用（如"在把反斜杠当分隔符的系统上"）若条件在部署目标上未确立 → 必须 `needs_validation`，禁止 `confirmed`。

## 诚实未完成交付

预算耗尽时：输出 REPORT.md（含已确认 findings）+ 覆盖摘要（covered/candidate/blocked/deferred 计数）+ 未验证候选清单（带单元与原因），运行状态 `incomplete` + 精确 reason（`validation_budget_exhausted` 等）。未验证候选**不得**进入 findings.json。

## 保留的现有机制

源码冻结、执行台账（.linen-executions）、租约、预算取消、Docker 隔离墙、独立 oracle、引用 canonicalize、envelope 合同、熔断与 orphan 检测。

## A/B 对照方案

- 同语料（BenchmarkPython 12 例）、同 worker（codex gpt-6-luna）、同预算（wall-clock 与 run 数同 run 4 口径）。
- 基线（run 4，静态门）：候选层 recall 100%（6/6 expected）、case 精度 75%（f105 把负对照 00004/00005 判为可利用）、fact 级 10/11。
- 成功判据：recall ≥ 基线、负对照 FP=0 或均降为 needs_validation、报告含诚实缺口披露。
- skill-driven 模式用独立 project（proj_008+）跑，run 4 结果封存作对照。

## 实施顺序

1. 本文档 + vendored 副本 + 角色提示词包（hunter/verifier/critic/report）。
2. Dispatcher：`hunt`/`verify_candidate`/`verify_record`/`critic` 任务路由 + 覆盖单元 fact schema + 三裁定 contract。
3. findings.json 序列化 + 上游校验器接入（`validate-findings.cjs`）。
4. proj_008 对照跑 → 按判据决定是否替换旧流程。

## 实施状态（2026-10-17）

- M1 `59f864d`：contracts + prompt pack。
- M2/M3（本分支）：全链落地。
  - `contracts/skill_audit.py`：与上游 report-schema.json 逐字段对齐（trace 用 kind/file/line/scope/description，severity/confidence/execution/remediation 为结构化对象，overall_severity 为字符串枚举且不得超过 impact），`validate-findings.cjs` 实测通过。
  - `dispatcher/contracts.py`：`validate_hunt_payload` / `validate_skill_verifier_payload` / `validate_critic_payload` / `validate_record_verification_payload`，错误信息均带形状示例。
  - `analysis/skill_prompts.py`：ATTACK-CLASSES 攻击类块逐字切块（"Do not send block or companion names alone"）+ core hunting method 按 code fence 完整提取。
  - `analysis/skill_findings.py`：findings.json 序列化（顶层数组）+ 上游校验器调用（失败即 incomplete）+ 替换反弹判定（SUBSTANTIVE_FIELDS）+ 未验证候选诚实降级（blocker 注明 candidate validation never ran）。
  - `tasks/skill_audit.py`：四个角色共享一个任务骨架（lease/healthcheck/projection/envelope），hunt 产 coverage_unit/candidate_finding/coverage_gap facts 并派生 verify-candidate 与 critic；verify-record 的 replace 经 bounce 预算（ substantive → 新会话复核；超预算 → finding_dropped）。
  - `scheduler/loop.py`：`_dispatch_skill_audit` + intent 路由（hunt / verify-candidate / coverage-critic / verify-record）。
  - `analysis/audit_graph.py`：`_skill_driven_proposals` 从覆盖单元状态派生意图（候选验证 > 种子 hunt > critic wave），幂等键 = 开放意图或确定性描述。
  - `config.py`：`audit.skill_driven`（coverage_seeds/max_bounces/max_candidates_per_wave）+ TaskType 扩展 + skill_audit prompt 组 token 注册。
  - 配置样例：`.linen-runtime/benchmark-python/dispatch-skill.yaml`（9 个种子单元，wall-clock/run 预算与 run 4 同口径）。
- 测试：`test_skill_audit_contracts.py`（11）+ `test_skill_audit_wiring.py`（16）+ `test_cf_vendor_resources.py`（10）。**测试总数以 CI 的实际 run 记录、commit 与测试报告为准**，本文档不再写未经实测的通过数。
- 待办 M4 运行：pi 配额恢复或 codex 独跑，用 dispatch-skill.yaml 起 dispatcher、建 proj_008、对照 run 4 基线评分。

## CF-S1-C 覆盖事件账本（追加式）

覆盖单元不是 fact，也不是审计事件：它是**计划边界**上的登记，因此走独立端点
`POST /projects/{project_id}/skill-coverage-events`，不复用 append-fact（后者只允许
observational fact 类型）。

**存储**（`server/db.py`，追加式迁移位点 `_ensure_vnext_columns`）：

```text
skill_coverage_events
    event_id / project_id / run_id / coverage_id / event_type / payload_version
    agent_id(NULL) / wave(NULL) / event_key / payload_json / payload_sha256 / created_at
    UNIQUE(project_id, run_id, event_key)
    FOREIGN KEY (run_id, project_id) REFERENCES runs(run_id, project_id)
    CREATE UNIQUE INDEX uq_skill_coverage_unit_registered
        ON skill_coverage_events(project_id, run_id, coverage_id)
        WHERE event_type = 'unit_registered'
    CHECK (event_type <> 'unit_registered' OR (agent_id IS NULL AND wave IS NULL))
```

只增不改由**数据库触发器**保证（`skill_coverage_events_no_update` /
`skill_coverage_events_no_delete`），不依赖调用方约定。该表**不随项目级联删除**：
外键取 NO ACTION，历史登记不可随项目一起消失。

**载荷**（`contracts/skill_audit.py` 的 `UnitRegisteredPayload`，v1）：

```json
{
  "schema_version": 1,
  "canonical_refs": {"surface": "...", "boundary": "...", "subsystem": "...", "attack_class": "..."},
  "prior_status": "none",
  "baseline": {"kind": "no_compatible_ledger", "lookup_ref": "..."}
}
```

`prior_status` 取上游 11 个合法值之一；`baseline.kind` 与 `prior_status` 必须自洽：
`none` 表示**已核验不存在**兼容历史，兼容历史存在时不允许写 `none`。摘要基于业务载荷
的规范化 JSON（固定键序/分隔符/UTF-8），**不**包含 `created_at`/`event_id`，因此合法
重试不会因时间变化被误判为冲突。

**请求契约只说"登记什么"，不说"凭什么"**：

```json
{"run_id": "...", "event_type": "unit_registered", "payload_version": 1,
 "coverage_id": "...", "canonical_refs": {...}}
```

请求体中**不允许**出现 `prior_status` / `baseline` / `agent_id` / `wave`（闭合模型，
多余字段直接 422）。历史基线与 run 计划由**服务端**通过注入的可信提供者解析。

**闸门（默认全部关闭）**：

| 情况 | HTTP |
|---|---|
| 首次成功登记 | 201 |
| 相同载荷幂等重放 | 200（返回原 event_id） |
| 非法 canonical / 枚举 | 422 |
| 同身份不同载荷 | 409 |
| run 不存在或不属本 project | 404 |
| 调用者不可信 | 403 |
| 生产写入关闭 | 503 `registration_disabled` |
| 可信基线不可用 | 503 `trusted_baseline_unavailable` |

**当前状态**：

```text
CF-S1-C  CONTRACT / PERSISTENCE  PASS
CF-S1-C  PRODUCTION REGISTRATION  BLOCKED — E48
```

生产注册被阻塞的原因不是实现缺失，而是**没有可信的历史基线来源**：CF-S2-B1 已具备
Cloudflare coverage 工件的**登记与引用**能力，但尚无任何历史来源通过源码身份核验
（实测已核验数 = 0），因此仍无法证明"不存在兼容历史"，而"未知"不等于 `none`。
默认策略（`CoverageRegistrationPolicy`）是关闭的，可信基线提供者与
可信 run 计划只能通过应用依赖注入安装，生产代码里**没有**任何"默认视为无历史"的
解析器。**CF 工件（coverage-ledger.json / findings.json）的生产仍等待 S2-A/B/C/D。**

### HTTP v1 正式契约（D-029）

`POST /projects/{project_id}/skill-coverage-events` 与
`GET /projects/{project_id}/skill-coverage-events` 自本节起是**冻结的契约级接口**。
客户端必须按状态码与**机器原因码**判断，**不得**匹配错误消息的自然语言文本。

**请求体（闭合模型，多带一个字段即 422）**：

```json
{"run_id": "...", "event_type": "unit_registered", "payload_version": 1,
 "coverage_id": "...", "canonical_refs": {"surface": "...", "boundary": "...",
 "subsystem": "...", "attack_class": "..."}}
```

**响应体**（`event_id` / `project_id` / `run_id` / `coverage_id` / `event_key` /
`payload_sha256` / `created_at` / `replayed` / `payload`）：

| HTTP | 语义 | 机器原因码 |
|---|---|---|
| 201 | 首次成功登记 | — |
| 200 | 幂等重放，返回原 `event_id`，`replayed=true` | — |
| 422 | 非法结构或 canonical identity 不成立 | `coverage_event_rejected` |
| 422 | coverage 不属于可信计划 | `coverage_unit_not_in_plan` |
| 409 | 同身份不同载荷 | `coverage_event_conflict` |
| 404 | run 不存在或不属于本 project | `run_not_found` |
| 403 | 调用者未获授权 | `untrusted_caller` |
| 503 | 生产写入关闭 | `registration_disabled` |
| 503 | 可信基线不可用 | `trusted_baseline_unavailable` |

**检查顺序是 v1 行为，不得无意识调整**：同一个 422 可能由不同原因码产生，
取决于请求是否落在可信计划内——计划不含该 coverage id 时报
`coverage_unit_not_in_plan`，计划含该 id 但四维派生的 canonical id 对不上时
才报 `coverage_event_rejected`。完整顺序为：

```text
1. 503 registration_disabled            生产写入未开启
2. 403 untrusted_caller                 调用者未被接受
3. 422 coverage_unit_not_in_plan        无可信计划，或该单元不在计划内
4. 503 trusted_baseline_unavailable     无可信基线 / 历史未知 / 查询失败
5. 422 coverage_event_rejected          cov-<n> 旧式 id，或 canonical id 不自洽
6. 404 run_not_found                    run 不存在或不属本 project
7. 409 coverage_event_conflict          同事件键、载荷不同
```

**幂等语义**：事件键为 `unit_registered:<coverage_id>`，唯一范围
`(project_id, run_id)`。同键同载荷（按规范化 JSON 摘要比对，**不含**
`created_at`）返回 200 与原事件；同键不同载荷返回 409，**不覆盖**。

**只读端点**：`GET /projects/{project_id}/skill-coverage-events?run_id=...`
返回该 run 的登记投影，**按 project 隔离**（跨 project 读取返回空列表），
未知 project 返回 404。该端点只读，但仍会暴露 surface / boundary / prior_status，
不得被当作"天然无暴露风险"。

**生产开启条件（D-030）**：以下条件**必须全部满足**才允许开启生产写入，
当前前三项**均未实现**：

| 条件 | 状态 |
|---|---|
| 可信调用者证明 | 未实现 |
| 可信 run 计划解析 | 仅测试注入 |
| 可信历史基线解析 | 未实现 |
| canonical ID 验证 | 已实现 |
| 数据库不可变性 | 已实现 |
| 幂等与事务 | 已实现 |

回环地址（server 默认监听 `127.0.0.1`）**不构成**可信身份：同机任意进程都能
向该地址发 HTTP。可信调用者、执行身份与 artifact owner 的绑定机制归 CF-S2-C；
凭据不得进入 prompt、模型 stdout、审计图或普通日志。

**删除策略（D-028）**：审计事件默认保留。项目一旦拥有不可变覆盖事件，
`DELETE /projects/{project_id}` 返回 **409 `PROJECT_HAS_COVERAGE_EVENTS`**；
直接删除被事件引用的 run 会被外键拒绝。**这不是临时限制，而是产品行为**，
受控清除（归档 / 保留期限）需单独裁定，不得通过改回 CASCADE 绕过事件不可变性。

**实测的删除语义**（SQLite 3.50.4，脚本见取证记录）：

| 场景 | 结果 |
|---|---|
| 外键 NO ACTION（当前设计） | `FOREIGN KEY constraint failed` → 409 `PROJECT_HAS_COVERAGE_EVENTS` |
| 外键 CASCADE | 被 append-only 触发器拦下，消息 `skill_coverage_events is append-only`（**不含** `FOREIGN KEY`）→ 会落到 500 而非 409 |
| CASCADE 且**去掉**触发器 | 删除成功，账本被抹光 |
| `PRAGMA foreign_keys=OFF` | 级联不发生，事件行留下但其引用的 run 已消失（孤儿） |

因此外键取 NO ACTION 的理由是**删除失败时给出的错误类别**，不是"级联会绕过触发器"：
SQLite 执行外键动作时**会**触发子表的 BEFORE DELETE 触发器，且
`PRAGMA recursive_triggers` **不**影响这一行为（SQLite 官方文档 foreignkeys.html
第 6 节："The PRAGMA recursive_triggers setting does not affect the operation of
foreign key actions"）。另外，"级联会触发子表触发器"是 SQLite 3.6.19 起的行为，
仓库未锁定 SQLite 版本，因此**触发器是第二道防线、不是主防线**；NO ACTION 约束
不依赖版本。`get_conn()` 每条连接都设 `PRAGMA foreign_keys=ON`，但**裸 `sqlite3`
打开数据库的维护脚本会绕过该约束**——UPDATE/DELETE 触发器仍然有效。

## CF-S2-A 多轮事件（追加式）

`skill_coverage_events` 除登记外还承载两类**历史**事件，它们记录单元的
"谁接手了、接手时拿到了什么块、这一轮以什么终态结束"：

```text
unit_registered
       |
       v
wave_started(wave=1)      owner + 选块来源 + 起始路径
       |
       v
attempt_recorded(wave=1)  终态 + 证据
       |
       v
wave_started(wave=2)      新的 owner + 重新分配理由
       |
       v
attempt_recorded(wave=2)  终态 + 证据
```

**事件键（幂等范围 `(project_id, run_id)`）**：

```text
wave_started:<coverage_id>:<wave>
attempt_recorded:<coverage_id>:<wave>
```

同键同载荷 → 幂等重放（返回原 `event_id`）；同键不同载荷 → 409 冲突，**不覆盖**。

**服务端状态机**（`server/skill_coverage_waves.py`，顺序判断在**写入的同一事务**内完成，
客户端不能自称"这是第 3 轮"）：

| 规则 | 拒绝异常 |
|---|---|
| 单元未登记 | `CoverageEventRejected` |
| 单元的首轮不是 wave 1 | `CoverageWaveOrderRejected` |
| 前一轮没有终态 attempt 就换 owner | `CoverageWaveOrderRejected` |
| attempt 引用未启动的 wave | `CoverageWaveOrderRejected` |
| attempt 的 owner 不是该 wave 的 owner | `CoverageWaveOrderRejected` |
| 新 wave 复用早先 wave 的 owner | `CoverageWaveOrderRejected` |
| artifact 复用早先 attempt 的产物 | `CoverageWaveOrderRejected` |
| 同事件键、载荷不同 | `CoverageEventConflict` |

（多轮事件**没有** HTTP 端点，因此这些是服务层异常名，不是 HTTP 状态码。）

**重新分配理由的时序**：上游要求**每个**归档 attempt 都带非空
`reassignment_reason`，但"为什么换人"往往在派发下一轮时才确定。因此理由
**随下一次 `wave_started` 记录**，由只读投影关联回被归档的那一轮（PM R4）。
若没有下一轮，最后一轮仍是当前轮，**不会**被虚构为归档 attempt，也**不会**
编造理由。

**可信选块来源**：选块是**计划**的决定，不是模型的自述——上游同样把
"assignment block map"作为父进程写进 hunter prompt 的东西，hunter 的输出契约里
没有块字段。linen 侧的计算点是 `dispatcher/analysis/coverage_blocks.py`：
`seed.attack_class` → 从 pinned 快照里逐字切出 `ATTACK-CLASSES.md` 的块 →
记录为 `ATTACK-CLASSES.md#<类名>`。

**D-033：描述性引用与可信选块是两个概念。** `canonical_refs.attack_class` 是
**描述性身份引用**（四维之一，决定 canonical id），`ordinary_attack_class_block`
是**可信计划选中的上游块**（必须是快照里九个标题之一）。二者不可假设相等：

| 对象 | 职责 |
|---|---|
| `AttackClass`（`contracts/skill_audit.py`） | 仅保留历史公开 API 兼容，**不参与**协议判定 |
| `canonical_refs.attack_class` | 描述性身份引用 |
| `ordinary_attack_class_block` | 可信计划明确选择的上游攻击类块 |
| `ATTACK-CLASSES.md` | ordinary block 标题与内容的权威来源 |
| `CoverageBlockSelection` | 选块结果、来源及 capability 的可信登记 |

最小过渡策略：当 `attack_class` **精确等于**合法块标题时保留精确匹配；否则
必须由可信计划显式给出 `ordinary_block`（`dispatch.yaml` 的 seed 字段）。两者都没有
时抛 `BlockSelectionUnresolved`（`code = "block_selection_unresolved"`）——**禁止**
模糊匹配、大小写折叠、snake_case 转换或任何自动猜测。生产 prompt 路径
（`dispatcher/tasks/skill_audit.py`）已按此改为严格解析。

```yaml
audit:
  skill_driven:
    coverage_seeds:
      # attack_class 恰好是上游块标题：直接精确匹配
      - surface: "http-public-api"
        boundary: "anonymous-to-authenticated"
        subsystem: "authorization"
        attack_class: "Access control"
        starting_paths: ["app/authz.py"]
      # attack_class 是描述性引用：必须由计划显式指定块
      - surface: "http-public-api"
        boundary: "anonymous-to-authenticated"
        subsystem: "authorization"
        attack_class: "injection"
        ordinary_block: "Injection"
        starting_paths: ["app/api.py"]
```

`ordinary_block` 是可选字段（默认 `null`）；它**不进入** canonical id——新增可信
选块依据不会改变既有 `coverage_id`（D-033）。

**D-032：companion capability 显式化。** `selected_companion_blocks = []` 本身有歧义
（"目录在、但没选"与"根本没有目录"是两回事）。`CoverageBlockSelection` 因此带
`companion_catalog_state ∈ {available, unavailable, unknown}`：

| 取值 | 含义 | 约束 |
|---|---|---|
| `available` | 目录存在 | 可合法选择空集，但必须带可信选择记录（`source` 必填） |
| `unavailable` | 目录不存在 | **必须**对应空选择，否则契约拒绝 |
| `unknown` | 旧事件未记录该字段 | 不自动转 `unavailable` |

linen 当前产出 `unavailable`（10 个 companion playbook **未 vendored**）。
该字段**只属于 linen 的可信溯源**：不进 canonical refs、不进 coverage id、
不进上游 ledger 顶层、不进模型可填的 hunt payload。**受控兼容**：字段为 `None` 时
`digest_content()` 省略该键，因此该字段出现之前写入的事件**摘要不变**；投影对缺
字段的旧事件报 `unknown`，**不补造** `unavailable`。

**D-034：登记状态与完整 ledger 导出资格分离。** 只有 `unit_registered` 的单元在
linen 原生投影里是 `planned`，但**不得**导出为完整上游 ledger——上游要求
`starting_paths` 非空，编造它等于声称一次从未发生的覆盖。导出资格由
`CoverageUnitProjection.exportable` / `export_blockers` 表达，
`upstream_coverage_ledger()` 跳过不合格单元，
`upstream_ledger_export_report()` **显式列出**被跳过的单元与原因（不静默缺口）。

**只读投影**（`project_multiwave()`）：纯函数，重放同一事件流必得同一结果。
投影**不发明**任何未发生的 wave / attempt / finding：只有登记的单元是 `planned`，
启动但未终结的 wave 是 `in_progress` 且不进入归档。投影可直接产出上游形状的
coverage ledger（`upstream_coverage_ledger()`），并**已用包内上游校验器实测通过**
（`test_skill_coverage_waves.py` 跑 `validate-coverage-ledger.cjs`）。

**事件顺序合法性由 linen 自有测试保证，静态文档合法性由上游 validator 保证，
两者不互相替代。**

**当前状态**：

```text
CF-S2-A  EVENT CONTRACT / STATE MACHINE / PROJECTION  PASS
CF-S2-A  PRODUCTION MULTIWAVE WRITE  BLOCKED — 无可信 owner / 选块提供者
```

多轮事件的**生产写入仍然关闭**：可信 owner（assignment registry）属 CF-S2-C，
可信选块提供者尚未安装。`POST /projects/{project_id}/skill-coverage-events`
**仍然只接受 `unit_registered`**，多轮事件走独立可信写入接口且默认关闭。


## CF-S2-B1 不可变历史工件登记

`prior_status` 只有在背后的历史**能被重新找回并重新校验**时才值得存下来。一句自由文本
的 `lookup_ref` 做不到：路径可以被改写，句子可以被重打。本节描述这条链
（PM v2.1 的 **D-036**）：

```text
外部 run 目录
    -> 受控导入 (import_historical_run)
    -> 格式与来源验证
    -> 不可变登记 (coverage_baseline_sources)
    -> 冻结历史清单 (BaselineLineageManifest)
    -> 可信 resolver (CF-S2-B2)
```

**受控导入**（`server/skill_baseline_sources.py`）：导入根目录由运维声明，路径**不是**。
读取必须留在根目录内、拒绝 `..`、拒绝任何路径分量上的符号链接、拒绝非普通文件；
读到的每个文件都记 sha256。导入**不因为来源不可信而抛错**——它返回一个说明原因的
候选，因为「静默丢弃后再宣称历史完整」正是必须避免的事（D-036）。

**不可变登记**（表 `coverage_baseline_sources`，`server/db.py`）：追加式，**不随项目删除
级联**（外键 NO ACTION + 两个只增不改触发器）。项目若拥有基线来源，`DELETE /projects/{id}`
返回 **409 `PROJECT_HAS_BASELINE_SOURCES`**（与 `PROJECT_HAS_COVERAGE_EVENTS` 分开）。

**冻结历史清单**（`BaselineLineageManifest`）：声明本次基线可比的历史范围，并说明该范围
是否**封闭**：

| 状态 | 含义 |
|---|---|
| `complete` + 无 `unprocessed` | 范围封闭 → 可以支撑**负证据** |
| `incomplete` / 有 `unprocessed` | 范围未封闭 → **不得**得出 `none` |
| `scope_kind = lineage_root` | 显式声明「本项目没有前代」，成员必须为空 |

清单里的每个成员**必须已登记**——清单不能指向没人导入过的来源。

**不可变引用**：`cf-ref-v1:<64 位小写 hex>`，摘要输入是 `cf_canonical_json(structured_ref)`。
引用**本身不是证据**：读取时必须找回本体并**重算摘要**；本体丢失或摘要不符 → 不可验证
引用（D-037）。

**source identity 不自动升为 verified**：真实语料的 `source_ref` 有三种形状（纯 40 位
commit / commit + 自由文本注释 / 非 Git 发行包）。导入器**从不**把正则匹配成功当作验证：
它只保留原文与候选 commit，`kind = "unverified"`、`verified = false`。
`git_commit` 身份必须带 40 位 commit；`frozen_digest` 身份（非 Git 发行包）必须带
冻结源码摘要。

**上游没有可复用的实现，但有规范性的行为原则**：实测表明上游**现成脚本**从不读取任何前次
run 的 ledger（语料里 `prior_run_paths` 全空，无脚本读他次 `coverage-ledger.json`），9 个
非平凡 `prior_*` 字面量在真实语料中**零命中**（只存在于 `validate-coverage-ledger.cjs:71-79`
的集合字面量），且 `source_ref` **从不被任何代码比较**。

但上游的**规范性指令**（`SKILL.md` 与 `RECONNAISSANCE.md`，commit `c1c8a8c`，**未 vendored**）
明确要求协调者在存在历史运行时读取兼容的 coverage ledger 与 findings，并比较**相关源码、
条件与证据**；且明确说明**单独的历史 source ref 不能证明源码未变化**。

因此准确的登记是：

> 上游**规定了历史对比的行为原则，但没有提供自动执行该比较的通用代码实现**。

⇒ 上游文档可作为历史状态与证据要求的依据；**不可**声称上游提供了可直接复用的
source comparison 算法。**比较规则由 linen 自己实现并承担测试责任**；凡上游未定义、
现有证据又不足以确定的映射，一律失败关闭（`unknown`）。

跨运行可用锚点只有 `coverage_id`（由 `canonical_refs` 派生）与 `result_fingerprints`；
上游**不存在**「prior unit」这种数据结构。

**当前状态**：

```text
CF-S2-B1  可信历史工件登记能力  PASS（本地）
CF-S2-B2  真实 resolver / prior_status 解析  NOT STARTED
生产注册与多轮写入                继续关闭
```

真实语料分级（16 个 run 目录）：结构合法 ledger **11**、metadata 完整 **11**、
source identity 已记录 **11**、**已核验 0**（导入器不自动核验）、可信负证据 **0**
（全部 `prior_run_paths` 为空，尚无 lineage root 声明）、导入失败 **5**（无 ledger 文件）。


## CF-S2-B1 P1-A 受控上游格式验证

**PM v2.4 裁定（D-043/D-044/D-050/D-051）**：导入器此前只做**最低限度 JSON 检查**
（能取出数组 / unit 是 Mapping / 有 `coverage_id`），**没有执行完整上游 schema 校验**；
`seal_lineage_manifest()` 也只核对成员的 `source_ref` 已登记，**未核对成员声明的
`ledger_sha256` / `metadata_sha256`**。因此 B1 的阶段登记收窄为：

```text
CF-S2-B1  不可变登记与引用机制            PASS
CF-S2-B1  上游格式验证的生产导入边界       缺口 → 本片修复
```

**三层必须分开，不得合并**（D-043 / D-051）：

| 层 | 含义 | 取得方式 |
|---|---|---|
| `readable_candidate` | 文档**可读**且带 unit | `import_historical_run()`（不抛错，说明原因） |
| `upstream_schema_validated` | 文档**符合上游完整契约** | 受控离线流程跑 pinned 上游 validator 得到的凭据 |
| `source_identity_verified` | 源码身份**已核验** | 尚未实现（属 CF-S2-B2 的 attestation） |

`_ledger_units()` 成功 **≠** 上游格式验证成功；`HistoricalSourceCandidate.eligible=True`
**≠** upstream-valid。二者现在在代码与文档里都显式分开。

**受控离线验证**（`dispatcher/analysis/cf_baseline_validation.py`，PM v2.4 Q40）：

- 复用既有 `validator_command()`，**不新建第二套 validator**，**不在 Python 内复制 872 行
  Node validator**；本片**不新增顶层 CLI**。
- **防竞态**：验证的是**已经被读取并固定的那份 bytes**，不是运维给的原路径——先安全读取 →
  受控暂存同一份 bytes → validator 验证暂存文件 → 回读确认摘要一致 → 才签发凭据。
  暂存目录安全创建（`O_EXCL`）、受控、失败必清理。
- **凭据（`LedgerValidationReceipt`，版本化）强制四项绑定**：
  1. 原始 ledger bytes 的 **SHA-256**（不得只比路径或文件名）；
  2. **validator 身份**：pinned upstream commit + **实际执行的 validator 文件摘要**
     （不能只写 `"validator": "cloudflare"`）；
  3. **验证执行本身**：凭据由受控离线流程产生；
  4. **被登记的历史来源**：`project_id` / `source_ref` / `ledger_sha256` / `metadata_sha256`
     ——同一来源后来换了 ledger 内容，旧凭据即失效。
- **server 不执行 Node**（Q40-c），只做**信任验证**：凭据必须来自受控通道、凭据引用的
  ledger 仍存在、重算 SHA-256 一致、validator 固定版本符合预期、与本项目历史来源记录一致。
  **`valid=true` 不是可信输入**：即使 JSON 内摘要全对，只要普通 HTTP 客户端能自造完整凭据，
  就**不能**获得可信提升权限。**本片只做可信来源隔离，不建设公开验证上传服务。**
- **Windows 边界（D-051）**：上游 CLI 用 `O_NOFOLLOW | O_NONBLOCK` 打开输入，Node on win32
  不暴露这两个常量，故 Windows 走仓库自有 `run-validator.windows.cjs`。它能给出**同样的
  schema 判定**，但**不具备**与 Linux 相同的内核级文件打开保证。凭据记录实际 runner，
  正式 Ubuntu 验收继续用原生 pinned validator。

**可信封存与结构完整必须分开（D-052）**：`seal_lineage_manifest()` 现在**逐项核对**成员声明的
`ledger_sha256` / `metadata_sha256` 与已登记来源是否一致，不一致直接拒绝——清单不能声明一份
从未被导入过的历史。但 `closed=True` **仍然只表示结构封闭**；「可信历史范围已封存」还需要
受控调用者 + 明确项目/lineage scope + 不可变封存凭据，那是 B2-A 的基础设施。
**在此之前，生产 resolver 继续返回 `unknown`。**

**本片验收**：CR-T01（错误 canonical ID 不得取得 upstream-valid 资格）、CR-T02（上游不允许的
顶层形状必须拒绝）、CR-T03（manifest 成员摘要与登记不一致必须拒绝），以及 5 项凭据边界
（绑定精确 bytes / 改动即失效 / 不可信 JSON 不得提升来源 / Windows runner 与上游判定一致 /
schema 合法不等于来源已核验）。原 30 条 B1 用例保留。


## CF-S2-B1 P1-B 安全物化与引用项目隔离

**PM v2.5 裁定**：P1-A 的**格式验证**通过，但**可信签发者准入**仍为 OPEN（D-056）；Q42 用**完整
64 位 SHA-256** 作目录身份（D-053），Q43 共用不可变证明基础设施但**分表**（D-054），Q44 约定
P1-B 完成后再统一做 P1-C（D-055）。阶段登记：

```text
CF-S2-B1  上游格式验证                      PASS
CF-S2-B1  manifest 成员摘要逐项核对           PASS
CF-S2-B1  安全物化 + 引用项目隔离             本片修复
CF-S2-B1  验证凭据的可信签发者准入            OPEN → P1-C
```

**目录身份是内容摘要，不是名字**（D-053）。物化目录名为

```text
sha256(b"linen:baseline-materialization:v1\x00" + source_ref.encode("utf-8")).hexdigest()
```

的**完整 64 位**，取自**未经任何规范化**的 `source_ref`（不 trim、不折叠大小写、不改写路径分隔符）。
因此 `a/b` 与 `a__b` 落在**两个**不同目录；旧实现用 `source_ref.replace("/", "__")` 会让两者
落到同一目录。目录名**不承载业务语义**——`source_ref` 本来就存在 `BaselineSourceRecord` 里。

**文件系统步骤全部相对已打开的目录，且从不跟随符号链接**（`server/baseline_materialization.py`）：

- 每层目录用父目录描述符 `mkdir` + `O_DIRECTORY | O_NOFOLLOW` 打开；
- 每个文件用目录描述符 `O_CREAT | O_EXCL | O_NOFOLLOW` 创建——`O_EXCL` 保证不会覆盖既有
  文件，也不会穿过一个已存在的符号链接；
- **先 `resolve()` 再按路径写并不能阻止并发目录替换**，所以不这么做。

**平台不支持时失败关闭，不静默退回弱保护**：没有 `O_NOFOLLOW` / `dir_fd` 的平台（Windows）
**拒绝物化**并报明确原因，而不是退回到「先检查再写」。这与 D-001 一致（linen 只支持
macOS/Linux）。Windows 上的相关用例**跳过**而不是假装通过。

**幂等与失败清理**：

| 场景 | 行为 |
|---|---|
| 同一来源重复物化 | 文件字节不变、artifact 行数不变（`register_artifact` 本身幂等） |
| 已存在文件摘要不同 | **拒绝复用**，且**不覆盖**原文件 |
| 中途写失败 | 删除本次创建的文件，**不登记**任何 artifact 行 |
| 目标文件是符号链接 | 拒绝，不写入链接目标 |
| 中间目录是符号链接 | 拒绝，不写入链接目标 |

**引用读取必须带项目**（CR-T06）：`read_reference(conn, *, project_id, reference)` 与
`referenced_manifest(conn, *, project_id, reference)` 现在**必须**传 `project_id`，查询条件带上
`project_id`。理由：引用是**记录体**的摘要，而记录体里含 `project_id`，所以两个项目的引用
本就不同；此前按 `lookup_ref` 全局查询，等于让一个项目读到另一个项目的历史。**没有保留任何
无项目约束的兼容旁路**（原 4 处调用点已同步迁移）。

**仍然 OPEN，不得当作已关闭**：

- **D-056**：自摘要自洽 + 已在库中 + 自称来自 operator，**都不单独构成可信凭据**；
  「登记只能经受控签发入口」尚未证明。P1-C 增补 CR-T07/08/09。
- **D-052**：`closed=True` 仍只表示结构封闭；可信 lineage seal 属 B2-A。


## CF-S2-B1 P1-C 可信签发与一致性闭合

**PM v2.6 裁定**：Q45 = A（Windows **永久失败关闭**，不提供开发期 unsafe 旁路，D-057）；
Q46 = 受控内部入口 + 最小 HMAC 签发认证（D-058）；Q47 = P1-C **只**关闭 D-056 与必要的一致性
回归，source attestation / lineage seal / prior_status resolver 留给 B2-A/B2-B/B2-C（D-059）。

### 自摘要不等于签发权

【事实】`LedgerValidationReceipt.sealed()` 只能证明**自身内容未被改动**；任何能构造 JSON 的调用者
都能算出自洽的摘要。因此「已在库中 + 自称来自 operator + 摘要自洽」**不构成可信凭据**（D-058）。

**认证封套（`LedgerValidationAuth`）**把「谁签发」变成可验证的事实：

```text
{"auth_version": 1, "key_id": "...", "receipt_sha256": "...",
 "project_id": "...", "source_ref": "...",
 "ledger_sha256": "...", "metadata_sha256": "...", "mac": "<HMAC-SHA256>"}
```

- 【事实】MAC 输入是**域分隔 + 规范化 JSON**（`linen:baseline-ledger-validation:v1` + 排序后的
  五个字段），因此**同一张封套不能跨项目、跨 source_ref、跨 receipt 重放**。
- 【事实】封套**不改变** `LedgerValidationReceipt.receipt_sha256` 的计算规则；receipt 的业务载荷
  不变时，其摘要必须不变。
- 【事实】认证证明存在**独立的追加式表** `coverage_ledger_validation_auths`（唯一键
  `project_id + receipt_sha256 + key_id`，append-only 触发器），**不 UPDATE 回填旧记录**，
  也不承担 B2-A 的 source identity attestation 职责（D-059）。

### 密钥从哪来、怎么用

- 【事实】密钥由**运维通过环境变量注入**：`LINEN_BASELINE_VALIDATION_KEYS`，
  形如 `{"baseline-validator-key-1": "<hex>"}`。**密钥字节不进 Git、不进 SQLite、不进 prompt、
  不进模型 stdout、不进普通日志、不进错误响应、不进 audit graph**；只记录 `key_id`。
- 【事实】服务端用 `hmac.compare_digest()` 校验。
- 【事实】**没有配置可信密钥 → 失败关闭**：受控流程签不出封套，`verify_ledger_validation()` 对
  该 receipt 报「无可信签发证明」。没有「默认开发密钥」兜底。
- 【推断】HMAC 证明的是「持有共享密钥的一方在受控流程里签发」，**不证明具体是哪位自然人**；
  dispatcher 与 server 共享密钥，因此这是**进程间认证**，不是不可抵赖的个人签名。P1-C 范围内足够。

### 三条一致性绑定

| 检查 | 位置 | 说明 |
|---|---|---|
| pinned validator 实际摘要 | `server/skill_baseline_sources.py` `pinned_validator_sha256()` | 比较 receipt 的 `validator_sha256` 与**实际读取的 pinned validator 文件摘要**；只比 commit 名称不够 |
| ledger 三方摘要 | 同上 `verify_ledger_validation()` | `SHA256(actual bytes) == registered_source.ledger_sha256 == receipt.ledger_sha256`，任一不同即不成立 |
| 凭据自洽 | `register_ledger_validation()` | 登记时即拒绝「validator 摘要不符」的 receipt |

### 两项代码复核加固

- **R-A（登记局部原子性）**：`materialize_baseline_artifacts()` 的 artifact 登记包在
  **SAVEPOINT** 里——中途失败则本次新增行**全部回退**（不是靠外层事务回滚）。
  文件写入与 SQLite 仍**不是**跨存储原子事务：写失败清文件，登记失败留完整文件，重试幂等。
- **R-B（既有文件类型竞态）**：`existing_digest()` 在 `os.open()` 之后用 `os.fstat()` **复核**
  打开的描述符确实是普通文件，并加 `O_NONBLOCK`，避免被换成 FIFO 时阻塞。

### 本片验收

P1-C-T01–T12（未认证自签 receipt 不得取得权威资格 / 可信签发可登记 / MAC 篡改拒绝 / key_id 未知
或密钥缺失失败关闭 / 跨项目跨来源重放拒绝 / 重复登记幂等 / 一张封套不能承载另一张 receipt /
pinned validator 摘要不符拒绝 / 三方摘要一致 / 旧的无认证 receipt 保持可读但不获权威资格 /
登记部分失败回滚新增行 / 非普通文件安全失败不阻塞），
加上 CR-T07（自签 receipt 不能绕过可信签发）、CR-T08（pinned validator 摘要）、CR-T09（三方摘要）。



## CF-S2-B1 P1 阶段验收与 P1-H1 密钥加固

**PM v2.7 裁定**：Q48 = 批准登记 `CF-S2-B1 P1 TRUSTED IMPORT BOUNDARY PASS`（P1-A/P1-B/P1-C 三个子片
均可关闭），并授权开工 CF-S2-B2-A；Q49 = **接受**现有单变量 JSON 密钥环，不拆成
`..._SIGNING_KEYS` / `..._VERIFY_KEYS`（对称密钥下拆变量并不产生密码学隔离，真正的隔离取决于
进程能否读到密钥）；Q50 = **接受**动态语料的性质断言，不把 366 或 386 固定为协议常量。

### 阶段关闭时的 CI 实测

【事实】Ubuntu CI run `39817241795`（head `323eaca`）conclusion **success**：

```text
collected 1116 items
1109 passed, 0 failed, 7 skipped
```

【事实】七条 skip 的分布是：**2** 条真实 CF 语料测试（CI 机器没有外部对照语料）、**3** 条 Docker
oracle E2E 测试（`test_oracle_docker_e2e.py` 的一个用例经 `parametrize` 展开成 3 条）、
**2** 条真实 Docker 隔离测试。

### P1-H1：密钥长度下限

【事实】HMAC-SHA256 不会因为密钥短而变弱，**秘密本身**会：一个字节的密钥可以被枚举，
因此**短密钥不能承担「可信签发」的重量**。`configured_validation_keys()` 现在只接受
**不少于 32 字节（256 位）**的密钥材料，短密钥**被排除在密钥环之外**——不是报错，而是
「不构成可信密钥」，于是依赖它的每一项判定都**失败关闭**。

- 【事实】实现：`server/baseline_validation_auth.py` `MINIMUM_VALIDATION_KEY_BYTES = 32`。
- 【事实】验收测试：`test_validation_key_shorter_than_32_bytes_is_rejected`
  （31 字节 → 密钥环为空且 `signing_key()` 为 `None`；32 字节 → 被接受）。
- 【推断】**在该加固完成之前，不得把任意运维配置的非空密钥都视为具有足够认证强度。**

### 密钥轮换的运维规则

【推断】正式运维应遵守：

- 签发使用**当前活动密钥**；
- 验证可以使用**仍处于信任期内的旧密钥**；
- 撤销旧密钥后，对应历史凭据**失去可信资格**（这是**显式**失败，不是静默降级）；
- **不得**为了维持旧凭据可用性而接受未知密钥或关闭 MAC 验证。

【事实】本片**不建设**新的密钥管理服务：封套只记录 `key_id`，不保存密钥本身。



## CF-S2-B2-A 可信源码身份证明与可信历史封存

**PM v2.7 裁定**：Q48 = 批准登记 `CF-S2-B1 P1 TRUSTED IMPORT BOUNDARY PASS` 并授权开工 B2-A；
Q49 = 接受现有单变量 JSON 密钥环；Q50 = 接受动态语料的性质断言，不冻结总数。
B2-A 的范围**只**建立两样东西：**可信源码身份证明**与**可信历史范围封存**；
**不**开始源码差异比较，**不**开始 11 值 prior_status 生产解析（那是 B2-B / B2-C）。

### 职责边界

```text
coverage_baseline_sources          已登记的历史来源与 manifest（结构封闭，不带签名）
        |
        +-- coverage_source_attestations   证明历史源码身份
        |
        +-- coverage_lineage_seals         证明本轮历史范围被可信封存
```

【事实】两张表**共用**已有的规范 JSON、载荷摘要、追加式触发器与身份校验原语，
但**分表**（D-054）；没有第三套通用证明框架。
【事实】外键一律 `NO ACTION`（与既有证明表一致）：项目被删除后，证明行不得仍可被验证。

### 两种核验方式

| 方法 | 核验内容 | 位置 |
|---|---|---|
| `git_commit` | 提交对象**真实存在**（`cat-file -t`）、解析回自身、树对象名合法、**工作区干净**（`git status --porcelain` 为空）、仓库 remote 的 `owner/repo` 与登记来源的 origin 一致 | `server/source_identity.py` `verify_git_source_identity()` |
| `frozen_digest` | 重新读取**冻结的工件字节**，与登记摘要逐字节比对 | `server/source_identity.py` `verify_frozen_source_digest()` |

【事实】git 核验**不止**检查「40 位十六进制格式合法」：`git rev-parse` 会原样回显一个并不存在的
提交名，所以真正被问的是**对象本身**；工作区若有未登记改动，磁盘上的文件就不是那个提交，
因此工作区必须干净。
【事实】git 证明还必须与**冻结快照**一致：登记来源里记录的提交名就是证明可声明的提交，
声明别的提交会被拒绝（这正是「证明描述了另一段历史」的防线）。

### 信任边界

- 【事实】证明由**服务端自己核验**得到（`build_source_attestation()` / `build_lineage_seal()`），
  调用方只能给出「我认为是哪个仓库、哪个提交」，**不能**给出「结论是已核验」——
  自称 `verified = true` 的 JSON 得不到任何权威（A-T03）。
- 【事实】证明由**受控流程签名**（`dispatcher/analysis/cf_baseline_validation.py`
  `attest_historical_source()` / `seal_historical_scope()`），服务端只**验证**签名，从不签发（D-058）。
- 【事实】封套 MAC 输入按证明种类**域分隔**（`linen:source-identity-attestation:v1` /
  `linen:lineage-seal:v1`），所以 attestation 封套**不能**被当作 seal 封套重放。
- 【事实】**没有配置可信密钥 → 不产生任何证明**，`source_identity_verified` 保持 0。
- 【推断】**这两张表都不是确认权威**：证明说的是「源码是什么」，不是「本轮发现的漏洞是真的」
  （D-039）；不得由历史 verified 直接推导本轮 confirmed。

### 冲突不被静默覆盖

【事实】同一来源出现**相互矛盾**的两份证明时，两份都保留（追加式，不 UPDATE），
解析结果是 **conflict**，而不是「取最新一条」（D-045、R4）。
已注册来源的成员 attestation 变化后，原 seal 在**再验证**时会失配，
`trusted_negative` 随之降为 false。

### trusted negative 的条件

【事实】`lineage_seal_status().trusted_negative` 为 true 需要**同时**满足：

1. 该 run 存在一张**可验证**的 seal（封套 MAC 有效）；
2. seal 引用的 manifest 仍然**封闭**（complete 且无 unprocessed）；
3. manifest 的**每个**成员仍有**可信**的 source attestation。

【事实】结构 complete 的 manifest **本身不是** seal，也不能承载负证据（A-T11）；
`lineage_root`（声明本项目没有前代历史）同样必须由可信签发入口产生（A-T12）。

### 本片验收

B2-A-T01–T14：证明只能关联已登记来源 / 跨项目关联被拒 / JSON 自报 verified 不产生可信身份 /
git 提交与冻结快照不一致时拒绝（含错误仓库、脏工作区）/ 非 Git 来源可由冻结摘要核验 /
两张表 UPDATE+DELETE 被数据库拒绝 / 同一证明重复登记幂等 / 矛盾证明不静默覆盖 /
缺少可信证据时保持 unverified / seal 必须关联明确的 run 与项目 / complete manifest 但无可信封存时
不可作负证据 / lineage root 来自可信受控声明 / seal 成员可再验证 / 两张证明不自动开放生产注册。

### 真实语料的分层（分开报告，不合并）

【事实】对真实对照语料的只读分级：

```text
candidate_run_dirs        18
readable_candidate       12
upstream_schema_validated 12
frozen_snapshot_anchored 12   （冻结工件字节仍与登记摘要一致）
source_identity_verified  0   （审计代码的身份未被证明）
trusted_negative          0   （没有任何可信封存）
units_in_readable_candidates 393
```

【推断】`frozen_snapshot_anchored = 12` 与 `source_identity_verified = 0` **不是同一件事**：
前者证明「导入进来的 ledger 快照字节未变」，后者证明「被审计的**代码**是哪个提交」。
审计对象的上游仓库在本机不可得，因此真实语料的**代码身份**仍为 0，本片**不**用合成样本抬高它
（R1）。**维持 0 是正确结果。**

### 本片不做的事

- 不做源码差异比较（B2-B）；不做 11 值 prior_status 生产解析（B2-C）；
- 不开放生产注册与多轮写入（S2-C）；
- 不恢复 D-014 / I4 的三位语义；
- 不把 attestation 或 seal 当作任何 finding 的确认权威。






