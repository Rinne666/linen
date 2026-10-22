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




