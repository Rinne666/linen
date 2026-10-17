# Skill-Driven Audit Mode（CF skill 定方法，linen 做底盘）

状态：设计冻结（2026-10-17）。先并行新增一种运行模式跑对照，不替换 run 4 流程。

## 上游与版本

- vendored 副本：`.linen-runtime/cf-security-audit-skill/` @ `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`（见其 `PROVENANCE`，不入 git）。
- 适配产物（入 git）：`linen/src/linen/dispatcher/prompts/skill_audit/`。每个文件头部标注改编自哪个上游文件。

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
