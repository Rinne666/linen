# Linen vNext 架构演进路线

# 0. vNext 基线裁决

本节是 vNext 的实施与验收基线。若后续探索性章节与本节冲突，以本节为准。

### 0.1 产品边界

Linen 继续定位为：

> Blackboard Execution Kernel

当前产品边界保持为单用户本地工具：用户可以选择任意有权访问的本机 Git 目录。多租户、组织权限、远程 Worker 和分布式高可用均不属于 vNext 首版。

vNext 首版只交付：

```text
统一运行契约
Context Projector
通用 SandboxBackend
内置 Capability Registry
最小 Policy Gate
```

首版不交付社区 Skill、MCP、长期记忆、Graphiti、Capability Hub、Bundle、Agent Profile 和自适应路由。这些能力必须建立在内核契约、安全隔离与可追溯执行稳定之后。

### 0.2 状态与写入边界

```text
Blackboard Database = 当前状态的唯一事实源
Event Store         = append-only 审计轨迹
Artifact Store      = 大体积原始证据
```

- 不采用完整事件溯源，不通过 Event 重建项目状态。
- 沿用并泛化现有 `audit_events`，不并行创建语义重复的第二套事件系统。
- Dispatcher 是 Worker 写入黑板的唯一入口。
- Worker 和 AuditGraph LLM 只能返回结构化变更提案；Dispatcher 完成 schema、引用、状态机、权限和幂等校验后才能落库。
- 每次写入使用 `run_id` 与结果幂等键，避免重试和恢复造成重复节点或边。

### 0.3 确定性控制面

统一调度顺序：

```text
任务需求
   ↓
候选 Capability / Provider
   ↓
Policy + Trust Gate
   ↓
不可变 WorkerManifest
   ↓
Worker 执行
   ↓
结构化校验与写回
```

严格区分：

```text
Capability = 任务需要什么能力
Permission = 本次运行允许哪些副作用
Tool       = 实际由哪个程序执行
```

Dispatcher 决定阶段、完成条件和候选执行范围；LLM 可在 `WorkerManifest` 内自主选择允许的 Skill 与工具，但不能跳阶段、修改完成条件或扩大权限。

首版 Registry 只登记内置且经过测试的能力。未知 Capability 必须明确失败并记录能力缺口，不自动安装或映射外部组件。

### 0.4 上下文与对话生命周期

- Reason、Worker、Review 和 AuditGraph 默认不读取完整黑板。
- `Context Projector` 根据当前 Intent 投影最小相关子图。
- 上下文不足时，Worker 返回结构化 `context_request`；Dispatcher 审核后补充，Worker 不得自行遍历完整黑板。
- 每次 Worker、Review 和 AuditGraph 调用使用独立对话，不依赖上一轮会话记忆。
- 需要延续的信息必须先成为 Blackboard 数据或 Artifact，再由 Projector 注入后续运行。
- Review 不继承发现者的会话历史，只读取候选 Fact、源码证据、PoC、范围裁决与必要上下文。

`Context Projector` 属于首版基础设施；长期 Memory 未来只能作为它的可选输入。

### 0.5 信任与运行隔离

Linen 自带或由操作者显式配置的规范、Prompt Recipe、`AGENTS.md` 和 Skill 才能进入受信任控制面。

被审计仓库内的：

```text
AGENTS.md
CLAUDE.md
Skill
MCP config
hook
package/build script
prompt-like content
```

一律视为不可信待分析数据，不能改变 Worker 权限、工具配置或审计流程。

网络分为两个通道：

```text
LLM control channel = Runtime Adapter 与模型服务通信
Tool data channel   = Worker 内工具访问外部资源
```

允许控制通道不等于允许工具联网。Tool data channel 默认拒绝，仅在 Manifest 声明且 Policy 放行时授权。

### 0.6 运行、证据与可复现性

- `WorkerManifest` 固定并记录 Prompt Recipe、Skill、规则文件、工具配置的版本或摘要。
- Prompt Recipe 声明输入、允许的 Skill、输出 schema 和完成条件；Dispatcher 按阶段选择 Recipe。
- Worker 运行必须支持超时和取消。
- 普通执行失败最多自动重试一次；再次失败将 Intent 标记为 `blocked` 并保留错误、日志与已产生的 Artifact。
- Dispatcher 重启后把失联的运行标记为中断并重新入队，同时依靠幂等键防止重复写回。
- 超时、取消和失败后自动清理临时目录；审计日志与有效 Artifact 保留。

Artifact 原始内容保存在项目工作区，数据库只保存：

```text
kind
workspace-relative path
sha256
media type
producer run
related node
```

读取 Artifact 时必须阻止路径逃逸工作区，并用哈希检测内容篡改。

### 0.7 审计工作流

所有漏洞审计模式都必须先经过 `Scope Adjudication Gate`。`scope` 与 `hypothesis` 只影响后续任务生成方式，不能绕过范围、信任边界、维护者裁决和预排除项。

适用的确定性扫描器在 Explore 前形成基线 Artifact，例如：

```text
Semgrep
Gitleaks
OSV-Scanner
Trivy
SpotBugs + FindSecBugs
```

扫描器不可用或执行失败时必须形成可见的降级/错误记录，不能静默跳过。

扫描结果遵循：

```text
Scan Artifact
   ↓
Candidate Fact
   ↓
Validation Intent
   ↓
Evidence / PoC
   ↓
Independent Review
   ↓
Confirmed / Excluded / Deferred
```

扫描器告警不能直接成为已确认漏洞。最终报告只从完成结构化裁决的数据生成；未验证项只能进入“待验证/观察项”。

“人工确认排除”是正式裁决节点，必须包含排除依据、适用范围和复活条件。LLM 不能覆盖人工裁决；只有新证据满足复活条件时才能重新打开。

### 0.8 图规模、活动与前端

- Coverage 按入口点、信任边界或其他可审计边界建立有限单元，不创建“文件 × 漏洞类型”笛卡尔积。
- 详细文件覆盖保存在 Artifact，只有异常、阶段性结论和裁决进入黑板。
- Activities 只记录关键状态变化、调度决定和错误。
- 完整命令、stdout/stderr 和 Pi 返回内容归入 Run/Artifact。
- 前端只保留三级信息架构：`项目阶段 → 黑板节点/关系 → 单次运行详情`。
- Capability、Policy、Manifest、命令与日志放入运行详情，不新增彼此割裂的顶级页面。
- 协议使用固定节点和边类型；UI 可以提供中文标签与颜色映射，LLM 不能动态创建新类型。

### 0.9 完成条件与兼容性

项目只有同时满足以下条件才能自动完成：

```text
所有必需阶段结束
所有 Coverage 单元具有终态
不存在进行中或可运行 Intent
候选漏洞已验证、排除或明确延期
必需 Review 已完成
最终报告已生成
```

否则项目保持 `active`，并显示具体阻塞原因。

数据库升级必须使用向前迁移，保留现有 Project、Intent、Fact、Review、Coverage、Activity 与运行记录；不得要求用户删除数据库或重新创建项目。

### 0.10 实施阶段

```text
Phase 0  冻结 Kernel 不变量
Phase 1  统一契约 + Context Projector + 可观测性
Phase 2  通用 SandboxBackend（控制通道与工具网络隔离）
Phase 3  内置 Capability Registry
Phase 4  最小 Policy Gate 与不可变 WorkerManifest
Phase 5  社区 Skill / MCP（版本固定、摘要、审核）
Phase 6  SQLite 长期记忆；Graphiti 仅作为可选后端评估
Phase 7  基于历史数据的自适应路由
```

首个 vNext 版本以完成 Phase 4 为发布边界。

### 0.10.1 实施状态

- Phase 0：完成，Kernel 不变量已冻结。
- Phase 1：已完成统一契约、Context Projector、受控单次上下文续跑、运行/Artifact/审计可观测性，以及服务端引用校验与幂等重放保护；全量回归通过。
- Phase 2：已完成 Sandbox contract、Policy Gate、后端能力声明、fail-closed 执行前校验，以及首个离线 DockerSandboxBackend。该后端只接受 `control=deny/tool=deny`，使用本地固定镜像、只读源码、受限可写工作区、最小环境和资源限制；尚未接入 scheduler。严格的模型 control/tool 网络分离仍未完成，`LocalBackend` 仅能作为显式 `legacy-unverified` 路径。

---

# 1. 背景

Linen 当前已经具备一个较完整的 Blackboard Agent Runtime 基础：

- Blackboard：`Fact / Intent / Hint / Review`
- 显式 `GraphEdge`
- Dispatcher 驱动的短生命周期 Worker
- Claude Code / Codex / Pi Runtime Adapter
- Intent claim / lease / heartbeat / retry
- 多 Worker 并发调度
- Security Audit 垂直工作流
- Managed Scanner / Skill Receipt
- Evidence / Review / Completion Gate
- Audit Event
- Execution Artifact
- Source Generation / Plan Revision / Graph Revision

Linen 当前最有价值的设计不是“多 Agent 角色”，而是：

```text
Blackboard
    +
Deterministic Dispatcher
    +
Ephemeral Workers
    +
Evidence-driven Validation
```

Worker 本身不拥有系统状态，系统状态存在 Blackboard 中。

因此下一阶段不建议推翻 Linen 重做 Agent Framework，而应将 Linen 保持为：

> Blackboard Execution Kernel

并在它之上逐层增加：

```text
Capability Plane
Policy Plane
Memory Plane
Secure Runtime Plane
```

最终形成：

```text
                 Linen Platform

        ┌────────────────────────┐
        │   Capability Plane     │
        ├────────────────────────┤
        │      Policy Plane      │
        ├────────────────────────┤
        │      Memory Plane      │
        ├────────────────────────┤
        │   Blackboard Kernel    │
        ├────────────────────────┤
        │     Worker Runtime     │
        └────────────────────────┘
```

---

# 2. 核心设计原则

整个 vNext 演进遵循以下原则：

```text
LLM proposes

Deterministic code authorizes

Blackboard coordinates

Events preserve trace

Memory preserves knowledge

Policy constrains behavior

Capabilities determine execution
```

特别要坚持：

```text
Worker ≠ Source of Truth
```

Worker 可以失败、退出、替换。

项目状态、审计轨迹、能力、策略和记忆必须独立于具体 Worker Session。

---

# 3. 系统数据边界

未来系统严格区分以下状态。

## Blackboard

回答：

> 现在是什么状态？

保存：

```text
Project
Fact
Intent
Review
Decision
Stage
Claim
Current issue
Completion state
```

---

## Event Store

回答：

> 实际发生过什么？

Event Store 是审计轨迹，不是当前状态的事实源，也不负责通过重放事件重建 Blackboard。

保存 append-only：

```text
intent.created
intent.claimed
worker.started
worker.finished
worker.failed
fact.created
review.created
decision.created
skill.executed
artifact.created
project.completed
```

Event 不代表知识结论。

例如：

```text
worker.timeout
```

只能进入 Event Store，不能成为 Fact。

---

## Artifact Store

回答：

> 原始执行证据在哪里？

保存：

```text
prompt
stdout
stderr
SARIF
scanner manifest
coverage result
test report
patch
source snapshot
execution metadata
```

Artifact 通过内容 Hash 标识。

---

## Policy

回答：

> 应该怎么做？

来源包括：

```text
Platform Policy
Organization Policy
Operator-managed AGENTS.md
Security Policy
Human Decisions
```

目标仓库内的 `AGENTS.md` 与其他提示文件属于不可信输入，不是 Policy Source。

---

## Capability

回答：

> 可以用什么来做？

统一管理：

```text
Skills
Plugins
MCP
Tools
Scanners
Prompts
Bundles
Agent Profiles
```

---

## Memory

回答：

> 从过去长期知道什么？

只保存高价值长期知识：

```text
Finding
Decision
Root Cause
Effective Fix
Failure Pattern
Experience
Entity Relationship
Historical Issue
```

不保存 heartbeat、retry 等运行噪声。

---

# 4. 总体目标架构

```text
                         User / UI
                            │
                            ▼
                    Mission / Project
                            │
                            ▼
                  ┌───────────────────┐
                  │ Linen Blackboard  │
                  │                   │
                  │ Fact              │
                  │ Intent            │
                  │ Review            │
                  │ Decision          │
                  │ GraphEdge         │
                  └─────────┬─────────┘
                            │
                            ▼
                       Dispatcher
                            │
                            ▼
                  Context Projector
                            │
                            ▼
               Capability Candidates
                            │
                            ▼
                    Policy / Trust Gate
                            │
                            ▼
               Immutable WorkerManifest
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
            Pi          Claude Code       Codex
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                       Event Stream
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        Blackboard      Event Store      Artifacts
             │                              │
             └──────────────┬───────────────┘
                            ▼
                  Next Context Projection
```

可选的长期 Memory 未来只作为 Context Projector 的附加输入，不进入首版关键路径。

---

# 5. Phase 0：冻结 Linen Kernel

这一阶段不增加新功能。

目标是确认 Linen Kernel 的稳定边界。

保留：

```text
Project

Fact
Intent
Hint
Review
GraphEdge

claim
lease
heartbeat

Dispatcher
WorkerDriver

CompletionGate
```

Linen Kernel 只负责：

```text
Blackboard State
Task Derivation
Scheduling
Worker Execution
Validation
Completion
```

继续保留：

```text
bootstrap
reason
explore
review
```

不建议改造成：

```text
Planner Agent
Coder Agent
Security Agent
Reviewer Agent
```

Worker 不应该拥有固定人格或固定组织关系。

工作应该继续由 Blackboard 当前状态动态产生。

验收标准：

```text
相同 Blackboard State
+
相同系统配置

→ 应得到相同 executable frontier
```

LLM 输出可以不同，但以下行为必须 deterministic：

```text
什么任务可执行
谁可以 claim
何时释放
何时完成
什么结果可以写 Blackboard
```

社区参考：

- Cairn：Fact / Intent / Hint、Stigmergy、OODA Worker
- MoMo：安全场景 Blackboard、并行探索、证据链、Conclude Recovery

---

# 6. Phase 1：Contract Layer

这是第一个实际开发阶段。

当前 Linen 已经有：

```text
graph_revision
source_generation
plan_revision
audit_events
report_snapshots
execution records
```

下一步需要把它们正式升级成统一协议。

新增七个核心 Contract：

```text
BlackboardSnapshot
AuditEventEnvelope
ArtifactMetadata
RunEnvelope
WorkerManifest
ComponentManifest
ContextProjection
```

推荐目录：

```text
linen/contracts/

├── snapshot.py
├── event.py
├── artifact.py
├── run.py
├── worker_manifest.py
├── component.py
└── context.py
```

---

## BlackboardSnapshot

不要让 Memory、UI、Context Projector 直接依赖 SQLite 表结构。

新增：

```json
{
  "schema_version": 1,
  "snapshot_id": "snap-001",
  "project_id": "proj-1",
  "graph_revision": 82,
  "source_generation": 2,
  "plan_revision": 4,
  "nodes": [],
  "edges": [],
  "created_at": "..."
}
```

形成：

```text
SQLite
   │
   ▼
Blackboard Repository
   │
   ▼
Snapshot Projector
   │
   ▼
BlackboardSnapshot
```

以后统一供：

```text
UI
Memory
Context Projector
Analytics
Export
```

消费。

---

## Event Contract

为当前 `audit_events` 增加统一事件 Envelope 与 Repository 接口。保留现有表及其迁移路径，不新增语义重复的 `events` 表。

例如：

```json
{
  "event_id": "evt-82",
  "project_id": "proj-1",
  "run_id": "run-19",
  "type": "worker.completed",
  "actor": "pi-worker-1",
  "entity_type": "intent",
  "entity_id": "I031",
  "graph_revision": 82,
  "payload": {},
  "created_at": "..."
}
```

原则：

```text
Event ≠ Fact
```

---

## Artifact Contract

当前 `.linen-analysis` 和 `.linen-executions` 保留。

数据库新增 Artifact Metadata：

```json
{
  "artifact_id": "art-91",
  "project_id": "proj-1",
  "kind": "sarif",
  "sha256": "...",
  "media_type": "application/sarif+json",
  "workspace_path": ".linen-analysis/run-17/results.sarif",
  "producer_run_id": "run-17",
  "related_node_ids": ["I031"]
}
```

数据库保存索引，原始大文件继续落文件系统或对象存储。`workspace_path` 必须是工作区相对路径；读取时执行路径逃逸检查并复核 SHA-256。

---

## RunEnvelope

一次 Worker 尝试必须拥有稳定运行身份和边界：

```json
{
  "schema_version": 1,
  "run_id": "run-19",
  "project_id": "proj-1",
  "intent_id": "I031",
  "stage": "validate",
  "attempt": 1,
  "idempotency_key": "proj-1:I031:validate:1",
  "context_projection_id": "ctx-19",
  "worker_manifest_digest": "sha256:...",
  "timeout_seconds": 900,
  "status": "queued"
}
```

状态变化由 Dispatcher 驱动并写入 Audit Event；Worker 不能修改 Envelope、Manifest 或重试次数。

---

## ContextProjection

`Context Projector` 在 Phase 1 建立，不等待长期 Memory。它根据当前 Intent、图邻域、阶段和权限生成最小上下文，并保留投影来源以便调试和复现。

Worker 需要额外信息时返回：

```json
{
  "status": "context_required",
  "context_request": {
    "node_ids": ["F031"],
    "relation_types": ["supports", "depends_on"],
    "reason": "Need the caller authorization evidence"
  }
}
```

请求由 Dispatcher 审核并产生新的 ContextProjection；Worker 不直接查询完整 Blackboard。

---

## Phase 1 目标

完成后：

```text
              Linen Core

                  DB
                  │
          ┌───────┴────────┐
          ▼                ▼
       Snapshot       Audit Events
          │                │
          └───────┬────────┘
                  ▼
          Context + Artifacts
```

这一阶段不要接长期 Memory。

---

# 7. Phase 2：Secure Worker Runtime

在接社区 Skill 和 MCP 之前，先解决运行隔离。

当前 Linen 的安全默认值很好：

```text
Pi:
--no-skills
--no-extensions
--no-context-files
```

但 Worker 仍然是宿主进程，并拥有 shell 能力。

安全审计环境中实际风险是：

```text
Untrusted Repository
        +
LLM
        +
Shell
        +
Host Process
```

因此新增：

```text
ExecutionBackend

├── LocalBackend
└── SandboxBackend
```

以及：

```text
SandboxProfile
```

例如：

```yaml
filesystem:
  repo: read-only
  workspace: read-write

network:
  control_channel: allow-configured-provider
  tool_channel: deny

credentials:
  allowed: []

process:
  timeout: 900
  memory_limit: ...
  cpu_limit: ...
```

安全审计默认：

```text
repo = read-only

workspace = read-write

llm control channel = configured provider only

tool network = deny

credentials = none
```

模型控制通道只供 Runtime Adapter 连接配置的模型服务，不能被 Worker 工具复用。只有 Manifest 明确声明且 Policy 放行：

```text
network.web
repo.write
test.execute
```

对应 Permission 时才授权。

实现时优先让宿主侧 Runtime Adapter 或受限代理持有模型凭据；沙箱内工具进程不直接获得模型凭据，也不能借控制通道任意访问外网。

---

## Repository Trust Boundary

继续坚持：

```text
Target Repository = Untrusted Data
```

默认不得自动加载目标仓库中的：

```text
AGENTS.md
CLAUDE.md
Skills
MCP config
hooks
package scripts
build scripts
```

目标仓库的配置只能作为数据读取。只有 Linen 自带或操作者显式配置的规范、Prompt Recipe、Skill 与 `AGENTS.md` 属于受信任控制面。

任何执行能力必须经过 Capability + Policy。

---

## 社区参考

OpenHands 可参考：

```text
Agent Server
Workspace
Sandbox Runtime
```

但不需要替换 Linen Dispatcher。

IntentFrame 可参考：

```text
Agent proposes
      ↓
Policy validates
      ↓
Executor acts
```

特别是 credential 与副作用执行权不应直接归 LLM。

---

# 8. Phase 3：Capability Control Plane

这是 Linen vNext 最关键的新增层之一。

当前 Linen 的 Skill Registry 主要管理：

```text
Semgrep
SpotBugs
OSV Scanner
Gitleaks
Trivy
```

本质已经是 Capability Registry 的雏形。

下一步先泛化这些内置且经过测试的 Provider；Bundle、Agent Profile、社区 Skill 与 MCP 延后实现。

推荐：

```text
linen/capability/

├── models.py
├── registry.py
├── resolver.py
├── bundles.py
├── profiles.py
├── trust.py
├── materializer.py
└── adapters/
```

---

## Capability

Task/Intent 不应该指定：

```text
use semgrep
```

而应该指定：

```text
requires:
    security.sast
```

例如：

```text
security.authz.review
security.taint.trace
security.sast
github.pr.read
```

这些是任务能力，不是副作用授权。权限单独表达：

```text
repo.read
repo.write
network.web
process.execute
database.postgres.read
```

工具是能力的具体 Provider。例如 `semgrep` 可以提供 `security.sast`，但仍需 `repo.read` 与 `process.execute` Permission 才能运行。

形成：

```text
Intent
   │
   └── REQUIRES
          ▼
      Capability
```

Provider：

```text
Skill   ── PROVIDES ──► Capability

MCP     ── PROVIDES ──► Capability

Scanner ── PROVIDES ──► Capability

Plugin  ── PROVIDES ──► Capability

Tool    ── PROVIDES ──► Capability
```

---

## ComponentManifest

统一描述：

```text
Skill
Plugin
MCP
Scanner
Tool
Prompt
Policy Pack
```

例如：

```json
{
  "id": "security.authorization-review",
  "kind": "skill",
  "version": "1.2.0",

  "provides": [
    "security.authz.review"
  ],

  "requires_capabilities": [],

  "required_permissions": [
    "repo.read",
    "process.execute"
  ],

  "runtime_compatibility": {
    "pi": "native",
    "claude": "native",
    "codex": "partial"
  },

  "risk": {
    "filesystem_write": false,
    "network": false,
    "shell": false
  }
}
```

---

# 9. WorkerManifest

Scheduler 不应该直接拼 Pi CLI 参数。

Capability Resolver 先输出候选 Provider，Policy / Trust Gate 过滤后由 Dispatcher 固化统一的 `WorkerManifest`：

```json
{
  "runtime": "pi",

  "intent_id": "I231",

  "recipe": {
    "id": "audit.authz.verify",
    "digest": "sha256:..."
  },

  "required_capabilities": [
    "security.authz.review"
  ],

  "skills": [
    {
      "id": "spring-authz",
      "version": "1.2.0",
      "digest": "sha256:..."
    }
  ],

  "plugins": [],

  "mcp": [],

  "tools": [
    "read",
    "grep"
  ],

  "permissions": {
    "repo.read": true,
    "repo.write": false,
    "process.execute": true,
    "network.web": false
  },

  "manifest_digest": "sha256:..."
}
```

Manifest 在调度开始后不可变。需要增加上下文、能力或权限时，Dispatcher 必须产生一个新版本并保留旧版本。

然后：

```text
WorkerManifest
      │
      ├── Pi Adapter
      ├── Claude Adapter
      └── Codex Adapter
```

Runtime-specific 参数只存在 Adapter。

---

# 10. Pi Capability Projection

当前 Linen 对 Pi 默认完全禁用 Skills/Extensions，这一点保留。

改成：

```text
deny by default
```

流程：

```text
Capability Resolver
        ↓
Policy / Trust Gate
        ↓
Approved Components
        ↓
Temporary Runtime Directory
        ↓
PI_CODING_AGENT_DIR
        ↓
Pi Worker
```

运行目录只 materialize 当前 Worker 被允许使用的：

```text
skills/
extensions/
context/
models.json
```

不得扫描用户全局：

```text
~/.pi
```

---

# 11. Agent Skills 社区兼容

不重新定义 Skill 格式。

优先兼容 Agent Skills 社区格式：

```text
skill/
├── SKILL.md
├── scripts/
├── references/
└── assets/
```

导入：

```text
Agent Skill
     ↓
Importer
     ↓
ComponentManifest
     ↓
Capability Extraction
     ↓
Risk / Trust Analysis
```

社区 Skill 默认：

```text
UNTRUSTED
```

不能直接进入 Runtime。

---

# 12. MCP 接入

MCP 作为另一种 Capability Provider。

例如：

```text
GitHub MCP
     │
     └── PROVIDES
            github.repo.read
            github.pr.read
```

未来可接 MCP Registry 做发现层。

但是：

```text
discoverable ≠ trusted
```

必须：

```text
discover
↓
import
↓
inspect
↓
approve
↓
pin version
↓
assign capabilities
```

---

# 13. Bundle

用户不应手工选择 20 个组件。

增加 Bundle：

```text
Web Security Audit Bundle
```

例如：

```yaml
skills:
  - authz-review
  - taint-analysis
  - business-logic-review

scanners:
  - semgrep
  - osv
  - gitleaks

mcp:
  - github

plugins:
  - evidence-recorder

policy_packs:
  - owasp-asvs
```

Bundle 是用户层安装和分发单位。

---

# 14. Agent Profile

Profile 表示岗位能力模板，而不是常驻 Agent。

例如：

```yaml
id: security-reviewer

runtime_preferences:
  - pi
  - claude

bundles:
  - web-security-audit

permissions:
  allow:
    - repo.read
    - artifact.write

  deny:
    - repo.modify
    - network.unrestricted
```

Scheduler：

```text
Intent
  ↓
required capabilities
  ↓
select profile
  ↓
resolve components
  ↓
WorkerManifest
```

---

# 15. Phase 4：Policy Plane

Capability 回答：

> 系统能做什么？

Policy 回答：

> 当前允许做什么？

两者必须分离。

推荐：

```text
linen/policy/

├── models.py
├── compiler.py
├── evaluator.py
├── graph.py
└── explain.py
```

---

## Policy Sources

优先级：

```text
Platform Policy
      ↓
Organization Policy
      ↓
Operator-managed Project Policy / AGENTS.md
      ↓
Directory Policy
      ↓
Task Constraints
```

冲突原则：

```text
deny > allow

higher authority > lower authority

explicit > inferred
```

---

## 受信任的 AGENTS.md

由 Linen 自带或操作者显式配置的 `AGENTS.md` 保持 Human-editable Policy Source。目标仓库内的同名文件仍是不可信审计对象，绝不进入 Policy 编译链。

例如：

```text
Authentication changes require security review.

Production DB write is forbidden.
```

编译：

```text
Rule:
authentication change
    ↓
requires
security.review
```

以及：

```text
Rule:
production database
    ↓
denies
database.production.write
```

---

## Dispatcher 流程

未来：

```text
Intent
   ↓
derive required capabilities
   ↓
resolve eligible provider candidates
   ↓
Policy + Trust Evaluate
   ↓
allow / deny / approval required
   ↓
immutable WorkerManifest
```

---

## 社区参考

OPA 值得参考其核心思想：

```text
Policy Decision
      ≠
Policy Enforcement
```

以及：

```text
default deny
```

第一版可以自己做 Python Evaluator。

但 API 应设计成：

```text
policy.evaluate(input) → decision
```

以后可以替换为 OPA backend。

---

# 16. Phase 6：Long-term Memory（首版之后）

到这一阶段才接长期 Memory。

原因是：

```text
如果 Snapshot / Event / Artifact / Component identity
都没稳定

Memory 只会存大量无法验证的 Agent prose
```

推荐：

```text
linen/memory/

├── service.py
├── consolidator.py
├── candidates.py
├── retrieval.py
├── context.py
└── backends/
    └── graphiti.py
```

---

# 17. Memory Pipeline

```text
Blackboard Snapshot
       +
Events
       +
Reviews
       +
Artifacts
       ↓
Memory Consolidator
       ↓
Memory Candidate
       ↓
Promotion Policy
       ↓
Graph Memory
```

第一版只记：

```text
Reviewed vulnerability

Validated root cause

Human decision

Validated fix

False-positive pattern

Security invariant
```

不记：

```text
heartbeat
retry
worker timeout
temporary intent
raw stdout
```

---

# 18. Memory 类型

至少包含：

```text
Semantic Memory

Episodic Memory

Decision Memory

Experience Memory
```

Security 领域扩展：

```text
Vulnerability Pattern Memory

Root Cause Memory

Fix Memory

False Positive Memory

Attack Surface Memory
```

---

# 19. Temporal Memory

历史不能覆盖。

例如：

```text
Decision v1
     │
     └── SUPERSEDED_BY
               ↓
           Decision v2
```

每个 Memory Node 最少包含：

```text
valid_from
valid_to
created_at
source
confidence
status
```

---

# 20. Memory Scope

跨项目记忆必须显式分层：

```text
project
repository
organization
global
```

例如：

```text
具体 SQLi Finding
→ project

Spring ownership bypass pattern
→ repository / organization

组织内部安全规则
→ organization
```

不同 Tenant 默认不得共享。

---

# 21. Graphiti

Graphiti 适合作为 Memory Backend。

使用它处理：

```text
Temporal relation

Typed graph

Provenance

Hybrid retrieval

Historical evolution
```

但：

```text
Graphiti ≠ Blackboard
```

不要用 Graphiti 保存：

```text
worker lock
heartbeat
current claim
current retry
```

这些仍属于 relational operational database。

---

# 22. Phase 1：Context Projector；Phase 6：Memory Enrichment

Context Projector 必须在 Phase 1 建立，解决当前完整 Graph 被塞给 Reason Worker 的问题。到 Phase 6 接入长期 Memory 后，只为既有投影器增加可选的 Memory Retrieval 输入。

统一命名为：

```text
Context Projector
```

流程：

```text
Intent
 ↓
Blackboard Snapshot
 ↓
Graph Neighborhood
 +
Policy Context
 +
Capability Context
 +
Optional Memory Retrieval
 ↓
Relevant Context Subgraph
 ↓
Worker
```

目标：

```text
20～100 个相关节点
```

而不是：

```text
整个项目几千条 Fact
```

---

## Context 示例

任务：

```text
Verify authorization on Spring controller
```

Context Builder 输出：

```text
Current:
Controller
Service
Relevant auth facts
Related reviews

Policy:
authorization changes require review

Optional Memory:
historical ownership bypass in same service

Capabilities:
spring-authz-review

Permissions:
repo.read
```

然后交给 Pi。

---

# 23. Phase 7：Adaptive Routing

等拥有稳定历史以后，再使用 Memory 改善 Worker/Skill Router。

例如长期统计：

```text
Task:
spring-authz

Pi + authz-skill:
82% success

Claude + authz-skill:
93% success

Generic:
61% success
```

Routing：

```text
eligible workers
     ↓
policy
     ↓
capability match
     ↓
historical performance
     ↓
cost / latency
     ↓
dispatch
```

关键原则：

```text
Memory can influence ranking.

Memory cannot override permission.
```

即：

```text
historically effective
```

不能绕过：

```text
Policy DENY
```

---

# 24. Phase 5：Community Capability Ecosystem

最后才做社区生态。

因为此时已经具备：

```text
Sandbox
Trust
Policy
Version Pinning
Capability Schema
Provenance
```

架构：

```text
                 Capability Hub

      ┌──────────────┼──────────────┐
      ▼              ▼              ▼
 Agent Skills      MCP          Linen-native
      │              │              │
      └──────────────┼──────────────┘
                     ▼
                  Importer
                     ▼
                  Scanner
                     ▼
               Trust Profile
                     ▼
                Capability
                     ▼
                  Bundle
```

---

# 25. Supply Chain

所有社区 Component 保存：

```text
publisher
source_repo
version
commit_hash
checksum
license
review_status
risk_level
```

Run 保存：

```text
Run
 └── USED_COMPONENT
          ↓
   skill@1.2.3
```

确保历史执行可复现。

---

# 26. 社区实现参考

## Cairn

适合参考：

```text
Fact / Intent / Hint

Blackboard

Stigmergy

OODA Worker

No fixed roles
```

不要把 Agent 组织关系做成核心。

---

## MoMo

适合参考：

```text
Security Blackboard

Parallel Explore

Evidence-driven investigation

Conclude fallback
```

适合作为安全场景参考。

---

## hivemind blackboard

适合参考：

```text
SQLite + WAL

Append-only collaboration

Shared core behind CLI/MCP

Persistent state over agent presence
```

但它本身不是完整 scheduler。

---

## OpenHands

参考：

```text
Workspace abstraction

Sandbox Runtime

Agent Server
```

不要用它替代 Linen Dispatcher。

---

## Agent Skills

参考：

```text
SKILL.md

progressive disclosure

portable skill packages
```

作为社区 Skill 导入标准。

---

## MCP Registry

参考：

```text
MCP discovery
```

但 Registry 只能解决：

```text
“有什么”
```

不能解决：

```text
“能不能用”
```

后者仍由 Linen Policy / Trust 决定。

---

## OPA

参考：

```text
Policy-as-code

Decision / Enforcement separation

default deny
```

---

## Graphiti

参考：

```text
Temporal Knowledge Graph

Provenance

Historical evolution

Hybrid retrieval
```

仅作为 Memory Backend。

---

## LangGraph

参考：

```text
checkpoint
vs
long-term store
```

即：

```text
current execution state
vs
durable memory
```

不需要把 Linen 重构成 LangGraph Workflow。

---

## Temporal

作为未来分布式阶段参考。

Temporal：

```text
Server/Event History
       ↓
Task Queue
       ↓
Workers
```

Linen：

```text
Blackboard/Event Store
       ↓
Intent
       ↓
Workers
```

理念接近。

只有 Linen 真正进入：

```text
多 Dispatcher
跨机器 Worker
高可用
长任务
```

阶段以后，再评估是否接 Temporal。

---

# 27. 推荐开发 DAG

最终开发依赖顺序：

```text
                    Linen Core
                        │
                        ▼
              Contracts / Snapshot
              /          |          \
             ▼           ▼           ▼
       Audit Events   Artifacts   Context Projector
             \           |           /
              └──────────┼───────────┘
                         ▼
                  Secure Runtime
                         │
                         ▼
                Capability Plane
                         │
                         ▼
                    Policy Plane
                         │
                         ▼
                 vNext 首版发布边界
                         │
               ┌─────────┴─────────┐
               ▼                   ▼
          Community Skills       MCP
               │                   │
               └─────────┬─────────┘
                         ▼
                    Graph Memory
                         │
                         ▼
              Context Memory Enrichment
                         │
                         ▼
                 Adaptive Scheduler
```

两个必须坚持的顺序：

```text
Sandbox
必须早于
Community Skills / MCP
```

以及：

```text
Snapshot + Events
必须早于
Graph Memory
```

---

# 28. 数据库演进

## Phase 0

现有：

```text
projects
facts
intents
reviews
graph_edges
audit_stages
skill_runs
human_decisions
audit_events
```

---

## Phase 1

增加：

```text
artifacts
snapshots
runs
context_projections
```

`audit_events` 原表向前迁移并实现统一 Event Contract，不新增重复的 `events` 表。

---

## Phase 2

增加：

```text
sandbox_profiles
runtime_permissions
```

---

## Phase 3

增加：

```text
components
capabilities
component_capabilities
run_components
```

---

## Phase 4

增加：

```text
policies
policy_decisions
policy_evaluations
```

---

## Phase 5

增加：

```text
community_components
component_approvals
component_versions
bundles
bundle_components
```

---

## Phase 6

增加：

```text
memory_ingestions
memory_candidates
memory_links
```

第一版使用 SQLite；只有确认有跨项目时序图检索需求后，才评估把长期记忆图放入可选 Graphiti Backend。

---

## Phase 7

增加：

```text
component_metrics
routing_outcomes
task_metrics
```

---

# 29. 第一个主要版本目标

第一个真正建议发布的大版本，不需要等待 Memory。

建议做到 Phase 4：

```text
            Linen vNext Core

Blackboard
    +
Snapshot / Events / Artifact
    +
Sandbox
    +
Capability Control Plane
    +
Minimal Policy Gate
```

此时系统已经可以做到：

```text
Intent
   ↓
required capabilities
   ↓
resolve built-in provider candidates
   ↓
policy/trust filtering
   ↓
construct immutable WorkerManifest
   ↓
Pi / Claude / Codex
   ↓
capture evidence
   ↓
validate
   ↓
Blackboard
```

这已经是一个完整的：

> Secure Blackboard Execution Kernel

而不仅仅是一个 Blackboard Demo。

---

# 30. 推荐实际编码顺序

如果直接从当前 Linen 仓库开始改，建议顺序：

```text
1. BlackboardSnapshot Contract

2. Event Contract

3. Artifact Contract

4. Run Model

5. WorkerManifest

6. Context Projector

7. Audit Event / Activity Observability

8. SandboxBackend

9. Built-in Component Registry

10. Capability Registry / Resolver

11. Policy Evaluator

12. Runtime Manifest Materializer

13. Trusted Operator Policy Compiler

--- vNext 首版发布边界 ---

14. Community Skill Importer / MCP Adapter

15. Bundle / Agent Profile（按需）

16. SQLite Memory Service

17. Memory Consolidator

18. Optional Graphiti Backend

19. Adaptive Routing
```

---

# 31. 最终系统职责

最终 Linen Core 只负责：

```text
State

Graph

Task derivation

Scheduling

Worker execution

Evidence

Review

Completion
```

Capability Plane 负责：

```text
“现在有什么能力可以使用？”
```

Policy Plane 负责：

```text
“当前允许使用什么？”
```

Memory Plane 负责：

```text
“过去什么方法有效？”
```

Event/Artifact 负责：

```text
“实际上发生了什么？”
```

Blackboard 负责：

```text
“现在是什么状态？”
```

最终 Agent Worker 只负责：

```text
“针对当前 Intent 做一次受约束的认知和执行。”
```

---

# 32. 最终工作模型

```text
Project
   ↓
Blackboard determines next unknown
   ↓
Intent
   ↓
Context Projector selects what is relevant
   ↓
Required capabilities select provider candidates
   ↓
Policy and trust determine what is allowed
   ↓
Immutable WorkerManifest fixes how to execute
   ↓
Worker investigates
   ↓
Evidence becomes candidate result
   ↓
Deterministic validation
   ↓
Fact
   ↓
Independent Review
   ↓
Memory learns durable knowledge
   ↓
Blackboard continues search
```

最终 Linen 不需要成为一个越来越庞大的多 Agent Framework。

它更适合成为：

> **一个以 Blackboard 为核心、以确定性控制平面约束 LLM Worker、支持能力组合、安全执行、长期记忆和领域工作流的 Agent Operating System。**
