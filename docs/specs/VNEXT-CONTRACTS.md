# Linen vNext Contract Layer

本文是 Phase 1 公共契约的精简说明。契约实现位于 `linen/src/linen/contracts/`；所有模型默认深度冻结嵌套集合并拒绝未知字段，规范化 JSON 与摘要用于幂等和重放。

## 七类公共契约

- `BlackboardSnapshot`：项目图的只读投影，包含版本、`graph_revision`、`source_generation`、`plan_revision`、Node/Edge envelope 和稳定 `snapshot_id`。`created_at` 不参与身份摘要。
- `AuditEventEnvelope`：现有 `audit_events` 的统一追加事件 envelope，携带项目/运行/实体、图版本、payload 和可选幂等键。
- `ArtifactMetadata`：工作区证据索引；路径必须是 workspace-relative，保存 kind、SHA-256、媒体类型、producer run 和相关节点。内容读取必须做路径逃逸与哈希校验。
- `RunEnvelope`：一次 Worker 尝试的生命周期和身份，包含 `run_id`、task/stage、`attempt`、幂等键、版本、状态、Manifest/Context 引用及 Artifact 引用。
- `WorkerManifest`：Dispatcher 发给 Worker 的不可变运行清单，固定 recipe、组件引用、能力、工具和权限，并产生 canonical digest。
- `ComponentManifest`：Skill、Plugin、MCP、Tool、Prompt 或 Policy pack 的版本化能力/权限/风险描述。
- `ContextProjection`：按 Intent、阶段和权限生成的最小上下文投影，引用快照、图版本、节点/边/Artifact 集合，并带可验证 `projection_digest`。

`ContextRequest` 是 `ContextProjection` 的配套请求模型，不是第八类运行时状态：Worker 只能通过显式的 `context_required` envelope 请求有限的节点、关系或 Artifact。

## Truth、trace 与 API

SQLite Blackboard（Project、Fact、Intent、Review、Coverage 等）仍是当前状态的唯一事实源；不通过事件重建状态。`audit_events` 是 append-only trace，记录状态变化、调度决定和错误，不取代事实表。Artifact 原始内容继续放在工作区，数据库保存 metadata 索引。

当前 vNext HTTP endpoints：

- `GET /projects/{project_id}/snapshot`
- `POST /projects/{project_id}/events`
- `GET|POST /projects/{project_id}/artifacts`、`GET /projects/{project_id}/artifacts/{artifact_id}` 及 `/content`
- `GET|POST /projects/{project_id}/runs`、`GET /projects/{project_id}/runs/{run_id}`、`PUT .../runs/{run_id}`、`POST .../runs/recover`
- `GET|POST /projects/{project_id}/context-projections`、`GET .../context-projections/{projection_id}`

Dispatcher 是 Worker 写黑板的唯一入口；API 层负责契约、版本、状态转换和幂等校验。

## Context 生命周期

Reason、AuditGraph Reason 和普通 Explore 支持一次受控的 `context_required`：Dispatcher 校验请求，生成新的 `ContextProjection`，再以独立 Run 重试；Worker 不直接遍历完整 Blackboard，也不依赖旧会话。Review 与 Bootstrap 当前明确拒绝合法 `context_required`，记录错误、释放 lease 并清理可用 sandbox，返回 `failed`；不会进入 conclude fallback、写 Review/Fact 或重用会话。畸形 envelope 仍按各任务既有的 invalid-output 路径处理。

## Runs、恢复与完整性

相同逻辑尝试重建相同的 run identity 和幂等键；只有新尝试递增 `attempt`。普通 Worker 执行失败最多自动重试一次，第二次由服务端语义进入 `blocked`；配额/429 的特殊退避仍可保留。Dispatcher 启动恢复超时失联的 running Run：有 Intent 的记录 transient orphan interruption 后重新入队，无 Intent 的 Reason/AuditGraph 恢复 checkpoint；恢复调用在成功后才幂等标记完成，异常可于后续 tick 重试。

Artifact 只接受 workspace-relative 路径，拒绝绝对路径、`..`、控制字符和 Windows 风格 traversal；读取时拒绝 symlink 逃逸并复核 SHA-256/大小。Run 必须引用同项目的 ContextProjection；ContextProjection 必须匹配其 Snapshot 的图版本及节点/边集合。Runs、Artifacts、ContextProjection 和审计事件的创建支持安全幂等重放。

## UI Runs

前端保持三级信息架构：项目阶段 → 黑板节点/关系 → 单次运行详情。Runs 页面/详情展示状态、attempt、run identity、ContextProjection、WorkerManifest、Policy/能力信息、命令和日志引用；完整 stdout/stderr 与大体积证据留在 Run/Artifact，而非黑板摘要。

## Phase 2 边界

Phase 2 已冻结 Sandbox contract（`SandboxProfile`、Filesystem/Network/Credential/Process policy、`ExecutionRequest`），并加入 Policy Gate 与后端能力声明。显式策略执行在创建进程前校验 Run、Manifest、Profile 摘要和后端能力；拒绝时 Run 进入 `blocked`，保留 execution Artifact 并追加 `execution_policy_denied` 事件，不允许回退宿主进程。无显式策略的兼容执行标记为 `legacy-unverified`。

`LocalBackend` 仍是宿主进程执行，不能称为安全隔离；当前实现尚未完成可承载模型 Worker 的通用 `SandboxBackend`，也尚未实现严格的 control-channel 与 tool-network 分离。不得将现有本地执行或 Review sandbox 的局部能力误称为 vNext 安全运行时完成。

当前另有一个尚未接入 scheduler 的 `DockerSandboxBackend`，用于验证离线工具执行边界。它只接受 `control_channel=deny` 且 `tool_channel=deny` 的 Profile，使用已经存在的本地镜像 ID（`pull=never`）、只读根文件系统、非 root 用户、`network=none`、capability drop、资源限制、只读 repo 和受限工作区；未授权宿主环境变量不会透传。需要模型控制通道的 Worker 会被该后端明确拒绝，直到独立 Host Runtime Adapter/Tool Broker 能证明通道分离。
