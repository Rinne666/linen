# Scope 审计流水线（黑板兼容）

## 不变量

审计能力复用 linen 黑板，不增加候选表、私有任务队列或 Agent 间消息：

- `Fact / Intent / Review` 是唯一可调度、可恢复的状态；
- 大结果写入项目工作目录的不可变 JSON/SARIF artifact，Fact 记录路径与 SHA-256；
- Dispatcher 是唯一协议写入者；Worker 只读 prompt/源码并返回结构化结果；
- `Intent.type` 表示本次工作模式，不绑定名为“审计员/验证员/报告员”的固定 Worker；
- `audit_mode=none` 不经过下述门禁，通用黑板行为保持不变。

即使同一个 Dispatcher 的 `audit.enabled=true`，项目级 `audit_mode=none` 的 bootstrap
仍走原有 Fact/complete 语义，不会被降级成 recon。

## 图上流程

```text
origin
  └─ policy-evidence → review
       └─ scope-adjudication → review
            └─ coverage-plan → review
                 ├─ coverage cells ──────────────→ per-module summaries ┐
                 ├─ each managed scanner → scan_batch → triage → verify ├─ audit_summary → review → complete
                 └─ Spring routes → route_scan → triage → verifies ────┘
```

1. 启用 `audit.scope_adjudication` 时，Dispatcher 先冻结仓库政策文档、显式配置的 VRP URL
   和可选 GitHub Security Advisory 响应；缺失、抓取失败和截断全部写成 gap。
2. Explore worker 在独立对话中只对冻结材料做范围裁决。输出的每个信任边界和预排除项
   必须引用原文；excluded/conditional/unknown 必须给出复活条件。本地代码逐行校验引用。
3. 两个门禁 Fact 都经过 attestation Review 后，覆盖计划才冻结唯一源码快照，记录所有
   包含文件、排除和跳过项。
4. 计划经有效 Review 后，Dispatcher 从相同快照派生覆盖、所有启用的受管扫描器和 Spring 路由任务。
5. `scan_batch`/`route_scan` 只声明“未验证候选”，不能直接作为漏洞或安全结论。
6. 候选按稳定 fingerprint 分批形成 `triage` Intent。每条必须显式标为
   `keep`、`drop` 或 `duplicate`，不能静默截断。
7. 每个 `keep` 候选形成一个独立 `verify:<category>` Intent；输出只能是确认的
   `vulnerability`，或带 `refuted/blocked` disposition 的 `candidate_disposition`。
8. 已复核覆盖结果按模块 fan-in，扫描结果按 scanner fan-in；普通源码追踪产生的已复核
   活跃事实也必须直接 fan-in，最终才能构造 `audit_summary`。零漏洞是合法结果，但只表示
   配置检查在冻结快照上完成。API 只接受一个已复核 `audit_summary`，且拒绝遗漏活跃事实的链。
9. 不同 Fact 使用不同复核契约：漏洞走反证/冷验证/矛盾推理，政策门禁、扫描与 triage 记录走
   `attestation_check`，模块和最终汇总走 `summary_check`；所选 profile 的诊断字段由代码强校验。
10. 首次 Review 若为 `NEEDS_REVIEW` 或 tentative VALID，图上只允许再派生一次不同模式复核；
   后到的 firm/certain VALID 可消解不确定性，任一 INVALID 仍立即落为 false positive。

每个受管步骤都由 `analysis/audit_graph.py` 从当前图重算。已存在的 open/closed Intent
和 Fact 是去重依据；Dispatcher 重启后无需恢复额外内存状态。

Dispatcher 同时维护一个确定性的阶段投影（`analysis/stages.py`）。阶段 id、顺序和
required 标志由已持久化的 audit profile 派生，状态只来自 Intent 生命周期和不可变
artifact manifest：`pending`/`running`/`satisfied`/`failed`/`not_applicable`。阶段投影
不是任务队列；重启或重复调度只 PUT 实际发生变化的行，因此不会因轮询制造新的工作或
无限推进图版本。

受管扫描器的能力来自 `dispatcher/skills/SKILL.md` 与同目录的可信 registry。Semgrep、
SpotBugs + FindSecBugs、OSV-Scanner、Gitleaks 和 Trivy 都必须使用注册的 skill id、版本
和 capability。阶段集合、可用性、重试预算和输入锚点由代码确定；AuditGraph LLM 每轮只可
从待执行清单选择一个 skill id 并说明排序理由，不能自造命令或跳过必需阶段。扫描结束后
Dispatcher 读取 manifest、限制 artifact 位于项目分析目录，
计算并再次校验 SHA-256，再提交 `skill_run` receipt；Worker/LLM 的文字不能创建或完成
receipt。Receipt 失败时 scan Fact 仍保留供诊断，但该阶段不会获得可信的执行证明。

可选的 `audit.graph_reason` 是现有 Reason worker 的执行 profile，不新增 Advisor 或
协议角色。确定性派生器没有待建边后，它针对当前 `graph_revision` 冷启动一个独立对话，
只允许返回 `search/trace/verify/validate/reach/characterize/review` 语义 Intent，或从当前
待执行可信清单中选择一个 Skill。
Dispatcher 会校验 revision、Fact 引用、生命周期、重复项、数量及保留描述，再通过原有
协议写入。模型不能 complete，失败或 stale 输出不改变黑板，并按 revision 限制重试次数。

可选的 `audit.semantic` 同样不新增 Worker 角色。Dispatcher 从单一
`prompts/vuln_audit/audit_recipes.yaml` 注册表中按黑板阶段选取一个配方，使用现有
Explore worker 启动独立对话。Worker 只收到公共只读/证据约束、当前配方与冻结输入；
产出经过 schema、引用行和 snapshot hash 校验后才形成 draft Fact，并继续经过现有
Review。语义映射、假设批次、逐候选验证、确认漏洞后的变体搜索最终汇入经 Review 的
`semantic_summary`；启用时它是 scope 完成门禁的一部分。

`audit_mode=hypothesis` 不建立 coverage DAG。代码确定所有已启用扫描器仍是必需阶段，
AuditGraph LLM 从可信 registry 决定下一项执行顺序；Dispatcher 再用固定保留描述从
`origin` 建立 Intent。扫描完成后仍由 Reason 选择候选并建立假设验证链，hypothesis 的
漏洞完成语义保持不变。

服务端 `Completion Gate` 是最终裁决者：所有 open Intent、未解决执行错误、必需阶段、
受管 Skill receipt、候选的独立 Review 与终态证据链都必须通过。项目生命周期仍可为
`active`，同时派生运行态为 `idle_attention_required`；当 Gate ready 时 Dispatcher 使用
已复核终态 Fact 原子提交 complete，并生成不可变最终报告快照。

## Bootstrap 与审计

纯 scope 审计推荐项目设置 `bootstrap_enabled=false`，且审计 Worker 不声明
`bootstrap`。若确实需要一次预勘察，必须同时启用 `audit.recon.enabled=true`：其结果
会降级为 `type=recon`，只能帮助排优先级，不能进入漏洞证明链或完成门禁。因此
bootstrap 与审计并非技术上不兼容，但 bootstrap 不能充当全面扫描。
Bootstrap 主阶段在未完成目标时可以只写一个进展 Fact，结束保留 Intent 后转交正常
Reason/Explore；只有返回 `fact + complete` 且服务端完成门禁通过时才会结束项目。

## Prompt 与源码信任边界

- Scope 项目使用独立 `reason_scope.md`，不再同时加载 hypothesis 完成语义；Reason 只补
  确定性 `audit_graph` 无法推导的语义验证边。
- Reason 同时使用 taint/data-flow 和 security-invariant 两套模型，后者覆盖授权、租户隔离、
  状态机、竞态、加密策略、危险默认值和业务逻辑。
- 目标仓库中的说明文件、注释、fixture 和 prompt-shaped 文本一律视为不可信数据。
  普通审计任务只读源码，不运行目标构建、测试、安装器或 hook；仅显式 `poc:isolated`
  可在声明的 sandbox 中执行有界复现。
- 新版 coverage `needs_followup` 必须给出结构化 `file/line/summary/next_step`，使后续
  Intent 能直接消费线索，而不是重新猜测一段自由文本。

## 配置要点

- `audit.scope_adjudication.enabled=true` 仅支持 scope + `vuln_audit`。本地路径必须是仓库内
  相对 glob；远端来源必须是无凭据 HTTPS URL，重定向和大小有界，并拒绝非公网地址。
  `github_advisories=true` 会从 GitHub origin 推导仓库 API；无法推导或访问时保留 gap。
- 范围裁决只表达项目/VRP 政策资格。即使某 bug 类被预排除，后续技术验证仍可记录其
  可达性；不得借此写 `false_positive`。复活条件用于在新部署、跨用户影响或信任边界变化时
  重新纳入范围。

- `audit.semgrep.enabled=true` 时必须提供本地规则文件；失败 manifest 经有效 Review 后最多
  重试 `max_attempts` 次，失败/partial 不能被解释为零发现或被悄悄跨过。
- `audit.spotbugs`、`audit.osv`、`audit.gitleaks`、`audit.trivy` 与 Semgrep 使用相同的
  `scan_batch → triage → verify → summary` 合约；每个 scanner 身份分别完成和门禁。
- SpotBugs 必须提供 FindSecBugs plugin jar 和已有的字节码目录。Dispatcher 不执行目标仓库的
  Maven/Gradle 构建脚本；Gitleaks 当前只扫描冻结工作树，不把 Git 历史混入 scope 快照。
- `audit.spring.enabled=true` 提取字面量 Spring MVC 路由和 MVC interceptor 模式；
  filter、代理、生成路由仍标记为待验证边界。
- `audit.triage.enabled` 在 scope scanner 开启时不可关闭。
- `audit.graph_reason.enabled` 默认关闭；开启后复用 `reason` worker 和 Reason 锁，
  `max_attempts_per_revision` 限制同一图版本的失败重试。
- `coverage_plan` 是范围执行记录，必须使用 artifact attestation 审验哈希、快照、
  cell 划分和排除项，不得使用漏洞审查语义。历史上不含 `attestation_check` 的
  Review 保留为审计记录，但不参与 plan 状态聚合；Dispatcher 会派生一次新的 attestation。
- `runtime.max_project_workers` 控制图分支的真实并行度；派生器单轮最多创建 8 条边。
- `audit.poc_sandbox` 默认关闭。开启前需准备可信的本地镜像及最小凭据 allowlist。

## 三次稳定性基准

同一 commit 创建三个独立 scope 项目，人工把每次确认结果映射为：

```json
{"confirmed": ["q2-001", "q2-003"]}
```

随后运行：

```bash
uv run --project linen linen audit-benchmark \
  --expected benchmarks/spring-ai-alibaba-piolium-reference.yaml \
  --run run-1.json --run run-2.json --run run-3.json \
  --min-recall 0.8 --min-stability 0.75
```

报告包含每轮 recall/precision、遗漏/额外项、三轮交并集、两两 Jaccard 和最低 recall。
仓库内 Piolium 参考集来自指定 commit 的本地审计结果，是比较基线而非自动真值；
静态-only 条目在作为发布门禁前仍需人工裁决。
