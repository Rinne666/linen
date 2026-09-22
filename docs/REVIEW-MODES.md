# Review Modes

> Implementation update: review diagnostic objects are now persisted and included
> in project reads and YAML exports. YAML also includes fact status and intent IDs.
> Cold-verifier prompts no longer receive the graph or prior candidate evidence;
> host filesystem isolation is not provided. Sections below describing diagnostics
> as discarded or graph context as supplied describe the earlier implementation.
> See [Audit pipeline](AUDIT-PIPELINE.md) for current configuration and limitations.

---

## 本质

`review` 任务是 linen **候选发现 → 复审 → 落定** 闭环的执行者。Phase 1a 之前它只有一种行为（"找反证"），现在按候选 fact 的特征拆成 **3 种 mode**：

| Mode | 适用场景 | 推理模型 | 默认 prompt 文件 |
|------|----------|----------|------------------|
| `devils-advocate` | 简单 fact、单点链 gap、无 chain conflict | 5-layer protection search + 8 Claude FP patterns | `review.md` |
| `cold-verifier` | 长链（≥ 3 个 fact 祖先）、`type=vulnerability` 终止 fact、可能 confirmation bias | 7 步独立 re-trace protocol | `review_cold_verifier.md` |
| `contradiction-reasoner` | 已有 ≥ 1 个 `NEEDS_REVIEW`、下游 fact 是 `false_positive`、sanitizer 被挑战 | TRIZ 矛盾分析 + Game Theory 适应性攻击者 | `review_contradiction_reasoner.md` |

**3 个 mode 的 reasoning 模型根本不同**（5-layer protection table vs 7-step independent re-trace protocol vs TRIZ+Game Theory），不是同一 prompt 的措辞微调。每个 mode 配套自己的 prompt 文件和 mode-specific extras 字段（`protection_search` / `cold_verification` / `contradiction_analysis`），未来 report assembler 可基于这些字段做差异化呈现。

**核心设计取舍**：3 种 mode 适合不同 fact 复杂度（简单 vs 长链 vs 冲突），硬塞进一个 prompt 会让 worker 不知道哪个 reasoning model 优先；**不**按"具名 sub-agent"做（与 linen "无固定角色" 哲学对立）——mode 是 review task 内部的 dial，由 reason worker 动态选择，不是 worker 的 fixed role。

---

## 怎么用

### 1. Reason worker 自动选 mode（推荐）

Reason worker 按 fact 特征选 mode 并 emit intent（`reason.md` "Emit a review intent" 段）：

```json
// 简单 fact（默认）—— devils-advocate
{"from": ["<fact>"], "type": "review:devils-advocate", "description": "Adversarially review ..."}

// 长链 / 终止 fact / 可能 confirmation bias —— cold-verifier
{"from": ["<fact>"], "type": "review:cold-verifier", "description": "Cold-verify ..."}

// 已有 NEEDS_REVIEW 或 chain 冲突 —— contradiction-reasoner
{"from": ["<fact>"], "type": "review:contradiction-reasoner", "description": "Contradiction-check ..."}
```

如果 reason 选错 mode（不常见），可以手工纠正。

### 2. UI 按钮

linen 静态 UI 已有 "Run review" 按钮（`linen/src/linen/server/static/index.html:1703-1733`），会 POST 一个 `type: "review"` intent。**Phase 1a 之后它仍然能用**——`type: "review"`（无 suffix）会回退到 `tasks.review.mode` 配置的默认 mode（默认 `devils-advocate`）。

### 3. API 直接 POST

```bash
curl -X POST http://127.0.0.1:9000/projects/<pid>/intents \
  -H 'Content-Type: application/json' \
  -d '{
    "from": ["f001"],
    "type": "review:cold-verifier",
    "description": "Manual cold verification of f001",
    "creator": "human"
  }'
```

返回 `201` + `Intent`。调度器下一个 tick 会路由到 `_dispatch_review`，加载 `review_cold_verifier.md` prompt，worker 跑完后写 `client.create_review(...)`。

---

## 三个 mode 各自做什么

### `devils-advocate`（默认）

**目标**：对候选 fact 穷尽 5-layer protection search + 显式做 8 个 Claude FP pattern check，**对每个 layer 给 YES/NO/PARTIAL/N/A 评级 + 引用 file:line**。

**5-layer protection search 表**（prompt `review.md`）：

| Layer | 查什么 |
|-------|--------|
| **Language** | 类型系统、内存安全、bounds check、null safety |
| **Framework** | ORM 参数化、模板自动转义、CSRF middleware、validation decorator |
| **Middleware** | WAF、反向代理、auth 强制、request signing |
| **Application** | allowlist、ownership check、role verify、input length limit |
| **Documentation** | `SECURITY.md` / `CHANGELOG` / inline comment 里**显式接受的风险** |

**8 个 Claude FP patterns**（prompt `review.md`）：

1. unsafe-looking code without path tracing
2. phantom validation bypass
3. framework protection blindness
4. same-origin confusion
5. dependency CVE without reachability
6. config-as-vulnerability
7. test / example code
8. double-counting

**Verdict 决策**：
- `VALID`：5-layer 全查完且无任何 layer 给出 blocking + 8 FP pattern 全部 not applicable
- `INVALID`：能指出**具体 file:line 或 doc 引用**证明 attack 被 block
- `NEEDS_REVIEW`：缺 config / runtime / 依赖版本信息，无法静态判定

### `cold-verifier`

**目标**：zero-context 独立 re-trace，**禁止读 chamber / debate / 其他 review**——只能读候选 fact 本身。补 audit worker 的 confirmation bias。

**7 步 protocol**（prompt `review_cold_verifier.md`）：

1. **Restate and Decompose**——用自己话重述 claim，拆成 A / B / C 三个 sub-claim
2. **Independent Code Path Trace**——从 entry point 自己 trace，不依赖 fact 里的 evidence
3. **5-Layer Protection Search**（同 devils-advocate，但 focus 在这条 path）
4. **Real-Environment Reproduction**（linen 静态推理 fallback）——按 reproduction steps 静态推理，不真跑 exploit
5. **Prosecution and Defense Briefs（Independent）**——两份 brief **互相不引用对方的 reasoning**
6. **Severity Challenge**——默认从 MEDIUM 起步，evidence-based 升级
7. **Verdict**——`CONFIRMED`（prosecution survive + static reproduction）/ `DISPROVED`（defense 找到 blocking 或 3 次 static reproduction 全 fail）/ `NEEDS_REVIEW`

**Rationalizations to Reject**（prompt 显式列出 5 条）：

1. "The audit worker already verified this" → 正是 cold verification 存在的理由
2. "I cannot reproduce but the code looks vulnerable" → 静态推理 block 必须有 file:line 证据
3. "Probably exploitable in some configuration" → 理论可利用 ≠ confirmed
4. "The severity seems right for this bug class" → severity 必须从 evidence 推导
5. "The defense brief is weaker than the prosecution" → defense 不需要 weak 就能 reject

### `contradiction-reasoner`

**目标**：TRIZ 矛盾分析 + Game Theory 适应性攻击者，**找 candidate fact 的最强反驳**。只用于 chain 有冲突（NEEDS_REVIEW / false_positive / sanitizer 被挑战）的场景。

**Reasoning Model 1: TRIZ 矛盾分析**（prompt `review_contradiction_reasoner.md`）：

- 找代码里的**张力（tension）**：compatibility / performance / convenience / completeness / async
- 识别**被牺牲的（sacrifice）**：为了 resolve tension，开发者牺牲了什么安全属性
- 评估 sacrificed 是不是可被利用

**Reasoning Model 2: Game Theory 适应性攻击者**：

- 找**交互机制（interactive mechanism）**：response_diff / rate_limit / state_accum / cross_user / timing_oracle
- 模型 adaptive attacker 的最优策略
- 评估 attack 是不是受 mechanism 制约

**Verdict 决策**：

- `INVALID`：TRIZ 找到 developer 正确 resolve 了 tension（或 sacrifice 不可被 candidate claim 的方式利用）**或** Game Theory 找到 adaptive attacker 不能真正 mount exploit
- `VALID`：TRIZ 找到 real sacrifice 且无补偿 control **且** Game Theory 找到 naive attacker 仍能成功
- `NEEDS_REVIEW`：两个 model 信号冲突（TRIZ 觉得 VALID，Game Theory 觉得 INVALID）**或** 无法判定 sacrificed 是否可被利用

---

## Mode 编码方式

`Intent.type` 字段（自由文本，server schema 没限制）：

| 值 | 含义 |
|---|---|
| `"review"` | 默认 mode（`tasks.review.mode` 配置的回退值，默认 `devils-advocate`） |
| `"review:devils-advocate"` | 显式 devils-advocate |
| `"review:cold-verifier"` | 显式 cold-verifier |
| `"review:contradiction-reasoner"` | 显式 contradiction-reasoner |
| `"review:<unknown>"` | **回退到默认 mode** + log warning（不 crash） |
| `""` / `null` | **回退到默认 mode**（legacy 兼容） |

**设计选择**：用 `:` 分隔的命名空间而不是新加 schema 字段（`review_mode: str | None`），因为：

1. `Intent.type` 已经是 freeform，加字符串不破坏 server schema
2. 调度器 `loop.py:317-321` 路由 trigger 只看字符串前缀（`i.type == "review" or i.type.startswith("review:")`），不引入新概念
3. Reason worker 已经会 emit 任意 type（`reason.py:228-237` 透传 `intent_type=intent_data.get("type")`），不需要 client 改

---

## 调度器路由

`linen/src/linen/dispatcher/scheduler/loop.py:317-321`：

```python
review_intents = [
    i for i in unclaimed_intents
    if (i.type or "").strip() == "review"
    or (i.type or "").strip().startswith("review:")
]
```

任何 `intent.type` 等于 `"review"` 或以 `"review:"` 开头，都路由到 `_dispatch_review`（`loop.py:553-611`）。`review_intents` 按 `created_at` 取最新，调用 `run_review_task`。

**Phase 1a 同步修了一个 scheduler bug**（`loop.py:295-303`）：`unclaimed_intents` filter 之前只查 `intent.to is None`，但 review task 写 review 时 server 端只更新 `intents.concluded_at`（`routers/reviews.py:90-108`），**没更新 `to_fact_id`**。所以 review 任务 conclude 的 intent 仍被 filter 选中，反复 dispatch。**Fix**：filter 同时检查 `intent.concluded_at is None`。

**Live 验证 fix 生效**：修复前 i008 / i009 被反复 dispatch（9 个 review rows 全部 share 同一 intent_id），修复后每个 review intent 只 dispatch 一次（i010 → i011 → i012 严格按 created_at 顺序）。

---

## Review task 实现

`linen/src/linen/dispatcher/tasks/review.py` 三个关键函数：

```python
REVIEW_MODES: frozenset[str] = frozenset(
    {"devils-advocate", "cold-verifier", "contradiction-reasoner"}
)
REVIEW_TYPE_PREFIX = "review"

def resolve_review_mode(intent: Intent, default: str = "devils-advocate") -> str:
    """解析 intent.type -> mode。

    "review" 或 None           -> default（来自 config 或兜底 devils-advocate）
    "review:devils-advocate"  -> "devils-advocate"
    "review:cold-verifier"    -> "cold-verifier"
    "review:contradiction-reasoner" -> "contradiction-reasoner"
    "review:<unknown>"         -> default + log warning
    """

def review_prompt_filename(mode: str) -> str:
    """mode -> prompt 文件名。

    "devils-advocate"        -> "review.md"（历史兼容，无后缀）
    "cold-verifier"          -> "review_cold_verifier.md"
    "contradiction-reasoner" -> "review_contradiction_reasoner.md"

    mode 字符串中的连字符被规范化为下划线（Python identifier 约定）。
    """
```

**Prompt 加载**（`review.py:104-145`）：

```python
default_mode = (
    config.tasks.review.mode
    if config.tasks.review is not None
    and getattr(config.tasks.review, "mode", None) in REVIEW_MODES
    else "devils-advocate"
)
mode = resolve_review_mode(intent, default=default_mode)
prompt_name = review_prompt_filename(mode)
LOG.info("review mode resolved ... mode=%s prompt=%s", mode, prompt_name)

prompt = render_prompt(
    load_prompt(config.runtime.prompt_group, prompt_name),
    {"graph_yaml": ..., "intent_id": ..., "fact_block": ..., "intent_description": ...},
)
```

**Config 默认 mode**（`dispatch.yaml`）：

```yaml
tasks:
  review:
    timeout: 300
    conclude_timeout: 60
    mode: devils-advocate   # 默认；intent.type="review" 走这个
```

如果 dispatch.yaml 没写 `mode`，`ReviewTaskConfig.mode` 兜底为 `"devils-advocate"`（`config.py:ReviewTaskConfig`）。如果 mode 拼写错，config load 阶段直接 raise `ValidationError`（`Literal` 类型约束）。

---

## 输出契约

**4 个基础字段**（所有 mode 必填）：

```json
{
  "verdict": "VALID" | "INVALID" | "NEEDS_REVIEW",
  "confidence": "certain" | "firm" | "tentative",
  "summary": "1-2 sentence conclusion. State WHY and cite decisive file:line or layer.",
  "reasoning": "optional longer argument"
}
```

**6 个 profile-specific 字段**（API 兼容可选；受管 `vuln_audit` 任务按所选 profile 强制）：

| 字段 | mode | 用途 |
|------|------|------|
| `protection_search` | devils-advocate | 5-layer 评级（language / framework / middleware / application / documentation） |
| `fp_pattern_check` | devils-advocate | 8 个 Claude FP pattern 的 matched / not applicable 列表 |
| `cold_verification` | cold-verifier | sub-claims + prosecution + defense + severity_challenged + isolation_observed |
| `contradiction_analysis` | contradiction-reasoner | TRIZ tension + sacrifice + Game Theory mechanism + adaptive path |
| `attestation_check` | source inventory / triage execution record | artifact integrity + frozen-source consistency + scope completeness |
| `summary_check` | module / audit summary | expected/referenced/missing input IDs + contradiction + fan-in completeness |

**Contract 校验**（`linen/src/linen/dispatcher/contracts.py:201-260`）：

- 4 个基础字段强校验（verdict ∈ enum，summary 非空，confidence ∈ enum，reasoning 是 string 或 None）
- 6 个 diagnostics 字段**如果存在必须是 dict**；受管 profile 还强制字段存在并校验必需 keys
- extras pass-through 到 `validate_review_payload` 返回的 dict
- `client.create_review(...)` 将 diagnostics 写入 Review JSON 列，并在 API、YAML export 和 UI 中保留

漏洞、执行证明与汇总分别加载不同 prompt。缺少所需诊断结构的模型输出会失败并释放 Intent，
不会写入一个只有笼统 verdict 的 Review。

---

## 已知限制与 polish 路径

| 限制 | 当前控制 |
|------|----------|
| LLM 仍可能给出语义上空洞的诊断值 | 结构由代码强制，真实性仍由冻结源码、artifact hash、独立复核与人工裁决保证 |
| 复核可能长期争论 | 每个 Fact 最多两次自动 Review；首次不确定后只允许一个不同 mode 的 follow-up |
| Cold-verifier 无真实部署环境 | 普通审计禁止执行目标应用；需要动态证明时只能派生显式 `poc:isolated` |
| 自动 mode 选择不理解所有业务语义 | `audit_graph` 确定性处理生命周期，Reason 只补非保留的语义验证边 |

---

## 怎么扩展（加新 mode）

**3 步**：

1. **写 prompt 文件** `linen/src/linen/dispatcher/prompts/vuln_audit/review_<new_mode>.md`，必须包含 4 个占位符：`{graph_yaml} {intent_id} {fact_block} {intent_description}`

2. **注册 mode** `linen/src/linen/dispatcher/tasks/review.py:REVIEW_MODES`：

   ```python
   REVIEW_MODES: frozenset[str] = frozenset({
       "devils-advocate", "cold-verifier", "contradiction-reasoner",
       "<new_mode>",  # <- 加这里
   })
   ```

3. **加 mode 字面值** `linen/src/linen/dispatcher/config.py:ReviewTaskConfig.mode`：

   ```python
   mode: Literal["devils-advocate", "cold-verifier", "contradiction-reasoner", "<new_mode>"] = "devils-advocate"
   ```

**然后**（如果 extras 是 mode-specific 诊断字段）：

4. **扩展 `validate_review_payload`** `linen/src/linen/dispatcher/contracts.py`：在 `extras` 校验 list 里加新字段名

5. **更新 `review_prompt_filename`** —— 如果新 mode 不希望走历史兼容的 `review.md` 默认文件，把 `if mode == "devils-advocate": return "review.md"` 扩到新 mode 同等

**测试**：在 `linen/tests/test_review_modes.py` 加：
- `test_resolve_review_mode_explicit_<new_mode>`
- `test_review_prompt_filename_<new_mode>`（如果文件名有变）
- 扩展 `test_review_prompts_have_mode_specific_content` 验证 prompt 包含新 mode 的特征字符串

**Prompt token 校验** `linen/src/linen/dispatcher/config.py:DEFAULT_PROMPT_REQUIRED_TOKENS` / `PROMPT_REQUIRED_TOKENS_BY_GROUP["vuln_audit"]` 都要加新 prompt 文件的 placeholder tuple。

---

## 测试

25 个测试覆盖（`linen/tests/test_review_modes.py` + `linen/tests/test_review_loop.py`）：

| 测试 | 覆盖 |
|------|------|
| `test_resolve_review_mode_default_review_type` | `type="review"` 回退到 default |
| `test_resolve_review_mode_explicit_devils_advocate` | `"review:devils-advocate"` |
| `test_resolve_review_mode_explicit_cold_verifier` | `"review:cold-verifier"` |
| `test_resolve_review_mode_explicit_contradiction_reasoner` | `"review:contradiction-reasoner"` |
| `test_resolve_review_mode_unknown_falls_back` | `"review:nonexistent"` 不 crash |
| `test_resolve_review_mode_none_type` | `type=None`（legacy）回退到 default |
| `test_resolve_review_mode_respects_non_default_config` | config default vs per-intent override 优先级 |
| `test_review_prompt_filename_devils_advocate` | 默认 mode 走 `review.md`（历史兼容） |
| `test_review_prompt_filename_other_modes` | 其他 mode 走 `<mode>` 后缀 |
| `test_all_three_review_prompts_exist_and_have_required_placeholders` | placeholder 校验覆盖 3 个 prompt |
| `test_review_prompts_have_mode_specific_content` | 每个 prompt 包含 mode 特征字符串（5-layer / 7-step / TRIZ） |
| `test_validate_review_payload_accepts_protection_search` | devils-advocate extras pass-through |
| `test_validate_review_payload_accepts_cold_verification` | cold-verifier extras pass-through |
| `test_validate_review_payload_accepts_contradiction_analysis` | contradiction-reasoner extras pass-through |
| `test_validate_review_payload_rejects_non_dict_extras` | extras 非 dict 拒绝 |
| `test_validate_review_payload_legacy_still_works` | 无 extras 时旧 worker 仍能跑 |
| `test_scheduler_loop_routes_review_colon_intents` | loop.py 含 `startswith("review:")` 路由 |
| `test_scheduler_loop_filters_concluded_intents` | loop.py `unclaimed_intents` filter 含 `concluded_at`（scheduler fix） |
| `test_review_task_config_default_mode` | 没设 `mode` 字段时默认 `devils-advocate` |
| `test_review_task_config_rejects_unknown_mode` | 拼写错 `mode: devls-advocate` 在 config load 阶段 raise |
| `test_validate_reason_payload_preserves_intent_type` | reason 合约不丢 `type` 字段 |
| `test_run_reason_task_passes_intent_type_to_create_intent` | reason 派发透传 `intent_type` |
| `test_aggregate_fact_status_for_each_verdict` | server 端 verdict → status 重算（4 种路径 + sticky terminal） |
| `test_review_loop_e2e_create_project_intent_review` | e2e: project → intent(review) → review(VALID) → status draft→triaged |
| `test_reason_md_teaches_emit_review_intent` | reason.md 含 3 个 mode 各自的 JSON example |

跑测：

```bash
cd /path/to/linen
uv run --project linen python -m pytest linen/linen/tests/test_review_loop.py linen/linen/tests/test_review_modes.py -v
```

**结果**：25 / 25 通过。

---

## Live 验证

手工 POST 3 个不同 mode 的 review intent 到 `proj_001`（proj_001 实际是空目录，f001-f007 都是 `type=source` 的 negative finding）：

```bash
# i010 devils-advocate
curl -X POST http://127.0.0.1:9000/projects/proj_001/intents \
  -H 'Content-Type: application/json' \
  -d '{"from":["f001"],"type":"review:devils-advocate","description":"Manual test of review mode=devils-advocate","creator":"human"}'

# i011 cold-verifier
curl -X POST http://127.0.0.1:9000/projects/proj_001/intents \
  -H 'Content-Type: application/json' \
  -d '{"from":["f002"],"type":"review:cold-verifier","description":"Manual test of review mode=cold-verifier","creator":"human"}'

# i012 contradiction-reasoner
curl -X POST http://127.0.0.1:9000/projects/proj_001/intents \
  -H 'Content-Type: application/json' \
  -d '{"from":["f003"],"type":"review:contradiction-reasoner","description":"Manual test of review mode=contradiction-reasoner","creator":"human"}'
```

**Live 行为**（`/tmp/linen-dispatcher.log`）：

```
[09:02:14] dispatched review project=proj_001 intent=i010 worker=local-pi
[09:02:14] review mode resolved ... intent=i010 fact_id=f001 mode=devils-advocate prompt=review.md
[09:03:12] review recorded ... intent=i010 fact_id=f001 verdict=VALID confidence=certain execute_ms=58293

[09:03:14] dispatched review project=proj_001 intent=i011 worker=local-pi
[09:03:14] review mode resolved ... intent=i011 fact_id=f002 mode=cold-verifier prompt=review_cold_verifier.md
[09:03:40] review recorded ... intent=i011 fact_id=f002 verdict=VALID confidence=certain execute_ms=25591

[09:03:41] dispatched review project=proj_001 intent=i012 worker=local-pi
[09:03:41] review mode resolved ... intent=i012 fact_id=f003 mode=contradiction-reasoner prompt=review_contradiction_reasoner.md
[09:04:10] review recorded ... intent=i012 fact_id=f003 verdict=VALID confidence=firm execute_ms=28877
```

**每个 review 的 summary 都反映对应 mode 的 reasoning 风格**：

| Review | Mode | Summary 标志 |
|--------|------|---------------|
| r010 (i010) | devils-advocate | 5-layer 证据列举（`ls -la` / `find -mindepth 1`） |
| r011 (i011) | cold-verifier | "Independently confirmed"（zero-context 独立复审标志语） |
| r012 (i012) | contradiction-reasoner | "TRIZ finds no tension to sacrifice"（直接引用 TRIZ model） |

**Confidence 分布合理**：devils-advocate 和 cold-verifier 给 `certain`（直接 code 验证），contradiction-reasoner 给 `firm`（reasoning model 强论证但非 exhaustive code verification）。

**fact.status 自动重算**（server `aggregate_fact_status_from_reviews`）：
- 之前：f001/f002/f003 = `draft`
- 之后：f001/f002/f003 = `triaged`（因为每条 review 都是 VALID）

---

## 与 linen 设计哲学的关联

**通用 OODA 范式** vs **具名 sub-agent 范式**：

linen 的核心差异化是"**无固定角色，任务从 graph 状态生成**"（参考 `docs/specs/dispatcher-design.md` "设计要点 5"）。任何把 worker 拆成"auditor / verifier / reporter / ..."等具名 role 的设计都与此对立。

Phase 1a 加 3 个 review mode **没破坏这个哲学**，因为：

1. **Mode 是 review task 内部的 dial**，不是 worker 的 fixed role——worker 仍是无角色的 "review worker"，只是被 task prompt 告知按哪个 angle 推理
2. **Mode 由 reason worker 动态选择**（基于 fact 特征），不是 orchestrator 预定义
3. **mode suffix 编码在 `Intent.type`**，跟其它 `type=search/trace/validate/reach/characterize` 是同一维度——linen 的"任务从 graph 状态生成"原则保留

**为什么 mode 而不是 prompt 微调**：

- 3 个 mode 的 reasoning model **根本不同**（5-layer table vs 7-step protocol vs TRIZ/Game Theory），不是 prompt 措辞调整
- 3 个 mode 产出的 extras 字段不同（`protection_search` vs `cold_verification` vs `contradiction_analysis`），未来 report assembler 可以基于 extras 字段做差异化呈现
- 3 个 mode 适合不同 fact 复杂度（简单 vs 长链 vs 冲突），硬塞进一个 prompt 会让 worker 不知道哪个 reasoning model 优先
