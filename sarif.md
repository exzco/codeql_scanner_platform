# SARIF 从零到实战：在本项目中如何调试与解析

> 适用代码：`internal/scanner/sarif.go`（你提供的当前版本）
> 
> 读者画像：对 SARIF 零认知，希望快速看懂代码 + 会调试 + 知道可改进方向。

---

## 1. SARIF 是什么？先建立最小认知

SARIF（Static Analysis Results Interchange Format）是静态分析结果的标准交换格式，当前主流版本是 **2.1.0**。

你可以把它理解为：

- **工具输出层标准**（CodeQL、Semgrep、ESLint 等都可产出）
- **结果传输中间层**（扫描引擎 -> 平台后端 -> 前端展示）
- **语义比文本更结构化**（规则、位置、严重性、数据流都可表达）

在你的项目中，SARIF 的职责很清晰：

1. CodeQL CLI 产出 `results.sarif`
2. `ParseSARIF(...)` 读取并转成内部结构 `ParsedVulnerability`
3. Service 层落库
4. 前端展示

---

## 2. 你这份 `sarif.go` 在做什么（整体视角）

`internal/scanner/sarif.go` 的核心是把“通用 SARIF JSON”翻译成“你业务里的漏洞模型”。

### 2.1 数据结构层（类型定义）

你定义了 SARIF 的关键子集：

- 顶层：`SARIFReport` -> `Runs`
- 规则元数据：`SARIFDriver` / `SARIFRule`
- 结果：`SARIFResult`
- 定位：`SARIFLocation` / `SARIFRegion`
- 数据流：`SARIFCodeFlow` / `SARIFThreadFlow`

这是一种很常见策略：

- 不把 SARIF 全量 schema 都建模（太大）
- 只保留业务展示与落库所需字段

### 2.2 解析入口

```go
func ParseSARIF(filePath string) ([]ParsedVulnerability, error)
```

流程：

1. `os.ReadFile` 读文件
2. `json.Unmarshal` 到 `SARIFReport`
3. 遍历 `runs`
4. 用 `rules` 构建字典（`buildRuleMap`）
5. 遍历每个 `result`，拼一个 `ParsedVulnerability`
6. 抽取 primary location、snippet、dataflow、fingerprint
7. 返回漏洞数组

这是典型的 **两阶段解析**：

- 阶段 A：把 JSON 反序列化到结构体
- 阶段 B：把结构体映射成业务 DTO

---

## 3. 逐段讲解关键代码（按“输入 -> 输出”）

## 3.1 规则映射：`buildRuleMap`

```go
func buildRuleMap(rules []SARIFRule) map[string]SARIFRule
```

用途：把 `ruleId -> rule` 建索引，后续处理 `result` 时 O(1) 获取规则信息。

意义：

- `result` 里通常只有 `ruleId`
- 人类可读标题、默认 severity 在 `rules` 元数据里

如果没有这个 map，你会频繁 O(n) 查找规则，结果多时性能差。

## 3.2 严重性映射：`mapSeverity` / `securityScoreToSeverity`

你的优先级：

1. 先看 `rule.properties["security-severity"]`（字符串分值，如 `7.5`）
2. 没有再回退到 `result.level`（error/warning/note）

评分区间规则：

- `>= 9.0` -> critical
- `>= 7.0` -> high
- `>= 4.0` -> medium
- `>= 0.1` -> low
- else -> info

这是一个合理的“定量优先、定性兜底”策略。

## 3.3 位置提取（primary location）

对于每个 `result`：

- 取 `locations[0]` 作为主定位
- 提取 `file_path`, `start_line`, `end_line`
- 若 `end_line == 0`，补成 `start_line`
- snippet 优先取 `contextRegion.snippet`，其次 `region.snippet`

这能满足大部分前端表格展示（文件、行号、摘要）。

## 3.4 数据流提取：`extractDataFlow`

从：

- `codeFlows[] -> threadFlows[] -> locations[]`

抽成你自己的：

- `[]FlowStep{file_path,start_line,message,snippet}`

这就是你以后做“污点传播路径可视化”的基础数据。

## 3.5 指纹策略（去重核心）

优先：

- `partialFingerprints["primaryLocationLineHash"]`

兜底：

- `fmt.Sprintf("%s:%s:%d", ruleId, filePath, startLine)`

作用：

- 同一漏洞多次扫描可归并
- Service 层可以按 `(repo_id, fingerprint)` 做 upsert

---

## 4. 如何调试 SARIF 解析（实战手册）

下面给你一套“从 CLI 到解析到入库”的排查顺序，按这个走基本不会迷路。

### 4.1 第 0 步：先确认 SARIF 文件本身存在

关注：

- `results.sarif` 路径是否正确
- 文件大小是否 > 0

若文件不存在，先排查 `codeql database analyze` 参数。

### 4.2 第 1 步：验证 JSON 可解析

如果 `json.Unmarshal` 报错：

- 先看输出是不是被截断
- 是否误用了非 `--format=sarif-latest`

建议临时打印：

- 文件前 1KB
- `len(report.Runs)`

### 4.3 第 2 步：检查 runs / results 数量

调试关键计数：

- `runs count`
- 每个 run 的 `results count`
- `rules count`

常见误区：

- 规则有但结果 0（可能确实没命中，不是解析问题）

### 4.4 第 3 步：检查 rule map 命中率

统计：

- 有多少 `result.ruleId` 在 `ruleMap` 找不到

如果 miss 很高，说明你结构字段或版本兼容有问题。

### 4.5 第 4 步：检查位置与 snippet

排查点：

- `locations` 为空比例
- `start_line==0` 比例
- snippet 为空比例

这一步直接决定前端“看起来有没有内容”。

### 4.6 第 5 步：检查指纹稳定性

对同一个仓库重复扫描后观察：

- 指纹是否稳定
- 是否出现大量重复插入

如果你只用 `rule+file+line` 兜底，会在代码行移动后产生漂移。

### 4.7 第 6 步：从解析到入库闭环验证

你项目里的关键验证点：

1. `ParseSARIF` 返回数量
2. `SaveScanResults` 成功写库数量
3. 任务表 `vuln_count`
4. `/scan/vulnerabilities?task_id=...` 能返回数据

要保证这 4 个数字逻辑一致。

---

## 5. 当前实现的优点

1. **结构清晰**：SARIF 子集模型 + 单一入口解析
2. **可维护**：`buildRuleMap`、`extractDataFlow` 拆分合理
3. **兼容性尚可**：severity 支持 score + level 双来源
4. **工程可落地**：有 fingerprint，可直接做去重

---

## 6. 当前缺点与风险（重点）

## 6.1 schema 兼容面偏窄

当前只建模了一部分字段；若不同工具/版本输出变体较大，可能丢失信息。

表现：

- 部分规则标题、描述为空
- 某些位置字段路径不一致时提取不到

## 6.2 指纹兜底较弱

`rule:file:line` 在代码移动后容易变化，导致“同一问题”变成“新问题”。

## 6.3 错误上下文不足

`ParseSARIF` 失败时目前只报顶层错误；缺乏 run/result 维度的定位信息。

## 6.4 大文件内存压力

`os.ReadFile + Unmarshal` 是一次性加载。大型 SARIF（几十 MB 以上）会增加内存峰值。

## 6.5 缺少契约测试

目前看不到针对 `sarif.go` 的样例回归测试，后续升级 CodeQL 版本可能静默退化。

---

## 7. 推荐改进路线（按投入产出排序）

## 7.1 短期（立刻可做）

1. **增加解析统计日志**（run/result/rule/dataflow 计数）
2. **增强错误信息**（携带 ruleId、file、line）
3. **加入 SARIF 样例单测**（happy path + 边界输入）

## 7.2 中期（稳定性提升）

1. **统一路径归一化**（Windows/Unix 分隔符）
2. **更稳健 fingerprint**：优先使用 SARIF 官方 fingerprint 字段组合
3. **支持更多 message 字段来源**（如 markdown/text fallback）

## 7.3 长期（平台化能力）

1. **流式解析**（`json.Decoder`）降低内存峰值
2. **规则元数据缓存表**（rule_id -> CWE/tag/help）
3. **数据流图可视化接口**（前端按 step 展示 source/sink path）

---

## 8. 给“零认知”同学的心智模型

把 SARIF 想成三层：

1. **规则层（Rule）**：这是什么问题、严重程度、标签
2. **结果层（Result）**：这个问题在当前代码库命中了几次
3. **位置/路径层（Location/CodeFlow）**：具体在哪里、如何传播

你当前 `sarif.go` 已经覆盖了这三层的最小闭环，所以项目能跑通扫描展示。

---

## 9. 建议阅读资料（官方优先）

### 9.1 标准与官方文档

1. OASIS SARIF v2.1.0 规范（权威）
   - https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
2. SARIF 官网（导航友好）
   - https://sarifweb.azurewebsites.net/
3. CodeQL CLI 文档（SARIF 输出相关）
   - https://codeql.github.com/docs/codeql-cli/

### 9.2 GitHub / CodeQL 实战

1. About code scanning alerts（理解结果如何落地到平台）
   - https://docs.github.com/en/code-security/code-scanning
2. CodeQL query help（理解 `ruleId` 背后的语义）
   - https://codeql.github.com/codeql-query-help/

### 9.3 适合入门的博客/文章（建议关键词）

建议检索关键词（中文/英文）：

- `SARIF 2.1.0 tutorial`
- `CodeQL SARIF parsing`
- `static analysis result normalization`
- `CWE-117 log injection CodeQL`

> 说明：博客质量参差，优先以 OASIS + GitHub 官方文档作为“准绳”。

---

## 10. 你下一步可以直接做什么

如果你准备继续提升这条链路，建议按这个顺序：

1. 给 `sarif.go` 增加 2~3 个固定样例单测
2. 补一版解析统计日志（便于线上排障）
3. 改进 fingerprint 策略
4. 前端增加 dataflow 展示抽屉（点击漏洞看传播路径）

这样你就从“能用”进阶到“可维护、可扩展、可解释”。
