# Skill 质量保证设计文档

| 项目 | 内容 |
|---|---|
| 文档状态 | Final |
| 生效日期 | 2026-08-20 |
| 设计对象 | Skill 质量保证 Module |
| 接入方式 | MCP Tool |
| MCP Tool | <code>scan_skill_quality</code> |
| 输入范围 | Skill ZIP 包 |
| 目标读者 | Skill 平台研发、安全研发、测试、运维与审核人员 |

## 1. 设计结论

<code>SkillQualityAssurance</code> 是无副作用的检查 Module。它接收一个 Skill ZIP，返回检查报告文件；请求修改结果时额外返回修改后的 ZIP。

Module 不上传、保存、入库、发布或修改 Skill，不写数据库，不调用不存在的平台上传流程。MCP Adapter 只负责 Base64 解码、Interface 调用和结果封装。

## 2. 设计范围与规则约束

### 2.1 来源文档

| 来源编号 | 文档 | 用途 |
|---|---|---|
| SRC-PKG-MD | <code>skill-upload-package-scan-rules(1).md</code> | 包检查 1—22 节、错误码和检查产物。 |
| SRC-SPEC | <code>原版-skills建设规范_0609(3).docx</code> | Skill 结构、描述、正文、代码、依赖、附件和内容规范。 |
| SRC-PKG-DOCX | <code>Skill 上传包扫描规则说明.docx</code> | 与 SRC-PKG-MD 交叉核对；不从残缺片段推导规则。 |
| SRC-SEC | <code>0720扫描规则说明.docx</code> | 15 类安全检测器、检测项、严重度和跳过规则。 |

Module 直接实现附录 A—C 的可确定规则。来源没有给出确定方法的项目返回 <code>NOT_EVALUATED</code>，不得假设存在外部包扫描器、安全扫描器、上传临时区、数据库或入库接口。

### 2.2 内容分类

| 分类 | 含义 | 是否改变检查结论 |
|---|---|---|
| <code>SOURCE_RULE</code> | 来源文档明确写出的检测、校验、跳过或严重度。 | 是，严格按来源执行。 |
| <code>SOURCE_ISSUE</code> | 来源规则存在缺失、歧义、可能误报或可能漏报。 | 否，只记录限制。 |
| <code>IMPLEMENTATION_ONLY</code> | Module Interface、MCP 接入、版本记录、脱敏和错误表达。 | 否，不改变规则命中。 |
| <code>REMEDIATION_OUTPUT</code> | 根据已命中问题生成的建议或修改后 ZIP。 | 否，不改变命中和结论。 |

<code>SOURCE_ISSUE</code> 和 <code>REMEDIATION_OUTPUT</code> 不得成为白名单、补充正则、严重度调整或规则修正。

### 2.3 运行配置

来源没有给出以下最终值，部署时必须显式配置，Module 不提供默认值：

~~~text
InspectionPolicy
  maxZipBytes: integer
  allowedExtensions: string[]
  skillNamePattern: string
~~~

配置缺失时 Module 返回 <code>ERROR</code>，不得自行采用推测值。请求参数不能覆盖这些配置。

### 2.4 能力覆盖

| 能力 | 状态 | 最终行为 |
|---|---|---|
| ZIP 结构、路径、大小、类型和元数据检查 | <code>SUPPORTED</code> | 执行附录 A 中可确定的来源规则。 |
| Skill 建设规范与安全检查 | <code>PARTIAL</code> | 只执行附录 B、C 明确且可确定的部分。 |
| 建议与修改后 ZIP | <code>SUPPORTED</code> | 由 <code>responseMode</code> 控制；原 ZIP 保持不变。 |
| 缺少确定方法的来源要求 | <code>NOT_EVALUATED</code> | 包括描述和正文质量、SQLi/XSS 数据流、依赖范围、内容合规、知识产权及已知恶意 IP/URL。 |
| RAR、目录和单个 <code>SKILL.md</code> 输入 | <code>NOT_PROVIDED</code> | Interface 只接受 Skill ZIP。 |
| 附加包强化 | <code>NOT_PROVIDED</code> | 不增加针对加密或嵌套 ZIP、链接、设备文件、Unicode 或大小写冲突、SVG XML、YAML 严格性及本地引用的拒绝规则。 |
| 全文与语义分析 | <code>NOT_PROVIDED</code> | 不把 64KB 样本扩展为全文，也不增加 AST、代码围栏语义、上下文豁免或语义补漏。 |
| 扩展安全分析 | <code>NOT_PROVIDED</code> | 不执行恶意文件、YARA、杀毒、大模型、SBOM、CVE、签名或动态沙箱扫描。 |
| Skill 生命周期管理 | <code>NOT_PROVIDED</code> | 不提供上传、存储、数据库、入库、发布、版本管理或写回操作。 |
| 规则例外管理 | <code>NOT_PROVIDED</code> | 不提供自动放行、误报豁免或例外审批。 |

<code>SUPPORTED</code> 表示 Interface 提供；<code>PARTIAL</code> 表示只覆盖来源中可确定的部分；<code>NOT_EVALUATED</code> 表示识别要求但不给出可靠判断；<code>NOT_PROVIDED</code> 表示本 Tool 没有该行为。

## 3. 质量保证 Module 与 MCP Adapter

### 3.1 结构

~~~text
MCP Client
    │
    ▼
MCP Adapter: scan_skill_quality
    ├── 校验 MCP 输入
    └── Base64 -> SkillPackageInput
    │
    ▼
SkillQualityAssurance.inspect(input, responseMode) -> SkillInspectionResult
    ├── Package Rule Evaluator
    ├── Specification Rule Evaluator
    ├── Security Rule Evaluator
    ├── Conclusion Builder
    └── Remediation Builder
    │
    ▼
MCP Adapter: SkillInspectionResult -> structuredContent + embedded resources
~~~

外部 seam 位于 MCP Adapter 与质量保证 Module 之间。各 Evaluator 和 Builder 是 Module 的内部实现，不作为外部 Interface 或假定存在的 Adapter。

### 3.2 质量保证 Module Interface

Module 只暴露一个操作：

~~~text
inspect(input: SkillPackageInput, responseMode: ResponseMode) -> SkillInspectionResult
~~~

~~~text
SkillPackageInput
  originalFileName: string
  content: ReadableBinary

ResponseMode
  REPORT_ONLY
  WITH_SUGGESTIONS
  WITH_REVISED_ZIP

SkillInspectionResult
  report: SkillInspectionReport
  revisedPackage: BinaryArtifact?

BinaryArtifact
  fileName: string
  mimeType: application/zip
  content: ReadableBinary
  sha256: string
~~~

Interface 不变量：

- <code>content</code> 只读；Module 不执行其中的脚本、命令或安装动作，也不改变输入 ZIP 的字节。
- 三种 <code>responseMode</code> 使用完全相同的检查过程、结论和问题列表。
- <code>WITH_SUGGESTIONS</code> 在报告文件中增加建议；<code>WITH_REVISED_ZIP</code> 同时生成一个新的修改后 ZIP。
- 修改后 ZIP 使用新文件名和 SHA-256；原 ZIP 仍由用户持有且保持不变。
- Interface 不提供规则开关、阈值覆盖、严重度覆盖、策略选择或忽略参数。
- 相同输入、配置和规则版本产生相同的检查结论。
- Module 不读写数据库、对象存储、上传区或 Skill 仓库。

### 3.3 Module 内部职责

- Package Rule Evaluator：执行附录 A 中可确定的 ZIP、路径、大小、类型、内容和元数据规则。
- Specification Rule Evaluator：执行附录 B 中可确定的建设规范。
- Security Rule Evaluator：执行附录 C 明确列出的检测条件；未定义部分不自行补全。
- Conclusion Builder：汇总检查状态和覆盖范围，不改变来源严重度。
- Remediation Builder：使用 Module 内置、按规则 ID 版本化的确定性修复模板生成建议；请求修改结果时，在内存中复制原包内容并生成新的修改后 ZIP，不调用大模型或外部服务。

### 3.4 MCP Adapter 职责

- 校验 JSON Schema，将 <code>contentBase64</code> 解码为只读字节并调用 Module。
- 将 <code>SkillInspectionReport</code> 序列化为 JSON 文件资源；存在 <code>revisedPackage</code> 时增加 ZIP 文件资源。
- <code>structuredContent</code> 只返回结论摘要和文件描述，不返回修改后的文件正文。
- Schema 或 Base64 无效时返回 MCP Tool 错误；不调用 Module。
- 不持久化请求、原 ZIP、报告文件或修改后 ZIP。

## 4. MCP Tool 契约

### 4.1 Tool 元数据

~~~json
{
  "name": "scan_skill_quality",
  "title": "Skill 质量与安全检查",
  "description": "检查 Skill ZIP，返回报告文件，并可返回独立的修改后 ZIP；不保存或覆盖原包。",
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  }
}
~~~

### 4.2 输入 Schema

~~~json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["skillPackage"],
  "properties": {
    "skillPackage": {
      "type": "object",
      "additionalProperties": false,
      "required": ["fileName", "contentBase64"],
      "properties": {
        "fileName": {
          "type": "string",
          "minLength": 1
        },
        "contentBase64": {
          "type": "string",
          "minLength": 1,
          "contentEncoding": "base64"
        }
      }
    },
    "responseMode": {
      "type": "string",
      "enum": [
        "REPORT_ONLY",
        "WITH_SUGGESTIONS",
        "WITH_REVISED_ZIP"
      ],
      "default": "REPORT_ONLY"
    }
  }
}
~~~

MCP 请求直接携带 ZIP 的 Base64 内容，不依赖 <code>uploadUri</code>、临时上传区或任意文件路径。Adapter 解码后仍按 <code>maxZipBytes</code> 检查原始 ZIP 大小；MCP Server 的请求大小上限必须容纳该值对应的 Base64 开销，否则配置无效。

### 4.3 输出

Tool 不返回修改后的文件正文。报告和修改后 ZIP 通过 MCP embedded resource 返回：

~~~json
{
  "content": [
    {"type": "resource", "resource": {"uri": "skill-check://si_01/report.json", "mimeType": "application/json", "blob": "<base64-json-bytes>"}},
    {"type": "resource", "resource": {"uri": "skill-check://si_01/pdf-revised.zip", "mimeType": "application/zip", "blob": "<base64-zip-bytes>"}}
  ],
  "structuredContent": {
    "inspectionId": "si_01...",
    "status": "COMPLETED",
    "conclusion": {"status": "REVIEW_REQUIRED", "coverage": "PARTIAL"},
    "artifacts": [
      {"role": "REPORT", "fileName": "skill-quality-report.json", "mimeType": "application/json", "sha256": "...", "uri": "skill-check://si_01/report.json"},
      {"role": "REVISED_PACKAGE", "fileName": "pdf-revised.zip", "mimeType": "application/zip", "sha256": "...", "uri": "skill-check://si_01/pdf-revised.zip"}
    ]
  }
}
~~~

<code>skill-check://</code> 只标识本次响应中的嵌入资源，不是下载地址，也不要求服务器保存文件。MCP Adapter 不产生 <code>text</code> 类型的修改内容。

## 5. 报告文件与修改后 ZIP

### 5.1 报告文件结构

<code>SkillInspectionReport</code> 序列化为 UTF-8 JSON 字节，以 <code>skill-quality-report.json</code> 文件资源返回。以下示例对应 <code>WITH_REVISED_ZIP</code>。

~~~json
{
  "inspectionId": "si_01...",
  "status": "COMPLETED",
  "target": {
    "originalFileName": "pdf.zip",
    "sha256": "..."
  },
  "versions": {
    "moduleVersion": "1.0.0",
    "rulesetVersion": "..."
  },
  "conclusion": {
    "status": "REVIEW_REQUIRED",
    "coverage": "PARTIAL",
    "summary": "发现 1 项潜在不合规信息；12 项规则未完全评估。",
    "basisRuleIds": ["SEC-SECRET-08"]
  },
  "packageCheck": {
    "passed": true,
    "fileCount": 4,
    "textType": "COMPOSITE_TEXT",
    "totalSizeBytes": 18020,
    "rootDir": "pdf",
    "metadata": {},
    "entries": [],
    "errors": [],
    "warnings": [],
    "details": []
  },
  "specificationChecks": [],
  "securityCheck": {
    "status": "FINDINGS",
    "findingIssueIds": ["issue-1"]
  },
  "issues": [
    {
      "issueId": "issue-1",
      "ruleId": "SEC-SECRET-08",
      "classification": "POTENTIAL_NON_COMPLIANCE",
      "sourceSeverity": "HIGH",
      "path": "SKILL.md",
      "line": 42,
      "message": "检测到疑似硬编码密码。",
      "evidenceRedacted": "password=[REDACTED]",
      "sourceRef": "SRC-SEC"
    }
  ],
  "notFullyEvaluatedRuleIds": [
    "PKG-11",
    "SPEC-NAME-STYLE",
    "SPEC-DESCRIPTION-QUALITY",
    "SPEC-BODY",
    "SPEC-RESOURCE-SEPARATION",
    "SPEC-LANGUAGE",
    "SPEC-CODE-SAFETY",
    "SPEC-DEPENDENCY",
    "SPEC-CONTENT",
    "SPEC-IP",
    "SEC-IOC-06",
    "SEC-IOC-07"
  ],
  "suggestions": [
    {
      "issueIds": ["issue-1"],
      "message": "删除硬编码密码，改为从运行环境读取。"
    }
  ],
  "revision": {
    "status": "GENERATED",
    "artifact": {
      "fileName": "pdf-revised.zip",
      "mimeType": "application/zip",
      "sha256": "..."
    },
    "changedFiles": [
      {
        "path": "SKILL.md",
        "issueIds": ["issue-1"]
      }
    ],
    "unresolvedIssueIds": []
  },
  "sourceIssues": [],
  "errors": []
}
~~~

### 5.2 结论语义

<code>conclusion.status</code>：

- <code>NON_COMPLIANT</code>：至少一个包规则或可确定建设规范明确失败。
- <code>REVIEW_REQUIRED</code>：没有明确失败，但存在安全 finding，且来源没有定义 finding 到通过/失败的映射。
- <code>COMPLIANT</code>：所有已执行检查均通过且没有安全 finding。
- <code>ERROR</code>：配置缺失或检查过程未完成，不能给出有效结论。

<code>conclusion.coverage</code> 独立表达覆盖范围：全部规则可执行时为 <code>FULL</code>；存在 <code>NOT_EVALUATED</code> 或仅执行了规则明确列出的部分时为 <code>PARTIAL</code>。<code>notFullyEvaluatedRuleIds</code> 列出相应规则。因此 <code>COMPLIANT + PARTIAL</code> 只表示已执行检查通过，不表示未评估要求已满足。

问题分类：

- <code>CONFIRMED_NON_COMPLIANCE</code>：来源给出明确条件且目标确定失败。
- <code>POTENTIAL_NON_COMPLIANCE</code>：检测到来源定义的可疑或安全模式，但来源没有给出最终裁决方式。
- <code>SOURCE_LIMITATION</code>：规则自身不完整、存在歧义或无法执行。

来源严重度原样保留；Module 不把严重度转换为结论。<code>SOURCE_ISSUE</code> 只进入 <code>sourceIssues</code>，不伪装成目标问题。

### 5.3 响应模式与文件产物

| 模式 | 报告 JSON 文件 | 报告内建议 | 修改后 ZIP |
|---|---|---|---|
| <code>REPORT_ONLY</code> | 返回 | 不包含 | 不返回 |
| <code>WITH_SUGGESTIONS</code> | 返回 | 包含 | 不返回 |
| <code>WITH_REVISED_ZIP</code> | 返回 | 包含 | 有安全修改时返回 |

每条建议必须引用一个或多个 <code>issueId</code>。<code>WITH_REVISED_ZIP</code> 生成的新包遵守以下约束：

- 以原 ZIP 为只读输入，复制未修改条目，只替换能够安全修改的 UTF-8 文本文件。
- 新包命名为 <code>&lt;原包基本名&gt;-revised.zip</code>，并记录独立 SHA-256；不得覆盖或改变原包。
- 保持原目录结构和未修改文件的字节，不向 Skill 包中加入检查报告。
- 修改只处理当前报告中的问题，不新增检测条件或重新判定原检查结论。
- 无法确定安全修改方式、目标为二进制文件或修改可能改变代码意图时，保留该问题，不猜测修改。
- 没有任何安全修改时不生成 ZIP；报告中的 <code>revision.status</code> 为 <code>NOT_GENERATED</code>，并列出原因。
- 修改后 ZIP 超过 MCP 响应大小限制时不转存到其他位置；报告记录 <code>OUTPUT_SIZE_LIMIT</code>，且不返回该 ZIP。
- 生成 ZIP 后至少验证其可打开、条目路径集合正确和修改文件内容一致；这不表示修改后已经合规。
- 报告证据保持脱敏；已检测到的密码、密钥或 Token 无法安全移除时不得生成修改后 ZIP。每项修改均可追溯到 <code>issueId</code>。

报告文件仅保存建议、修改状态和产物元数据，不包含修改后的文件正文或 ZIP Base64。

## 6. 检查顺序

1. MCP Adapter 校验 Schema 和 Base64，构造 <code>SkillPackageInput</code>。
2. Module 校验运行配置并执行包规则；包规则失败时生成结论，不执行建设规范或安全规则。
3. 包规则通过后执行建设规范和安全规则；未执行或仅部分执行的规则进入 <code>notFullyEvaluatedRuleIds</code>。
4. Module 生成结论和问题列表。
5. Module 根据 <code>responseMode</code> 选择是否生成建议和独立的修改后 ZIP。
6. MCP Adapter 返回报告 JSON 文件，并在存在修改后 ZIP 时一并作为嵌入资源返回。

整个过程只读、无网络访问、无持久化副作用。

## 7. 测试设计

### 7.1 Module Interface

- 相同输入在三种 <code>responseMode</code> 下的结论、问题和规则状态完全相同。
- Interface 不能关闭检测器、修改阈值、覆盖严重度或忽略问题。
- 测试确认 Module 不写文件、数据库、对象存储或网络。

### 7.2 MCP Adapter

- 校验 Schema、Base64 解码、ZIP 字节映射、报告 JSON 文件和修改后 ZIP 的嵌入资源封装。
- 无效 Schema 或 Base64 不调用 Module；无效 ZIP 作为检查结果返回。
- 验证响应不包含修改后的文件正文，<code>skill-check://</code> URI 不触发持久化或二次获取。

### 7.3 包规则

- 为 SRC-PKG-MD 的 1—22 节建立测试映射。
- 覆盖两种合法包根、缺失 <code>SKILL.md</code>、包根外路径、路径穿越、重复路径、大小限制、白名单、危险路径、文本/图片类型、危险内容和 front matter。
- 验证 macOS 垃圾文件不参与根判断、统计、重复检查和安全检查。
- 验证显式目录、隐式目录、文件类型、Content-Type 和 searchable 映射。

### 7.4 建设规范与安全规则

- 覆盖 ZIP 名与 <code>name</code>、附件 50MB 边界及 12 项规范状态。
- 缺少确定方法的规范固定返回 <code>NOT_EVALUATED</code>，不引入隐式启发式判断。
- 15 类检测器的 98 个检测项各有命中样例，并覆盖原文跳过规则。
- <code>df.info()</code>、<code>user: zh</code> 和 <code>writer.encrypt(...)</code> 只记录来源规则的实际匹配结果，不增加豁免或补漏。
- 原始密码、密钥和 Token 不出现在报告证据、建议或日志中。

### 7.5 建议与修改后 ZIP

- <code>REPORT_ONLY</code> 不执行 Remediation Builder。
- 建议和修改条目只引用已存在的 <code>issueId</code>，且不改变原检查结果。
- 不支持安全修改时返回原因，不猜测代码意图。
- 验证原 ZIP 的字节和 SHA-256 不变，修改后 ZIP 使用新文件名和独立 SHA-256。
- 验证修改后 ZIP 可打开、条目路径正确、未修改文件字节不变，且报告未写入包内。
- Tool 调用后文件系统和数据库状态不变。

## 8. 验收标准

- Module 与 MCP Adapter 符合第 3—5 节 Interface 和契约。
- 22 节包规则、12 项建设规范、98 项安全规则及 15 项来源限制均可追溯。
- 三种响应模式只影响报告建议和修改后 ZIP，不影响结论和问题列表。
- Tool 不上传、保存、入库、发布或覆盖原 Skill；修改后 ZIP 只作为独立响应资源返回。
- 范围外检测未实现；<code>SOURCE_ISSUE</code> 不改变规则行为，敏感证据完成脱敏。

## 附录 A：包扫描规则

### A.1 逐节规则映射

| 规则 ID | 来源节 | 行为 |
|---|---:|---|
| PKG-01 | 1 | 包扫描只负责 ZIP 结构、路径、大小、类型、基础内容和 <code>SKILL.md</code> 元数据。 |
| PKG-02 | 2 | 文件非空；原始文件名以 <code>.zip</code> 结尾且大小写不敏感；大小不超过 <code>skill.upload.max-zip-bytes</code>；文件头含 <code>PK</code>；ZIP 可正常打开。 |
| PKG-03 | 3 | 按原文执行路径标准化和非法路径判断；非法时返回 <code>ILLEGAL_PATH</code>。 |
| PKG-04 | 4 | 完全忽略指定 macOS 垃圾文件，不参与判断、统计、重复检查、入库和安全扫描。 |
| PKG-05 | 5 | 只接受根目录 <code>SKILL.md</code> 或唯一顶层目录下的 <code>SKILL.md</code>。 |
| PKG-06 | 6 | 唯一包根外的高风险路径导致失败；其他包根外路径忽略。 |
| PKG-07 | 7 | 在剥离包根后的标准化路径上检查重复文件、重复目录和文件/目录冲突，返回 <code>DUPLICATE_PATH</code>。 |
| PKG-08 | 8 | 最多 1000 个业务文件；单文件解压后最多 10MB；解压后总计最多 200MB；同时检查声明大小和实际读取大小。 |
| PKG-09 | 9 | 文件必须有扩展名并命中平台配置白名单；否则返回 <code>EXTENSION_NOT_ALLOWED</code>。 |
| PKG-10 | 10 | 命中原文高风险路径列表时返回 <code>DANGEROUS_PATH</code>。 |
| PKG-11 | 11 | 每个文件最多读取前 64KB 样本；文本似二进制或图片魔数不匹配时返回 <code>CONTENT_TYPE_MISMATCH</code>。 |
| PKG-12 | 12 | 只在文本文件前 64KB 样本中匹配原文危险内容；命中时返回 <code>DANGEROUS_CONTENT</code>。 |
| PKG-13 | 13 | <code>SKILL.md</code> 必须是 UTF-8，包含可解析为 Map 的 YAML front matter，并校验规定字段。 |
| PKG-14 | 14 | <code>name</code> 使用项目配置正则；非空 <code>version</code> 导致失败。 |
| PKG-15 | 15 | 返回规定的包扫描产物字段。 |
| PKG-16 | 16 | 生成文件和目录节点；保留显式目录并补齐隐式父目录。 |
| PKG-17 | 17 | 按规定扩展名映射 <code>fileType</code>。 |
| PKG-18 | 18 | 按规定扩展名映射 <code>contentType</code>。 |
| PKG-19 | 19 | 按规定扩展名设置 <code>searchable</code>。 |
| PKG-20 | 20 | 保持包扫描在上传流程中的原有顺序和短路行为。 |
| PKG-21 | 21 | 示例仅验证前述规则，不产生额外检测条件。 |
| PKG-22 | 22 | 保持包扫描与外部安全扫描分层、macOS 垃圾忽略、平台生成版本号和文本类型含义。 |

ZIP 无法打开时保留原错误信息 <code>zip 文件无法正常打开</code>。无法识别合法包根时保留原错误信息 <code>SKILL.md 必须位于 ZIP 根目录，或位于唯一顶层目录下</code>。

以上表格保留来源行为，不把原上传要求改写成检查规则。本 Tool 的映射为：PKG-02、PKG-09 和 PKG-14 所需配置由 <code>InspectionPolicy</code> 提供；PKG-04 的忽略项不参与任何检查；PKG-20 只保留检查顺序和短路；PKG-22 只保留规则分层、垃圾文件忽略和文本类型，Tool 不生成版本号或执行入库。

### A.2 路径和包根

路径标准化按以下顺序执行：

1. 去掉开头的 <code>./</code>。
2. 去掉目录路径末尾的 <code>/</code>。
3. 使用 <code>/</code> 作为统一路径分隔符。
4. 拒绝空文件路径。
5. 拒绝反斜杠 <code>\</code>。
6. 拒绝冒号 <code>:</code>。
7. 拒绝以 <code>/</code> 开头的绝对路径。
8. 拒绝连续分隔符和空路径片段。
9. 拒绝值为 <code>..</code> 的路径片段。
10. 拒绝归一化后以 <code>..</code> 开头的路径。

忽略项保持为：

- <code>__MACOSX/**</code>
- <code>.DS_Store</code> 和 <code>*/.DS_Store</code>
- <code>._*</code> 和 <code>*/._*</code>

高风险路径片段保持为：

- <code>.git</code>、<code>.svn</code>、<code>.hg</code>、<code>.ssh</code>
- <code>__macosx</code>、<code>node_modules</code>、<code>.idea</code>、<code>.vscode</code>
- <code>.env</code> 和 <code>*/.env</code>

不执行大小写折叠或 Unicode 正规化。

### A.3 文件数量、大小和白名单

- 业务文件数量上限：1000，错误码 <code>FILE_COUNT_EXCEEDED</code>。
- 单个解压后文件上限：10MB，即 10485760 字节，错误码 <code>SINGLE_FILE_SIZE_EXCEEDED</code>。
- 解压后总大小上限：200MB，即 209715200 字节，错误码 <code>TOTAL_UNCOMPRESSED_SIZE_EXCEEDED</code>。
- ZIP 原文件大小上限由 <code>InspectionPolicy.maxZipBytes</code> 提供，对应来源中的 <code>skill.upload.max-zip-bytes</code>。
- 扩展名白名单由 <code>InspectionPolicy.allowedExtensions</code> 提供；文档未列出的值不得自行补入。
- <code>properties</code> 只有在 <code>allowedExtensions</code> 中存在时才允许，不能因代码常量存在而放行。

### A.4 内容类型

文本类扩展名：

~~~text
md, txt, json, yml, yaml, js, ts, py, java, xml, html, css, sh
~~~

图片校验：

- <code>png</code> 检查 PNG 文件头。
- <code>jpg/jpeg</code> 检查 JPEG 文件头。
- <code>gif</code> 检查 GIF87a/GIF89a 文件头。
- <code>svg</code> 不做魔数校验，默认通过。

### A.5 基础危险内容

只在文本文件前 64KB 样本中匹配：

- <code>rm -rf /</code>
- <code>curl ... | sh</code>、<code>curl ... | bash</code>
- <code>wget ... | sh</code>、<code>wget ... | bash</code>
- <code>nc -e</code>
- <code>bash -i</code>
- <code>/etc/passwd</code>
- <code>BEGIN RSA PRIVATE KEY</code>
- <code>BEGIN DSA PRIVATE KEY</code>
- <code>BEGIN EC PRIVATE KEY</code>
- <code>BEGIN OPENSSH PRIVATE KEY</code>
- <code>AWS_SECRET_ACCESS_KEY</code>
- <code>AKIA[0-9A-Z]{16}</code>

### A.6 SKILL.md 元数据

- 文件按 UTF-8 读取。
- 文件以 <code>---</code> 开头并存在闭合的 <code>---</code>。
- front matter 解析结果为 Map。
- <code>name</code> 必填。
- <code>description</code> 必填。
- <code>title</code> 可选；为空时使用 <code>name</code>。
- <code>version</code> 不允许填写；非空时失败。
- <code>tags</code> 可选；为空时使用空数组。
- <code>name</code> 使用 <code>InspectionPolicy.skillNamePattern</code>。

对应错误码：

- <code>SKILL_MD_FRONTMATTER_REQUIRED</code>
- <code>SKILL_MD_FRONTMATTER_INVALID</code>
- <code>SKILL_MD_NAME_REQUIRED</code>
- <code>SKILL_MD_DESCRIPTION_REQUIRED</code>
- <code>SKILL_MD_VERSION_NOT_ALLOWED</code>

### A.7 扫描产物和文件节点

包扫描结果完整保留：

- <code>passed</code>
- <code>fileCount</code>
- <code>textType</code>
- <code>totalSizeBytes</code>
- <code>rootDir</code>
- <code>metadata</code>
- <code>entries</code>
- <code>errors</code>
- <code>warnings</code>
- <code>details</code>

<code>PURE_TEXT</code> 表示包内只有一个业务文件；<code>COMPOSITE_TEXT</code> 表示包内有多个业务文件。

每个 entry 保留：

- <code>rawPath</code>、<code>normalizedPath</code>
- <code>nodeType</code>、<code>nodeName</code>
- <code>parentPath</code>、<code>pathDepth</code>
- <code>sizeBytes</code>、<code>sha256</code>
- <code>contentType</code>、<code>fileType</code>、<code>searchable</code>

显式 ZIP 目录进入结果；文件路径中的父目录补为隐式目录。

### A.8 文件分类映射

| 扩展名 | fileType | contentType | searchable |
|---|---|---|---|
| md | MARKDOWN | text/markdown | true |
| txt | TEXT | text/plain | true |
| json | TEXT | application/json | true |
| yml、yaml | TEXT | application/x-yaml | true |
| xml | TEXT | text/xml | true |
| html | TEXT | text/html | true |
| css | TEXT | text/css | true |
| js、ts、py、java、sh | SCRIPT | application/octet-stream | true |
| png | IMAGE | image/png | false |
| jpg、jpeg | IMAGE | image/jpeg | false |
| gif | IMAGE | image/gif | false |
| svg | IMAGE | application/octet-stream | false |
| pdf | BINARY | application/pdf | false |
| 其他白名单扩展名 | OTHER | application/octet-stream | false |

## 附录 B：Skill 建设规范检查

| 规则 ID | 来源要求 | 检查方式 |
|---|---|---|
| SPEC-ZIP-NAME | ZIP 包名字与 Skill 名字完全一致。 | 对 ZIP 文件名去掉 <code>.zip</code> 后与 front matter 的 <code>name</code> 做原值精确比较；不增加大小写或 Unicode 正规化。 |
| SPEC-SKILL-MD | ZIP 至少包含一个有效 <code>SKILL.md</code>，含 <code>name</code> 和 <code>description</code>。 | 复用包扫描结果。 |
| SPEC-NAME-STYLE | <code>name</code> 通常使用小写字母和连字符。 | <code>NOT_EVALUATED</code>；保留为来源建议，不替代 <code>InspectionPolicy.skillNamePattern</code>。 |
| SPEC-DESCRIPTION-QUALITY | <code>description</code> 用 1—2 句话自包含地说明功能、场景和触发条件，避免歧义。 | <code>NOT_EVALUATED</code>；原文未给出确定性算法，且大模型扫描未启用。 |
| SPEC-BODY | 正文按任务灵活组织，不强制模板；逻辑或步骤应清晰、闭环并覆盖正常与异常场景。 | <code>NOT_EVALUATED</code>；不增加正文非空、章节或关键词规则。 |
| SPEC-RESOURCE-SEPARATION | 长文档、脚本和资源与正文分离。 | <code>NOT_EVALUATED</code>；不增加目录或引用规则。 |
| SPEC-LANGUAGE | 表述简洁，无模糊词汇。 | <code>NOT_EVALUATED</code>。 |
| SPEC-CODE-SAFETY | 不得含恶意或攻击性内容，包括 SQL 注入、XSS；不得用未验证输入构造 SQL 或 HTML。 | 安全检查结果原样报告；来源未定义的 SQLi、XSS 和数据流分析部分标记 <code>NOT_EVALUATED</code>。 |
| SPEC-DEPENDENCY | 不应依赖沙箱默认镜像范围外的安装包。 | 未取得默认镜像依赖清单时为 <code>NOT_EVALUATED</code>，不得自行建立清单。 |
| SPEC-ATTACHMENT-SIZE | 除 <code>SKILL.md</code> 外的附件总大小不超过 50MB。 | 对标准化业务文件求和并排除 <code>SKILL.md</code>；结果为 <code>PASS</code> 或 <code>FAIL</code>。该规范结果不改写包扫描的 200MB 上限。 |
| SPEC-CONTENT | 不得包含违法、违规、色情、暴力等不良信息。 | <code>NOT_EVALUATED</code>；来源未提供检测器。 |
| SPEC-IP | 避免未经授权的图片、音乐等知识产权内容。 | <code>NOT_EVALUATED</code>；来源未提供检测器。 |

规范检查状态：

- <code>PASS</code>：确定性要求满足。
- <code>FAIL</code>：确定性要求不满足。
- <code>NOT_EVALUATED</code>：来源有要求，但没有足够规则或已启用能力自动判断。

不使用综合分数，也不把 <code>NOT_EVALUATED</code> 转换为 <code>NON_COMPLIANT</code>。

## 附录 C：安全检查规则

### C.1 通用行为

- Security Rule Evaluator 只执行本附录明确列出的条件，不补写正则、匹配边界、大小写规则或文件范围。
- 原文使用“等”或缺少匹配细节时，只执行明确列出的部分，并将缺失范围记录为 <code>SOURCE_ISSUE</code>。
- finding 保留 SRC-SEC 中的严重度；<code>HIGH/CRITICAL</code> 和 <code>MEDIUM/HIGH</code> 等复合值不得自行归一化。
- 所有检测器默认跳过 <code>.git</code>、<code>__pycache__</code>、<code>.venv</code> 和 <code>node_modules</code> 目录。
- 恶意文件检测和大模型扫描保持未启用。
- 来源没有定义 finding 到通过/失败的映射；安全 finding 按第 5.2 节产生 <code>REVIEW_REQUIRED</code>，不从严重度推导最终结论。

### C.2 SecretsDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-SECRET-01 | AWS 访问密钥 | <code>AKIA</code> 开头的 20 位密钥 | HIGH |
| SEC-SECRET-02 | AWS 凭证 | <code>aws_access_key_id</code>、<code>aws_secret_access_key</code> 配置 | HIGH |
| SEC-SECRET-03 | 私钥 | <code>-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----</code> | HIGH |
| SEC-SECRET-04 | OpenAI API 密钥 | <code>sk-</code> 开头的密钥 | HIGH |
| SEC-SECRET-05 | GitHub Token | <code>ghp_</code>、<code>gho_</code>、<code>github_pat_</code> 开头 | HIGH |
| SEC-SECRET-06 | Slack Token | <code>xox[baprs]-</code> 开头 | HIGH |
| SEC-SECRET-07 | API 密钥/密钥 | <code>api_key</code>、<code>secret_key</code>、<code>access_token</code>、<code>auth_token</code> 等字段后跟 20 位以上字符串 | HIGH |
| SEC-SECRET-08 | 硬编码密码 | <code>password=</code> 后跟 8 位以上字符串 | HIGH |
| SEC-SECRET-09 | 硬编码用户名 | <code>username</code>、<code>user</code>、<code>login</code> 等字段后跟 4 位以上字符串 | MEDIUM |

### C.3 InjectionDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-INJECT-01 | eval 动态执行 | <code>eval()</code> 参数非字面量字符串 | HIGH |
| SEC-INJECT-02 | exec 动态执行 | <code>exec()</code> 参数非字面量字符串 | HIGH |
| SEC-INJECT-03 | 动态导入 | 使用 <code>__import__()</code> | HIGH |
| SEC-INJECT-04 | compile 编译 | 使用 <code>compile()</code> | HIGH |
| SEC-INJECT-05 | os.system | 使用 <code>os.system()</code> | HIGH |
| SEC-INJECT-06 | os.popen | 使用 <code>os.popen()</code> | HIGH |
| SEC-INJECT-07 | subprocess shell | subprocess 调用设置 <code>shell=True</code> | HIGH |
| SEC-INJECT-08 | execfile | 使用 Python 2 <code>execfile()</code> | HIGH |

### C.4 Base64Detector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-B64-01 | 可疑 Base64 解码 | 长度至少 50；解码后含 <code>exec</code>、<code>eval</code>、<code>import</code>、<code>subprocess</code>、<code>os.system</code>、<code>curl</code>、<code>wget</code>、<code>bash</code>、<code>socket</code> 等关键词 | HIGH |
| SEC-B64-02 | 普通 Base64 | 长度至少 50；解码后无明显恶意 | MEDIUM |
| SEC-B64-03 | 二进制 Base64 | 解码为非 UTF-8 内容 | MEDIUM |

跳过：<code>data:image/</code>、<code>package-lock.json</code>、<code>yarn.lock</code>、<code>pnpm-lock.yaml</code>，以及 <code>integrity</code>、<code>sha256</code>、<code>sha512</code>、<code>sha384</code> 字段。

### C.5 ObfuscationDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-OBF-01 | eval/exec | 参数非字面量的 <code>eval()</code> 或 <code>exec()</code> | HIGH |
| SEC-OBF-02 | Hex 序列 | 连续 5 个以上 <code>\xXX</code> 转义字符 | HIGH |
| SEC-OBF-03 | chr 拼接 | 3 个以上 <code>chr()</code> 函数拼接 | HIGH |
| SEC-OBF-04 | Python 反转 | 使用 <code>[::-1]</code> | MEDIUM |
| SEC-OBF-05 | JS 反转 | <code>.split().reverse().join()</code> 模式 | MEDIUM |
| SEC-OBF-06 | fromCharCode | 多参数 <code>String.fromCharCode()</code> | HIGH |
| SEC-OBF-07 | atob | 对长字符串调用 <code>atob()</code> | MEDIUM |

### C.6 HiddenCharDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-HIDDEN-01 | 零宽字符 | U+200B、U+200C、U+200D、U+2060、U+FEFF、U+2063、U+00AD | LOW |
| SEC-HIDDEN-02 | Unicode 转义零宽字符 | 源码中的 <code>\u200b</code>、<code>\u200c</code>、<code>\u200d</code>、<code>\u2060</code>、<code>\ufeff</code>、<code>\u2063</code>、<code>\u00ad</code> | LOW |
| SEC-HIDDEN-03 | 双向控制字符 | U+202A—U+202E、U+2066—U+2069、U+200E、U+200F | LOW |

### C.7 EntropyDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-ENTROPY-01 | 高熵文本行 | 行长度至少 100；Shannon 熵大于 5.5，中文或 Markdown 大于 6.5 | MEDIUM |

跳过：短于 100 字符的行、<code>data:</code> 前缀、以 <code>//</code>、<code>#</code>、<code>/*</code>、<code>*</code> 表示的注释行，以及 <code>package-lock.json</code>、<code>yarn.lock</code>、<code>pnpm-lock.yaml</code>、<code>Cargo.lock</code>、<code>Gemfile.lock</code>、<code>poetry.lock</code> 等锁定文件。

### C.8 DownloadExecDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-DOWNLOAD-01 | curl 管道到 shell | <code>curl ... | bash</code> 或 <code>curl ... | sh</code> | CRITICAL |
| SEC-DOWNLOAD-02 | wget 管道到 shell | <code>wget ... | bash</code> 或 <code>wget ... | sh</code> | CRITICAL |
| SEC-DOWNLOAD-03 | curl 下载后执行 | <code>curl -o ... && bash</code> | CRITICAL |
| SEC-DOWNLOAD-04 | wget 下载后执行 | <code>wget -O ... && bash</code> | CRITICAL |
| SEC-DOWNLOAD-05 | curl 管道到 Python | <code>curl ... | python</code> | CRITICAL |
| SEC-DOWNLOAD-06 | wget 管道到 Python | <code>wget ... | python</code> | CRITICAL |
| SEC-DOWNLOAD-07 | fetch 配合 eval | <code>fetch()</code> 返回值配合 <code>eval()</code> | CRITICAL |
| SEC-DOWNLOAD-08 | urllib 配合 exec | <code>urlopen()</code> 返回值配合 <code>exec()</code> | CRITICAL |
| SEC-DOWNLOAD-09 | requests 配合 exec | <code>requests.get()</code> 返回值配合 <code>exec()</code> | CRITICAL |

### C.9 CredentialTheftDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-CRED-01 | macOS 密码对话框 | <code>osascript display dialog password</code> | CRITICAL |
| SEC-CRED-02 | macOS 隐藏输入 | <code>osascript display dialog hidden answer</code> | CRITICAL |
| SEC-CRED-03 | Keychain 密码提取 | <code>security find-generic-password</code> 或 <code>security find-internet-password</code> | CRITICAL |
| SEC-CRED-04 | Keychain 导出 | <code>security dump-keychain</code> | CRITICAL |
| SEC-CRED-05 | SSH 私钥读取 | 读取 <code>.ssh/id_rsa</code>、<code>.ssh/id_ed25519</code>、<code>.ssh/id_ecdsa</code> | CRITICAL |
| SEC-CRED-06 | SSH 私钥访问 | 访问 <code>.ssh/id_</code> 开头文件 | CRITICAL |
| SEC-CRED-07 | 凭证文件读取 | 读取 <code>.env</code>、<code>.npmrc</code>、<code>.pypirc</code>、<code>.netrc</code> | CRITICAL |
| SEC-CRED-08 | AWS 凭证文件 | 访问 <code>.aws/credentials</code> | CRITICAL |
| SEC-CRED-09 | 浏览器凭证 | 访问 <code>Cookies.binarycookies</code>、<code>Login Data</code>、<code>cookies.sqlite</code> | CRITICAL |

### C.10 ExfiltrationDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-EXFIL-01 | ZIP 加上传 | 同时出现 <code>zipfile</code>、<code>ZipFile</code> 或 <code>make_archive</code> 与 <code>requests.post/put</code>、<code>urllib.request.urlopen/Request</code>、<code>http.client</code>、<code>fetch()</code> 或 <code>.upload</code> | HIGH |
| SEC-EXFIL-02 | 递归敏感枚举 | <code>glob.glob</code> 或 <code>glob.iglob</code> 枚举 <code>/home</code>、<code>~</code>、<code>**</code> | HIGH |
| SEC-EXFIL-03 | 敏感目录加上传 | 同时访问 <code>.ssh</code>、<code>.aws</code>、<code>.gnupg</code>、<code>.kube</code>、<code>.config/gcloud</code>、<code>.npmrc</code>、<code>.pypirc</code> 与网络上传能力 | HIGH |

执行来源规定的两遍扫描：第一遍标记敏感目录访问和上传功能；第二遍检查组合模式。

### C.11 PersistenceDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-PERSIST-01 | crontab 修改 | <code>crontab -e</code>、<code>crontab -l</code> 等操作 | HIGH |
| SEC-PERSIST-02 | Cron 安装 | 写入 crontab 或 <code>/etc/cron.d/</code> | HIGH |
| SEC-PERSIST-03 | LaunchAgents/Daemons | 引用 <code>LaunchAgents</code>、<code>LaunchDaemons</code>、<code>.plist</code> | HIGH |
| SEC-PERSIST-04 | launchctl 加载 | <code>launchctl load</code> 或 <code>launchctl bootstrap</code> | HIGH |
| SEC-PERSIST-05 | systemd 启用 | <code>systemctl enable</code> 或 <code>systemctl start</code> | HIGH |
| SEC-PERSIST-06 | systemd 文件 | 创建 <code>/etc/systemd/system/*.service</code> | HIGH |
| SEC-PERSIST-07 | Windows 启动项 | 访问 <code>HKEY_...\Run</code> 或 <code>CurrentVersion\Run</code> | HIGH |
| SEC-PERSIST-08 | Shell 配置写入 | 写入 <code>.bashrc</code>、<code>.zshrc</code>、<code>.profile</code>、<code>.bash_profile</code> | HIGH |

### C.12 PrivilegeEscalationDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-PRIV-01 | sudo | 使用 <code>sudo</code> | HIGH |
| SEC-PRIV-02 | chmod 777 | 设置世界可读写执行权限 | HIGH |
| SEC-PRIV-03 | chmod +s | 设置 SUID/SGID 位 | HIGH |
| SEC-PRIV-04 | chmod 含 SUID | 权限模式含 4xxx 或 2xxx | HIGH |
| SEC-PRIV-05 | chown root | 将所有者改为 root | HIGH |
| SEC-PRIV-06 | setuid/setgid | 使用 <code>os.setuid()</code> 或 <code>os.setgid()</code> | HIGH |
| SEC-PRIV-07 | macOS 管理员组 | <code>dscl -append /Groups/admin</code> | HIGH |

该检测器跳过 <code>.md</code>、<code>.txt</code>、<code>.rst</code>、<code>.adoc</code>。

### C.13 SocialEngineeringDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-SOCIAL-01 | 双重扩展名 | 文件名含 <code>.docx.exe</code>、<code>.pdf.bat</code>、<code>.txt.cmd</code>、<code>.jpg.ps1</code> 等双重扩展名 | HIGH |
| SEC-SOCIAL-02 | 诱饵文件名 | <code>wallet</code>、<code>airdrop</code>、<code>claim</code>、<code>reward</code>、<code>metamask</code>、<code>seed</code>、<code>recovery</code>、<code>invoice</code>、<code>urgent</code>、<code>important</code>、<code>password</code>、<code>credentials</code>、<code>secret</code>、<code>private-key</code> 等 | MEDIUM |
| SEC-SOCIAL-03 | 钓鱼 URL | URL 含 <code>secure-login</code>、<code>verify</code>、<code>signin</code>、<code>login</code>、<code>account</code>、<code>recover</code>、<code>restore</code>、<code>confirm</code>、<code>update</code>、<code>validate</code>、<code>check</code>、<code>auth</code>、<code>reset-password</code>、<code>unlock</code> 等 | MEDIUM |
| SEC-SOCIAL-04 | 假冒技术支持 | <code>Microsoft Support</code>、<code>Apple Support</code>、<code>Google Support</code>、<code>tech support</code>、<code>customer support</code>、<code>help desk</code>、<code>IT support</code>、<code>please call</code>、<code>call 1-xxx-xxx-xxxx</code>、<code>toll free</code>、<code>1-800</code>、<code>1-888</code>、<code>urgent</code>、<code>security alert/notice/update</code>、<code>your account has been suspended/locked</code>、<code>verify your identity</code>、<code>click here to</code> 等 | MEDIUM |
| SEC-SOCIAL-05 | Crypto/Wallet 钓鱼 | <code>crypto-wallet</code>、<code>airdrop</code>、<code>free-token</code>、<code>security-update</code>、<code>urgent-fix</code>、<code>claim-reward</code>、<code>bonus-token</code>、<code>wallet-connect</code>、<code>seed-phrase</code>、<code>private-key-recovery</code>、<code>metamask-fix</code>、<code>connect wallet</code>、<code>claim your</code>、<code>free crypto/token/coin</code>、<code>win bitcoin/ethereum/crypto</code>、<code>limited time offer</code>、<code>exclusive airdrop</code> 等 | LOW |

### C.14 NetworkDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-NET-01 | Python socket | <code>socket.socket()</code>、<code>socket.connect()</code>、<code>socket.create_connection()</code> | MEDIUM |
| SEC-NET-02 | Python http.client | <code>HTTPConnection</code>、<code>HTTPSConnection</code> | MEDIUM |
| SEC-NET-03 | Python urllib | <code>urllib.request.urlopen()</code>、<code>urllib.request.Request()</code> | MEDIUM |
| SEC-NET-04 | Python requests | <code>requests.get/post/put/delete/patch/head()</code> | MEDIUM |
| SEC-NET-05 | JavaScript fetch | 使用 <code>fetch()</code> | MEDIUM |
| SEC-NET-06 | XMLHttpRequest | 使用 <code>XMLHttpRequest</code> | MEDIUM |
| SEC-NET-07 | axios | <code>axios.get/post/put/delete/patch()</code> | MEDIUM |
| SEC-NET-08 | curl | 使用 <code>curl</code> | MEDIUM |
| SEC-NET-09 | wget | 使用 <code>wget</code> | MEDIUM |
| SEC-NET-10 | Node.js net | <code>net.createConnection()</code> 或 <code>require('net')</code> | MEDIUM |

### C.15 SupplyChainDetector

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-SUPPLY-01 | 可疑 npm 安装 | 包名含 <code>malicious</code>、<code>evil</code>、<code>suspicious</code>、<code>exploit</code>、<code>payload</code>、<code>backdoor</code>、<code>hack</code>、<code>inject</code>、<code>trojan</code>、<code>virus</code>、<code>ransom</code>、<code>steal</code>、<code>leak</code>、<code>drop</code>、<code>crack</code>、<code>rootkit</code>、<code>botnet</code> 等 | CRITICAL |
| SEC-SUPPLY-02 | 可疑 pip 安装 | <code>pip install/download</code> 的包名含 <code>malicious</code>、<code>evil</code>、<code>suspicious</code>、<code>exploit</code>、<code>payload</code>、<code>backdoor</code>、<code>hack</code>、<code>inject</code>、<code>trojan</code>、<code>ransom</code> 等 | CRITICAL |
| SEC-SUPPLY-03 | 可疑 Docker 镜像 | <code>docker pull</code> 镜像名含 <code>malicious</code>、<code>evil</code>、<code>suspicious</code>、<code>exploit</code>、<code>payload</code>、<code>backdoor</code>、<code>hack</code>、<code>inject</code>、<code>trojan</code>、<code>virus</code>、<code>ransom</code> 等 | CRITICAL |
| SEC-SUPPLY-04 | 非官方 Docker 镜像 | 从非官方域名或私有仓库拉取 | HIGH |
| SEC-SUPPLY-05 | pip 额外索引 | 使用 <code>--extra-index-url</code> 或 <code>--index-url</code> | HIGH |
| SEC-SUPPLY-06 | 可疑 gem 安装 | 包名含 <code>malicious</code>、<code>evil</code>、<code>suspicious</code>、<code>exploit</code>、<code>payload</code>、<code>backdoor</code> 等 | CRITICAL |
| SEC-SUPPLY-07 | package.json 钩子 | <code>preinstall</code>、<code>install</code>、<code>postinstall</code>、<code>prepublish</code>、<code>prepare</code>、<code>prebuild</code>、<code>postbuild</code> | HIGH/CRITICAL |
| SEC-SUPPLY-08 | 钩子可疑命令 | 钩子含 <code>curl</code>、<code>wget</code>、<code>bash</code>、<code>sh</code>、<code>python</code>、<code>node -e</code>、<code>eval</code>、<code>powershell</code>、<code>cmd</code>、<code>/tmp/</code>、<code>$env</code> 等 | CRITICAL |
| SEC-SUPPLY-09 | setup.py cmdclass | <code>setup.py</code> 使用 <code>cmdclass</code> | HIGH/CRITICAL |

对 <code>package.json</code> 解析 JSON 后检查生命周期钩子和包名；对 <code>setup.py</code> 检查 <code>cmdclass</code> 中的可疑关键词。

### C.16 IOCDetector

可执行扩展名：

~~~text
.exe, .msi, .bat, .cmd, .ps1, .sh, .bash, .zsh, .js, .vbs,
.jar, .dll, .so, .dylib, .bin
~~~

恶意关键词：

~~~text
malicious, evil, suspicious, phishing, malware, attack, exploit,
payload, hacker, hack, backdoor, ransom, steal, inject, trojan,
virus, botnet, exfil, dropship, darkweb, leak, dumped, crack
~~~

| 规则 ID | 检测项 | 来源规则 | 严重度 |
|---|---|---|---|
| SEC-IOC-01 | 可疑 TLD 加可执行下载 | URL 域名含内置可疑 TLD 且指向列表中的可执行文件 | HIGH |
| SEC-IOC-02 | 可疑 TLD | URL 域名含内置可疑 TLD | MEDIUM |
| SEC-IOC-03 | 恶意关键词加可执行下载 | URL 域名含恶意关键词且指向列表中的可执行文件 | HIGH |
| SEC-IOC-04 | 恶意关键词域名 | URL 域名含恶意关键词 | MEDIUM |
| SEC-IOC-05 | 独立域名可疑 TLD | 非 URL 的独立域名含可疑 TLD | MEDIUM/HIGH |
| SEC-IOC-06 | 已知恶意 IP | IP 匹配外部威胁情报数据库 | CRITICAL |
| SEC-IOC-07 | 已知恶意 URL | URL 匹配外部威胁情报数据库 | CRITICAL |

来源没有定义威胁情报数据源或查询 Interface，因此 <code>SEC-IOC-06</code> 和 <code>SEC-IOC-07</code> 在当前设计中固定为 <code>NOT_EVALUATED</code>；Tool 不自行联网查询。

内置可疑 TLD：

~~~text
.xyz, .top, .club, .work, .online, .site, .biz, .info, .ru, .su,
.to, .cc, .tk, .ml, .ga, .cf, .gq, .pw, .ws, .onion, .zip, .mov
~~~

## 附录 D：已知来源限制

以下 <code>SOURCE_ISSUE</code> 不改变规则行为：

| 编号 | 来源限制 | 处理 |
|---|---|---|
| SI-01 | SRC-PKG-DOCX 的 ZIP 基础校验片段不完整，而 SRC-PKG-MD 内容完整。 | 以内容完整的 SRC-PKG-MD 为依据；不从残缺片段推导规则。 |
| SI-02 | <code>skill.upload.max-zip-bytes</code>、扩展名白名单和 <code>name</code> 正则没有给出最终配置值。 | 通过 <code>InspectionPolicy</code> 显式提供；缺失时返回 <code>ERROR</code>，不硬编码替代值。 |
| SI-03 | “文本看起来像二进制”的具体算法没有写明。 | PKG-11 的该部分标记为 <code>NOT_EVALUATED</code>；不自创算法。 |
| SI-04 | 包扫描危险内容只检查前 64KB，可能漏掉后续内容。 | 保持 64KB，不扩展为全文扫描。 |
| SI-05 | SVG 当前默认通过，没有魔数或 XML 安全校验。 | 保持默认通过。 |
| SI-06 | <code>__MACOSX/**</code> 忽略规则与 <code>__macosx</code> 高风险片段的大小写关系未说明。 | 按来源字面值区分大小写，不增加折叠规则。 |
| SI-07 | description、正文质量、SQLi/XSS 数据流、依赖范围、内容合规和知识产权要求缺少确定性检测方法。 | 返回 <code>NOT_EVALUATED</code>，不使用自创启发式规则。 |
| SI-08 | 部分安全项使用“等”，且原文未给出完整正则、边界、大小写和适用文件范围。 | 只执行明确列出的条件；缺失范围记录为限制，不扩写关键词。 |
| SI-09 | <code>HIGH/CRITICAL</code>、<code>MEDIUM/HIGH</code> 没有单一严重度选择规则；严重度与安全扫描 <code>passed</code> 的映射也未说明。 | 原样保留来源严重度；finding 进入 <code>REVIEW_REQUIRED</code>，不归一化严重度。 |
| SI-10 | PrivilegeEscalationDetector 跳过 Markdown 等文档，可能漏掉文档中的命令。 | 保持跳过规则。 |
| SI-11 | <code>df.info()</code> 可能被 IOC 的 <code>.info</code> 规则当作域名。 | 该样例只记录潜在误报，不增加成员调用豁免。 |
| SI-12 | <code>user: zh</code> 可能被用户名规则命中。 | 该样例只记录潜在误报，不增加 Markdown 或语言代码豁免。 |
| SI-13 | <code>writer.encrypt("userpassword", "ownerpassword")</code> 不符合窄版 <code>password=</code> 条件，可能漏报。 | 不增加调用语义规则。 |
| SI-14 | 可疑 TLD 列表包含可合法使用的 TLD，单独命中只能表达来源定义的可疑性。 | 保留原严重度，不升级为已知恶意。 |
| SI-15 | 已知恶意 IP/URL 依赖外部数据库，但来源没有定义数据源、版本和不可用行为。 | <code>SEC-IOC-06</code> 和 <code>SEC-IOC-07</code> 返回 <code>NOT_EVALUATED</code>；Tool 不自行查询公网。 |
