# Skill 质量保证设计文档

| 项目 | 内容 |
|---|---|
| 文档状态 | Final |
| 生效日期 | 2026-08-19 |
| 设计对象 | Skill 质量保证 Module |
| 接入方式 | MCP Tool |
| MCP Tool | <code>scan_skill_quality</code> |
| 输入范围 | Skill ZIP 上传包 |
| 目标读者 | Skill 平台研发、安全研发、测试、运维与审核人员 |

## 1. 设计结论

<code>SkillQualityAssurance</code> 是独立业务 Module；MCP Adapter 只负责协议输入、上传句柄解析和结果封装。

Module 复用现有包扫描和外部安全扫描，并报告可确定性判断的建设规范；其余规范返回 <code>NOT_EVALUATED</code>。Module 不执行或修改上传包，也不改变现有规则和上传流程。

## 2. 设计范围与约束

### 2.1 来源文档

| 来源编号 | 文档 | 用途 |
|---|---|---|
| SRC-PKG-MD | <code>skill-upload-package-scan-rules(1).md</code> | 包扫描 1—22 节、错误码、扫描产物和上传顺序的完整依据。 |
| SRC-SPEC | <code>原版-skills建设规范_0609(3).docx</code> | Skill 结构、描述、正文、代码、依赖、附件和内容规范。 |
| SRC-PKG-DOCX | <code>Skill 上传包扫描规则说明.docx</code> | 与 SRC-PKG-MD 交叉核对；不从缺失或残缺片段推导新规则。 |
| SRC-SEC | <code>0720扫描规则说明.docx</code> | 当前启用的 15 类安全检测器、检测项、严重度和跳过规则。 |

包扫描的配置值以平台运行时配置为准。外部安全扫描的具体匹配实现和 <code>passed</code> 结果以现有安全扫描器为准。质量保证 Module 和 MCP Adapter 均不替代这两项现有实现重新解释规则。

### 2.2 内容分类

| 分类 | 含义 | 是否改变扫描结果 |
|---|---|---|
| <code>SOURCE_RULE</code> | 来源文档明确写出的检测、校验、跳过、严重度或流程规则。 | 是，严格按来源执行。 |
| <code>SOURCE_ISSUE</code> | 来源规则存在缺失、歧义、可能误报或可能漏报。 | 否，只记录限制。 |
| <code>IMPLEMENTATION_ONLY</code> | Module 封装、MCP 接入、版本记录、脱敏、审计和错误表达。 | 否，不得新增、删除、升级或降级命中。 |
| <code>PROPOSED_CHANGE</code> | 对来源规则的候选修改。 | 否，未启用。 |

只有 <code>SOURCE_RULE</code> 可以影响规则命中和原有上传结果。<code>SOURCE_ISSUE</code> 不得被实现为白名单、例外、补充正则或严重度调整。

### 2.3 明确不在范围内

- RAR、目录和单个 <code>SKILL.md</code> 输入。
- 加密 ZIP、符号链接、硬链接、设备文件和嵌套压缩包的新增拒绝规则。
- Unicode 等价路径和大小写折叠冲突的新增拒绝规则。
- SVG XML 解析；来源规则规定 SVG 当前不做魔数校验，默认通过。
- YAML 重复键、不安全类型、Markdown 正文非空和本地引用存在性的新增阻断。
- 将包扫描的 64KB 样本规则扩展为全文扫描。
- AST、代码围栏语义、上下文豁免或语义补漏。
- 把安全严重度自行转换为 <code>PASS</code>、<code>REVIEW</code> 或 <code>REJECT</code>。
- 恶意文件、YARA、杀毒、大模型、SBOM、CVE、签名、内容合规和动态沙箱扫描。
- 自动修复和例外审批。

规范性规则明细见附录 A—D。

## 3. 质量保证 Module 与 MCP Adapter

### 3.1 结构

~~~text
MCP Client
    │
    ▼
MCP Adapter: scan_skill_quality
    ├── 校验 MCP 输入
    ├── Upload Resolver: uploadUri -> SkillPackageInput
    │
    ▼
SkillQualityAssurance.scan(input) -> QualityReport
    ├── Existing Package Scanner Adapter
    ├── Specification Checker
    ├── Existing Security Scanner Adapter
    ├── Existing Security Result Store Adapter
    └── Report Builder
    │
    ▼
MCP Adapter: QualityReport -> structuredContent
~~~

外部 seam 位于 MCP Adapter 与质量保证 Module 之间，质量保证知识集中在 Module 内。

### 3.2 质量保证 Module Interface

Module 只暴露一个操作：

~~~text
scan(input: SkillPackageInput) -> QualityReport
~~~

<code>SkillPackageInput</code> 是协议无关的输入：

~~~text
SkillPackageInput
  originalFileName: string
  content: ReadableBinary
~~~

Interface 不变量：

- <code>originalFileName</code> 和 <code>content</code> 来自同一个上传目标，<code>content</code> 只读。
- Module 自行执行文件非空、ZIP 扩展名、ZIP 魔数和可打开性检查。
- Interface 不包含 <code>uploadUri</code>、<code>requestId</code>、MCP Schema 或 Tool 错误。
- Interface 不提供规则开关、阈值覆盖、严重度覆盖、策略选择或忽略规则参数。

### 3.3 Module 内部职责

- Existing Package Scanner Adapter：复用现有包扫描行为。
- Specification Checker：执行附录 B 中可确定性判断的建设规范检查。
- Existing Security Scanner Adapter：复用现有安全扫描行为和 <code>passed</code>。
- Existing Security Result Store Adapter：保持 <code>t_skill_security_scan</code> 的原保存行为。
- Report Builder：生成协议无关的 <code>QualityReport</code>。

### 3.4 MCP Adapter 职责

- 将 <code>uploadUri</code> 解析为 <code>SkillPackageInput</code> 后调用 Module；<code>requestId</code> 不进入 Module。
- 将 <code>QualityReport</code> 放入 <code>structuredContent.result</code>，协议错误进入 <code>toolErrors</code>；不执行或修改规则结果。

## 4. MCP Adapter 契约

### 4.1 Tool 元数据

~~~json
{
  "name": "scan_skill_quality",
  "title": "Skill 质量与安全扫描",
  "description": "通过 MCP 提供 Skill ZIP 上传包质量保证能力，返回质量报告。不会执行或修改上传包。",
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
  "required": ["uploadUri"],
  "properties": {
    "uploadUri": {
      "type": "string",
      "pattern": "^upload://[A-Za-z0-9._-]+$",
      "description": "平台生成的不可伪造上传句柄。"
    },
    "requestId": {
      "type": "string",
      "maxLength": 128
    }
  }
}
~~~

<code>uploadUri</code> 只能解析到平台上传临时区中的一个文件；Upload Resolver 提供对应的原始文件名和字节流。

### 4.3 输出 Envelope

~~~json
{
  "requestId": "optional-client-id",
  "toolStatus": "COMPLETED",
  "target": {
    "uploadUri": "upload://12345"
  },
  "result": {
    "scanId": "sq_01...",
    "status": "COMPLETED"
  },
  "toolErrors": []
}
~~~

输出语义：

- <code>toolStatus=COMPLETED</code> 表示 Adapter 已取得 <code>QualityReport</code>，不表示 Skill 通过扫描。
- 参数、句柄解析或 Adapter 执行失败时，<code>toolStatus=TOOL_ERROR</code>、<code>result=null</code>，错误进入 <code>toolErrors</code>。
- <code>requestId</code> 和 <code>target.uploadUri</code> 仅用于请求关联；<code>result</code> 原样承载 <code>QualityReport</code>。

## 5. QualityReport 结果模型

### 5.1 结构

~~~json
{
  "scanId": "sq_01...",
  "status": "COMPLETED",
  "target": {
    "originalFileName": "pdf.zip",
    "sha256": "..."
  },
  "versions": {
    "moduleVersion": "1.0.0",
    "packageScannerVersion": "...",
    "securityScannerVersion": "...",
    "sourceBundleId": "..."
  },
  "coverage": {
    "packageScan": "ENABLED",
    "specificationCheck": "PARTIAL",
    "externalSecurityScan": "ENABLED",
    "malwareFileScan": "DISABLED_BY_SOURCE",
    "llmScan": "DISABLED_BY_SOURCE"
  },
  "packageScan": {
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
  "specificationChecks": [
    {
      "ruleId": "SPEC-ZIP-NAME",
      "status": "PASS",
      "sourceType": "SOURCE_RULE",
      "sourceRef": "SRC-SPEC"
    },
    {
      "ruleId": "SPEC-DESCRIPTION-QUALITY",
      "status": "NOT_EVALUATED",
      "sourceType": "SOURCE_RULE",
      "sourceRef": "SRC-SPEC"
    }
  ],
  "securityScan": {
    "invoked": true,
    "passed": true,
    "findings": []
  },
  "uploadDecision": {
    "eligible": true,
    "basis": "EXISTING_UPLOAD_FLOW"
  },
  "sourceIssues": [],
  "scanErrors": []
}
~~~

### 5.2 结果语义

- <code>status=COMPLETED</code> 表示扫描流程已完成，包括包扫描失败、安全扫描失败或规范检查 <code>FAIL</code>；流程未完成时返回 <code>SCAN_ERROR</code>，错误进入 <code>scanErrors</code>。
- <code>packageScan</code> 完整保留现有包扫描产物。
- <code>securityScan.passed</code> 原样采用外部安全扫描器结果；Module 和 MCP Adapter 均不根据严重度重新计算。
- <code>uploadDecision.eligible</code> 只映射现有上传流程：
  - 包扫描失败：<code>false</code>。
  - 包扫描通过且安全扫描失败：<code>false</code>。
  - 包扫描和安全扫描均通过：<code>true</code>。
  - Module 未完成且来源未定义处理方式：<code>null</code>。
- <code>specificationChecks</code> 不改变现有上传决定；它独立表达建设规范符合情况。
- <code>SOURCE_ISSUE</code> 只出现在 <code>sourceIssues</code>，不得混入安全 findings。
- <code>QualityReport</code> 不包含 <code>uploadUri</code>、<code>requestId</code>、<code>toolStatus</code> 或 <code>toolErrors</code>。

安全 finding 保留来源检测项、来源严重度、位置和外部扫描器标识。证据可脱敏，但不得因脱敏改变是否命中。

~~~json
{
  "ruleId": "SEC-SECRET-08",
  "detector": "SecretsDetector",
  "detectionItem": "硬编码密码",
  "sourceSeverity": "HIGH",
  "path": "SKILL.md",
  "line": 42,
  "evidenceRedacted": "password=[REDACTED]",
  "sourceRef": "SRC-SEC"
}
~~~

## 6. 扫描顺序

1. MCP Adapter 校验输入，将 <code>uploadUri</code> 解析为 <code>SkillPackageInput</code>。
2. Module 执行现有包扫描；失败时返回报告，不调用外部安全扫描或入库。
3. 包扫描通过后，Module 执行建设规范检查和现有外部安全扫描，并将安全扫描结果写入 <code>t_skill_security_scan</code>。
4. 现有平台根据安全扫描结果继续入库，或返回失败结果且不入库。
5. Module 返回 <code>QualityReport</code>，MCP Adapter 将其放入输出 Envelope。

## 7. 实施约束（IMPLEMENTATION_ONLY）

- Module 只读上传包，不执行其中的脚本、命令或安装动作。
- <code>QualityReport</code> 记录目标 SHA-256、Module/扫描器版本和来源包标识；稳定规则 ID 只用于来源追溯。
- 报告和日志中的密钥、密码及 Token 必须脱敏，且不改变规则命中。
- MCP Adapter 不持久化扫描结果。

## 8. 测试设计

### 8.1 质量保证 Module Interface

- 校验 <code>SkillPackageInput</code>、<code>QualityReport</code> 及其传输协议隔离约束。
- 验证 Interface 不能关闭检测器、修改阈值或覆盖严重度。

### 8.2 MCP Adapter 契约

- 校验输入 Schema、<code>uploadUri</code> 到 <code>SkillPackageInput</code> 的映射和 <code>QualityReport</code> 的无损封装。
- 验证 Adapter 错误进入 <code>toolErrors</code>，Module 错误进入 <code>scanErrors</code>。

### 8.3 包扫描等价性

- 为 SRC-PKG-MD 的 1—22 节建立测试映射。
- 使用相同 ZIP 同时调用现有包扫描器和质量保证 Module，<code>packageScan</code> 结果必须等价。
- 覆盖两种合法包根、缺失 <code>SKILL.md</code>、包根外路径、路径穿越、重复路径、大小限制、白名单、危险路径、文本/图片类型、危险内容和 front matter。
- 验证 macOS 垃圾文件不参与根判断、统计、重复检查、持久化和安全扫描。
- 验证显式目录、隐式目录、文件类型、Content-Type 和 searchable 映射。

### 8.4 建设规范检查

- ZIP 名与 <code>name</code> 原值一致和不一致。
- 附件总大小在 50MB 边界内外。
- 复用包扫描的 <code>SKILL.md</code>、<code>name</code> 和 <code>description</code> 结果。
- 所有缺少确定性方法的规范固定返回 <code>NOT_EVALUATED</code>，不得由测试引入隐式启发式判断。

### 8.5 安全扫描等价性

- 15 类检测器的 98 个检测项各有命中样例，并覆盖原文跳过规则。
- 相同包在现有外部安全扫描器和质量保证 Module 中的 <code>passed</code>、finding 和来源严重度必须等价。
- <code>df.info()</code>、<code>user: zh</code> 和 <code>writer.encrypt(...)</code> 测试记录现有扫描器实际行为，不把期望的误报修复或漏报补偿写入当前规则。
- 原始密码、密钥和 Token 不出现在 <code>QualityReport</code>、MCP 响应或日志中。

### 8.6 流程

- 包扫描失败后不调用外部安全扫描。
- 包扫描通过后保存外部安全扫描结果。
- 两层扫描的通过/失败与现有上传入库流程一致。
- Module 错误不产生虚假的 <code>eligible=true</code>。
- MCP Adapter 错误不调用质量保证 Module，且不返回伪造的 <code>QualityReport</code>。

## 9. 验收标准

- Module 与 MCP Adapter 符合第 3—5 节 Interface 和契约。
- 22 节包规则、12 项建设规范、98 项安全规则及 15 项来源限制均可追溯。
- 扫描结果、短路行为和 <code>t_skill_security_scan</code> 保存顺序与现有实现一致。
- 第 2.3 节范围外能力未实现；恶意文件检测和大模型扫描保持未启用。
- <code>SOURCE_ISSUE</code> 不改变规则行为，敏感证据完成脱敏。

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
- ZIP 原文件大小上限由 <code>skill.upload.max-zip-bytes</code> 读取。
- 扩展名白名单从平台配置读取；文档未列出的值不得自行补入。
- <code>properties</code> 只有在平台配置中存在时才允许，不能因代码常量存在而放行。

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
- <code>name</code> 使用项目配置正则。

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
| SPEC-NAME-STYLE | <code>name</code> 通常使用小写字母和连字符。 | 保留为来源建议；不替代平台名称正则，不单独阻断。 |
| SPEC-DESCRIPTION-QUALITY | <code>description</code> 用 1—2 句话自包含地说明功能、场景和触发条件，避免歧义。 | <code>NOT_EVALUATED</code>；原文未给出确定性算法，且大模型扫描未启用。 |
| SPEC-BODY | 正文按任务灵活组织，不强制模板；逻辑或步骤应清晰、闭环并覆盖正常与异常场景。 | <code>NOT_EVALUATED</code>；不增加正文非空、章节或关键词规则。 |
| SPEC-RESOURCE-SEPARATION | 长文档、脚本和资源与正文分离。 | <code>NOT_EVALUATED</code>；不增加目录或引用规则。 |
| SPEC-LANGUAGE | 表述简洁，无模糊词汇。 | <code>NOT_EVALUATED</code>。 |
| SPEC-CODE-SAFETY | 不得含恶意或攻击性内容，包括 SQL 注入、XSS；不得用未验证输入构造 SQL 或 HTML。 | 安全扫描结果原样报告；来源未定义的 SQLi、XSS 和数据流分析部分标记 <code>NOT_EVALUATED</code>。 |
| SPEC-DEPENDENCY | 不应依赖沙箱默认镜像范围外的安装包。 | 未取得默认镜像依赖清单时为 <code>NOT_EVALUATED</code>，不得自行建立清单。 |
| SPEC-ATTACHMENT-SIZE | 除 <code>SKILL.md</code> 外的附件总大小不超过 50MB。 | 对标准化业务文件求和并排除 <code>SKILL.md</code>；结果为 <code>PASS</code> 或 <code>FAIL</code>。该规范结果不改写包扫描的 200MB 上限。 |
| SPEC-CONTENT | 不得包含违法、违规、色情、暴力等不良信息。 | <code>NOT_EVALUATED</code>；来源未提供检测器。 |
| SPEC-IP | 避免未经授权的图片、音乐等知识产权内容。 | <code>NOT_EVALUATED</code>；来源未提供检测器。 |

规范检查状态：

- <code>PASS</code>：确定性要求满足。
- <code>FAIL</code>：确定性要求不满足。
- <code>NOT_EVALUATED</code>：来源有要求，但没有足够规则或已启用能力自动判断。

不使用综合分数，也不把 <code>NOT_EVALUATED</code> 转换成人工复核或上传阻断。

## 附录 C：外部安全扫描规则

### C.1 通用行为

- 质量保证 Module 通过 Existing Security Scanner Adapter 复用现有外部安全扫描器；Module 与 MCP Adapter 均不重写正则、匹配边界、大小写规则或文件范围。
- finding 保留 SRC-SEC 中的严重度；<code>HIGH/CRITICAL</code> 和 <code>MEDIUM/HIGH</code> 等原文复合值不得由 Module 或 MCP Adapter 自行归一化。
- 所有检测器默认跳过 <code>.git</code>、<code>__pycache__</code>、<code>.venv</code> 和 <code>node_modules</code> 目录。
- 恶意文件检测和大模型扫描保持未启用。
- 安全扫描器的 <code>passed</code> 由 Module 原样接收，并由 MCP Adapter 原样封装；两者都不从 finding 严重度重新推导。

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

内置可疑 TLD：

~~~text
.xyz, .top, .club, .work, .online, .site, .biz, .info, .ru, .su,
.to, .cc, .tk, .ml, .ga, .cf, .gq, .pw, .ws, .onion, .zip, .mov
~~~

## 附录 D：已知来源限制

以下 <code>SOURCE_ISSUE</code> 不改变规则行为：

| 编号 | 来源限制 | 处理 |
|---|---|---|
| SI-01 | SRC-PKG-DOCX 的 ZIP 基础校验片段不完整，而 SRC-PKG-MD 内容完整。 | 包扫描复用现有平台实现；不从残缺片段推导规则。 |
| SI-02 | <code>skill.upload.max-zip-bytes</code>、扩展名白名单和 <code>name</code> 正则没有给出最终配置值。 | 运行时读取平台配置并记录配置摘要；不硬编码替代值。 |
| SI-03 | “文本看起来像二进制”的具体算法没有写明。 | 复用现有包扫描器，不重新定义算法。 |
| SI-04 | 包扫描危险内容只检查前 64KB，可能漏掉后续内容。 | 保持 64KB，不扩展为全文扫描。 |
| SI-05 | SVG 当前默认通过，没有魔数或 XML 安全校验。 | 保持默认通过。 |
| SI-06 | <code>__MACOSX/**</code> 忽略规则与 <code>__macosx</code> 高风险片段的大小写关系未说明。 | 保持现有实现，不增加大小写规则。 |
| SI-07 | description、正文质量、SQLi/XSS 数据流、依赖范围、内容合规和知识产权要求缺少确定性检测方法。 | 返回 <code>NOT_EVALUATED</code>，不使用自创启发式规则。 |
| SI-08 | 部分安全项使用“等”，且原文未给出完整正则、边界、大小写和适用文件范围。 | 复用现有外部扫描器，不扩写关键词。 |
| SI-09 | <code>HIGH/CRITICAL</code>、<code>MEDIUM/HIGH</code> 没有单一严重度选择规则；严重度与安全扫描 <code>passed</code> 的映射也未说明。 | 原样保留来源或扫描器结果；Module 与 MCP Adapter 均不归一化、不裁决。 |
| SI-10 | PrivilegeEscalationDetector 跳过 Markdown 等文档，可能漏掉文档中的命令。 | 保持跳过规则。 |
| SI-11 | <code>df.info()</code> 可能被 IOC 的 <code>.info</code> 规则当作域名。 | 该样例只记录潜在误报，不增加成员调用豁免。 |
| SI-12 | <code>user: zh</code> 可能被用户名规则命中。 | 该样例只记录潜在误报，不增加 Markdown 或语言代码豁免。 |
| SI-13 | <code>writer.encrypt("userpassword", "ownerpassword")</code> 不符合窄版 <code>password=</code> 条件，可能漏报。 | 不增加调用语义规则。 |
| SI-14 | 可疑 TLD 列表包含可合法使用的 TLD，单独命中只能表达来源定义的可疑性。 | 保留原严重度，不升级为已知恶意。 |
| SI-15 | 已知恶意 IP/URL 依赖外部数据库，但来源没有定义数据源、版本和不可用行为。 | 原样使用现有外部扫描器结果；Module 不自行查询公网或定义陈旧策略，MCP Adapter 不承担威胁情报职责。 |
