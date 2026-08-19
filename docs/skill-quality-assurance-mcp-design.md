# Skill 质量保证 MCP Tool 设计文档

| 项目 | 内容 |
|---|---|
| 状态 | Draft |
| 日期 | 2026-08-19 |
| 目标读者 | Skill 平台研发、安全研发、测试、运维与审核人员 |
| 建议工具名 | `scan_skill_quality` |
| 默认策略 | `enterprise-intranet-v1` |

## 1. 结论

将 Skill 质量保证封装为一个 MCP Tool 是可行的。设计上只暴露一个稳定的外部接口，把包结构校验、元数据校验、内容质量检查、安全检测、上下文判定和企业策略裁决收进一个深模块。

该工具默认只读，不执行 Skill 中的脚本，不自动修复文件，不直接发布 Skill。生产上传链路采用失败关闭策略：结构扫描未通过、存在确认的 CRITICAL/HIGH 风险或扫描器自身未能完成时，不得入库。

## 2. 设计依据

本文综合以下资料：

1. `C:\Users\simon\Documents\nari\skill-upload-package-scan-rules(1).md`
2. `C:\Users\simon\Documents\nari\原版-skills建设规范_0609(3).docx`
3. `C:\Users\simon\Documents\nari\Skill 上传包扫描规则说明.docx`
4. `C:\Users\simon\Documents\nari\0720扫描规则说明.docx`
5. MCP Tools 官方规范：<https://modelcontextprotocol.io/specification/2025-06-18/server/tools>

资料存在冲突时采用以下优先级：

1. 平台实际配置和生产安全策略；
2. 上传包扫描规则；
3. Skill 建设规范；
4. 文档中的示例值。

每次扫描必须在报告中记录 `policyVersion`、`rulesetVersion`、`engineVersion` 和配置摘要哈希，保证结果可复现、可审计。

## 3. 目标与非目标

### 3.1 目标

- 为上传前预检和平台正式上传提供同一套质量保证能力。
- 保持包扫描和安全扫描两层语义，同时通过一次 MCP 调用返回统一报告。
- 支持 ZIP 上传包、开发目录和单个 `SKILL.md` 三种扫描范围。
- 输出机器可判定、人员可解释的结构化发现和最终结论。
- 对密码、密钥等证据自动脱敏。
- 支持内网离线部署、规则版本化和离线威胁情报。
- 降低纯正则造成的误报，同时保留无法确认时的人工复核入口。

### 3.2 非目标

- 不执行 Skill、脚本、安装命令或网络请求。
- 不在首版中自动修改或重新打包 Skill。
- 不把一个综合分数作为唯一准入依据。
- 不以本工具替代杀毒、沙箱、人工审核、等保测评或内容合规审核。
- `UPLOAD_PACKAGE` 模式只接受 ZIP；RAR 不是平台上传格式。

## 4. 核心术语

| 术语 | 定义 |
|---|---|
| 上传包 | 用户提交的 ZIP 文件。 |
| 包根 | 根目录或唯一顶层目录中 `SKILL.md` 所在的逻辑根。 |
| 业务文件 | 标准化、剥离包根并排除系统垃圾文件后的文件。 |
| 包扫描 | ZIP、路径、大小、类型、根目录和 front matter 等确定性校验。 |
| 质量扫描 | description、指令完整性、依赖、资源引用和建设规范检查。 |
| 安全扫描 | 代码内容、危险行为、供应链和 IOC 检测。 |
| 发现 | 一条带位置、规则、严重度、置信度和处置建议的扫描结果。 |
| 策略 | 将发现转换为阻断、复核或放行结论的版本化规则集合。 |
| 规则集 | 检测器及其模式、阈值、白名单和上下文排除规则的版本化集合。 |

## 5. 关键规则冲突与裁决

| 主题 | 资料中的口径 | 设计裁决 |
|---|---|---|
| 附件大小 | 建设规范要求除 `SKILL.md` 外附件总计不超过 50MB；包扫描安全上限为解压后 200MB | 同时执行：200MB 是防解压炸弹硬上限，50MB 是 Skill 质量准入上限。 |
| 内容采样 | 包扫描只读取每个文件前 64KB | 包扫描保持 64KB 快速校验；安全扫描对允许的文本文件全文分块扫描。 |
| ZIP 名称 | 建设规范要求 ZIP 名与 Skill 名完全一致 | 生产策略默认阻断不一致；开发预检可给出明确修复提示。 |
| `name` 格式 | 建设规范建议小写字母和连字符；上传规则以项目配置正则为准 | 不在实现中硬编码，统一由策略配置提供正则。 |
| `version` | 上传规则禁止用户填写 | 只要 front matter 中存在非空 `version` 即阻断。 |
| 扩展名白名单 | 文档未完整展示，说明以配置为准 | 从平台配置加载；扫描报告记录白名单配置哈希。 |
| macOS 垃圾文件 | 上传规则明确忽略 | 不计数、不入库、不进入任何安全检测。 |
| 恶意文件与大模型扫描 | 0720 文档说明当前未启用 | 报告必须显示覆盖缺口；企业增强阶段通过 Adapter 启用，不能默认为已检测。 |

## 6. 模块设计

外部 seam 是 MCP Tool 的接口。调用者只需提供目标引用和扫描范围，复杂实现保留在 `SkillQualityScanner` 模块内部。

```text
MCP Client
    │
    ▼
MCP Adapter: scan_skill_quality
    │
    ▼
SkillQualityScanner.scan(request) -> ScanReport
    ├── Target Resolver
    ├── Safe Package Reader
    ├── Package Inspector
    ├── Metadata & Quality Linter
    ├── Security Detector Orchestrator
    ├── Context Adjudicator
    ├── Policy Engine
    └── Report Builder
```

`SkillQualityScanner` 是深模块：调用者不需要理解 ZIP 读取、规则顺序、去重、上下文判定、证据脱敏或结论计算。

### 6.1 外部接口

模块只提供一个主要操作：

```text
scan(request: ScanRequest) -> ScanReport
```

接口不允许调用者逐项开关安全检测，也不允许调用者降低阻断阈值。生产环境中的策略选择必须经过服务端授权。

### 6.2 内部 seams 与 Adapters

只在确实存在多种实现时设置内部 seam：

| Seam | Adapters | 用途 |
|---|---|---|
| Target Resolver | `UploadHandleAdapter`、`LocalFileAdapter` | 生产使用上传句柄；开发环境可使用受限本地路径。 |
| Package Reader | `ZipPackageAdapter`、`DirectoryAdapter`、`MarkdownAdapter` | 统一产出标准化业务文件流。 |
| Threat Intelligence | `OfflineThreatIntelAdapter`、测试 Fake | 查询内网 IOC 快照，禁止直接访问公网。 |
| Malware Scanner | `ClamAvYaraAdapter`、`DisabledAdapter` | 显式体现恶意文件扫描是否启用。 |
| Semantic Analyzer | `InternalModelAdapter`、`DisabledAdapter` | 可选质量语义检查，禁用时报告覆盖缺口。 |
| Report Store | `SqlReportStoreAdapter`、内存 Fake | 生产审计和测试隔离。 |

各检测器属于模块内部实现，不单独暴露为 MCP Tools，避免形成大量浅接口。

## 7. MCP Tool 接口

### 7.1 Tool 元数据

```json
{
  "name": "scan_skill_quality",
  "title": "Skill 质量与安全扫描",
  "description": "只读扫描 Skill 上传包、开发目录或单个 SKILL.md，返回结构、质量、安全和企业准入结论。不会执行或修改目标文件。",
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  }
}
```

当启用实时外部情报查询时，`openWorldHint` 应改为 `true`；企业内网默认使用版本化离线情报快照。

### 7.2 输入

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["targetUri"],
  "properties": {
    "targetUri": {
      "type": "string",
      "description": "生产使用 upload://<id>；开发环境可使用受白名单限制的 file URI。"
    },
    "scope": {
      "type": "string",
      "enum": ["AUTO", "UPLOAD_PACKAGE", "DIRECTORY", "SKILL_MD_ONLY"],
      "default": "AUTO"
    },
    "policyProfile": {
      "type": "string",
      "default": "enterprise-intranet-v1",
      "description": "服务端必须鉴权，调用者不得选择更宽松策略绕过门禁。"
    },
    "requestId": {
      "type": "string",
      "maxLength": 128
    }
  }
}
```

### 7.3 输入不变量

- `UPLOAD_PACKAGE` 只接受未加密 ZIP。
- `SKILL_MD_ONLY` 只读取指定 Markdown 文件，不读取同目录 ZIP 或其他文件。
- `AUTO` 根据受信任文件类型识别，不根据用户提供的扩展名直接决定。
- `file://` 仅在开发模式开放，且目标必须位于配置的允许根目录内。
- 生产模式优先使用不可伪造的 `upload://` 句柄，不接受任意 Windows/Linux 路径。
- 同一目标、相同规则集、策略、引擎和情报快照应产生确定性结果。

### 7.4 输出

MCP 返回 `structuredContent`，同时提供简短文本摘要以兼容只读取文本结果的客户端。

```json
{
  "scanId": "sq_01...",
  "requestId": "optional-client-id",
  "verdict": "REJECT",
  "target": {
    "uri": "upload://12345",
    "sha256": "...",
    "scope": "UPLOAD_PACKAGE"
  },
  "versions": {
    "engineVersion": "1.0.0",
    "rulesetVersion": "2026.08.1",
    "policyVersion": "enterprise-intranet-v1.0",
    "threatIntelSnapshot": "2026-08-19T00:00:00Z"
  },
  "coverage": {
    "package": "ENABLED",
    "quality": "ENABLED",
    "security": "ENABLED",
    "malware": "DISABLED",
    "semantic": "DISABLED",
    "threatIntel": "OFFLINE_SNAPSHOT"
  },
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 1,
    "blocking": 1,
    "needsReview": 2
  },
  "package": {
    "rootDir": "pdf",
    "fileCount": 4,
    "totalSizeBytes": 18020,
    "textType": "COMPOSITE_TEXT"
  },
  "findings": [
    {
      "ruleId": "SEC_SECRET_HARDCODED_PASSWORD",
      "source": "SECURITY",
      "category": "SECRETS",
      "severity": "HIGH",
      "confidence": "HIGH",
      "disposition": "CONFIRMED",
      "blocking": true,
      "location": {
        "path": "SKILL.md",
        "line": 231,
        "column": 6
      },
      "message": "发现硬编码密码",
      "evidenceRedacted": "--password=[REDACTED]",
      "remediation": "改为运行时安全输入、环境变量或企业密钥管理。",
      "fingerprint": "..."
    }
  ],
  "errors": [],
  "timingMs": 412
}
```

完整 `package` 域保留现有上传包扫描产物：`passed`、`fileCount`、`textType`、`totalSizeBytes`、`rootDir`、`metadata`、`entries`、`errors`、`warnings` 和 `details`。每个 `entries` 节点包含 `rawPath`、`normalizedPath`、`nodeType`、`nodeName`、`parentPath`、`pathDepth`、`sizeBytes`、`sha256`、`contentType`、`fileType` 和 `searchable`，供后续入库和文件树直接复用。

### 7.5 结论枚举

| Verdict | 含义 |
|---|---|
| `PASS` | 全部必需检查完成且没有阻断项。 |
| `PASS_WITH_WARNINGS` | 没有阻断项，但存在 LOW/INFO 或明确的非阻断提示。 |
| `REVIEW` | 存在无法自动确认的风险、情报不可用或语义质量问题，需要人工复核。 |
| `REJECT` | 结构不合法或存在策略规定的确认风险。 |
| `ERROR` | 扫描器未能完成，不能代表目标安全。生产上传必须失败关闭。 |

## 8. 扫描流程

```text
解析并授权 targetUri
  → 计算目标哈希
  → 安全读取 ZIP/目录/Markdown
  → 路径标准化与包根识别
  → 包结构、大小、类型和元数据扫描
  → 若结构阻断：构建 REJECT 报告并停止
  → 全文分块内容扫描
  → 质量规则扫描
  → 安全检测器扫描
  → 上下文判定与重复发现合并
  → 企业策略裁决
  → 脱敏并构建结构化报告
  → 持久化审计结果
```

包扫描和安全扫描仍保留独立结果域，以兼容现有上传链路中 `packageScan` 和 `t_skill_security_scan` 的语义。

## 9. 包扫描规则

### 9.1 ZIP 与资源限制

- 文件非空、扩展名为 `.zip`、文件头符合 ZIP 魔数且可以正常读取。
- 最大 ZIP 大小由 `skill.upload.max-zip-bytes` 提供。
- 业务文件最多 1000 个。
- 单个解压后文件最多 10MB。
- 解压后总大小最多 200MB。
- 附件质量上限：除 `SKILL.md` 外合计最多 50MB。
- 同时校验 ZIP entry 声明大小和实际读取大小。
- 默认拒绝加密 ZIP、符号链接、硬链接、设备文件和嵌套压缩包。
- 所有限制均在流式读取过程中执行，禁止先无界解压再统计。

### 9.2 路径安全

- 去掉开头 `./` 和目录末尾 `/`，统一使用 `/`。
- 禁止空路径、反斜杠、冒号、绝对路径、连续分隔符和 `..`。
- 检测标准化后重复路径、文件/目录冲突。
- 企业增强规则增加 Unicode 规范化冲突和大小写折叠冲突，防止跨平台覆盖。
- `.git`、`.svn`、`.hg`、`.ssh`、`node_modules`、`.idea`、`.vscode`、`.env` 等高风险路径直接拒绝。

### 9.3 包根与系统文件

- 支持根目录 `SKILL.md`。
- 支持唯一顶层目录中的 `SKILL.md`，后续剥离该前缀。
- 包根外普通文件忽略；包根外高风险路径仍阻断。
- `__MACOSX/**`、`.DS_Store`、`._*` 完全忽略，不计数、不持久化、不安全扫描。

### 9.4 文件类型

- 扩展名必须存在且命中平台白名单。
- 文本类文件样本不能表现为二进制。
- PNG、JPEG、GIF 校验魔数；SVG 需要 XML 安全解析，不能只按扩展名放行。
- 内容类型识别结果不得用于执行文件，只用于分类和报告。

### 9.5 基础危险内容

保留上传包扫描中的快速拦截：`rm -rf /`、下载管道执行、`nc -e`、`bash -i`、`/etc/passwd`、私钥头、AWS Secret 和 AKIA 格式。与安全扫描命中相同内容时，按 `fingerprint` 合并，不重复计数。

## 10. SKILL.md 与质量规则

### 10.1 确定性阻断规则

- 文件必须使用 UTF-8。
- 必须以 `---` 开始，并存在闭合 front matter。
- YAML 必须解析为 Map；禁止重复关键字段和不安全 YAML 类型。
- `name`、`description` 必填。
- `version` 不允许填写。
- `name` 必须满足平台配置正则。
- ZIP 文件名必须与 `name` 对应，比较规则由策略定义。
- front matter 与 Markdown 正文均不得为空。
- 正文引用的本地脚本、资源和文档必须存在于包根内。

### 10.2 质量告警规则

- `description` 应用 1–2 句话自包含地说明能力、输入/输出、适用场景和触发条件。
- 过于宽泛的描述，如“处理 PDF”“查询数据库”，标记 `QUALITY_DESCRIPTION_AMBIGUOUS` 并进入复核。
- 正文应包含可执行步骤、异常处理和结果要求，避免相互矛盾的指令。
- 长资料、脚本和资源应与 `SKILL.md` 分离，并通过相对路径引用。
- 依赖必须在平台沙箱允许范围内；临时安装命令进入供应链检测。
- 附件中的违法、不良内容和知识产权风险属于内容合规范围；在没有专用检测器时必须显示为覆盖缺口，不能宣称已通过。

### 10.3 密码使用规范

- 禁止在 Skill、示例代码和命令中写入真实或示例密码，如 `mypassword`、`12345678`。
- Python 交互场景使用 `getpass()`；自动化场景使用企业密钥管理或受控环境变量。
- 命令行工具优先通过标准输入或受保护的密码文件读取，避免把密码放入进程参数。
- 不要求用户在聊天消息中发送密码，不打印、不记录密码。

## 11. 安全检测规则

首版必须覆盖 0720 文档中的 15 类检测器：

| 组 | 检测器 |
|---|---|
| 代码内容 | Secrets、Injection、Base64、Obfuscation、HiddenChar、Entropy |
| 危险行为 | DownloadExec、CredentialTheft、Exfiltration、Persistence、PrivilegeEscalation、SocialEngineering、Network |
| 供应链 | SupplyChain、IOC |

### 11.1 扫描策略

- 对文本业务文件全文分块扫描，不只检查前 64KB。
- 检测 Markdown fenced code block 的语言，并在支持时使用 AST/语法分析。
- 规则必须有稳定 `ruleId`、严重度、适用文件类型、版本和测试样例。
- CRITICAL/HIGH 证据必须脱敏；原始秘密不得写入日志、数据库或 MCP 结果。
- 组合行为规则采用多遍扫描，例如“压缩 + 上传”“敏感目录 + 上传”。
- IOC 先做语法提取，再查内网情报快照；没有真实 URL/IP 时不调用情报 Adapter。

### 11.2 上下文误报控制

已知回归用例必须进入测试集：

| 内容 | 旧规则问题 | 新判定 |
|---|---|---|
| `df.info()` | 被当作 `.info` 可疑域名 | Python 成员调用，非域名。 |
| <code>user: &#96;zh&#96;</code> | 被当作硬编码用户名 | Markdown 自然语言中的语言代码。 |
| `--password=mypassword` | 命中硬编码密码 | 确认风险，即使是示例也应修复。 |
| `writer.encrypt("userpassword", "ownerpassword")` | 窄版 `password=` 规则可能漏报 | 通过调用语义识别为硬编码密码。 |

代码围栏中的内容不能因为“只是文档示例”而自动降级，因为 Skill 可能指导智能体实际执行该命令。上下文分析只用于提高置信度，不用于静默忽略高风险行为。

### 11.3 高熵内容

- 普通文本阈值：Shannon 熵大于 5.5、行长至少 100 字符。
- 中文/Markdown 阈值：大于 6.5。
- 跳过图片 data URI、锁文件完整性字段和明确哈希字段。
- 高熵只产生需要复核的线索；若同时匹配密钥格式或可疑解码行为，再提升严重度。

### 11.4 当前覆盖缺口

下列能力在来源文档中明确未启用或没有实现依据：

- 恶意文件、Office 宏、二进制和 YARA/杀毒扫描；
- 大模型语义扫描和提示词注入检测；
- 完整 SCA/SBOM、依赖 CVE、签名与来源证明；
- 违法、不良内容和知识产权自动判定；
- 动态沙箱执行。

报告必须逐项返回 `ENABLED`、`DISABLED`、`DEGRADED` 或 `NOT_APPLICABLE`，禁止用整体 `PASS` 掩盖覆盖缺口。

## 12. 企业策略裁决

默认 `enterprise-intranet-v1`：

| 条件 | 结论 |
|---|---|
| ZIP、路径、大小、类型、根目录或必需元数据错误 | `REJECT` |
| 确认的 CRITICAL/HIGH | `REJECT` |
| 确认的 MEDIUM | `REVIEW`；高安全环境可配置为 `REJECT` |
| LOW/INFO | `PASS_WITH_WARNINGS` |
| `LIKELY_FALSE_POSITIVE` | 不静默删除，保留发现并按策略进入复核或警告 |
| IOC 命中内网恶意库 | CRITICAL，`REJECT` |
| 需要 IOC 查询但情报库过期或不可用 | `REVIEW`；生产高安全环境失败关闭 |
| 扫描超时、崩溃、规则加载失败 | `ERROR`，生产上传失败关闭 |

例外必须由独立审批流程生成带到期时间的 `exceptionRef`。MCP 调用者不能在参数中直接传入“忽略规则”。

## 13. 安全与内网部署要求

### 13.1 文件系统和进程

- 生产仅解析 `upload://` 句柄；本地路径 Adapter 默认关闭。
- 扫描 Worker 使用非特权账户、只读源文件和独立临时目录。
- 禁止调用 shell 执行包内内容；压缩解析库不得自动运行钩子。
- 临时目录权限最小化，扫描完成后可靠清理。
- 设置 CPU、内存、文件数、解压比例、嵌套深度和总时间限制。
- 拒绝路径穿越、绝对路径、符号链接、硬链接、设备文件和 Unicode/case 冲突。

### 13.2 网络和情报

- 默认无公网出口。
- 威胁情报通过企业内网镜像更新，规则包和情报快照需要签名验证。
- 报告记录情报快照 ID、生成时间和过期状态。
- 网络异常不能被解释为“未发现恶意”。

### 13.3 数据保护与审计

- 日志和指标不包含文件正文、密码、Token 或完整本地路径。
- 证据片段限制长度并执行密钥脱敏。
- 审计记录至少包含请求主体、目标哈希、版本信息、结论、规则命中和例外引用。
- 扫描报告需要保留策略规定的期限，并支持按哈希追溯。
- 规则和策略变更采用代码评审、签名发布、灰度验证和可回滚版本。

## 14. 平台集成

建议上传链路：

1. 接收 multipart ZIP 并写入隔离临时区。
2. 创建不可伪造的 `upload://<id>`。
3. 调用 `scan_skill_quality`，范围为 `UPLOAD_PACKAGE`。
4. `REJECT`、`REVIEW` 或 `ERROR`：不入库，返回结构化发现。
5. `PASS` 或策略允许的 `PASS_WITH_WARNINGS`：写入 Skill、版本和文件表。
6. 将统一报告保存至 `t_skill_security_scan`，或新增 `t_skill_quality_scan` 并保留旧表兼容映射。

缓存键必须至少包含：

```text
targetSha256
+ engineVersion
+ rulesetVersion
+ policyVersion
+ threatIntelSnapshot
+ malwareSignatureVersion
```

任一版本变化都使旧缓存失效。

## 15. 错误模型

### 15.1 MCP 协议错误

仅用于调用本身不合法，例如缺少 `targetUri`、无权使用策略、目标句柄不存在。

### 15.2 扫描结果错误

目标内容不合规应作为正常 `ScanReport` 返回，而不是 MCP 协议错误。例如：

- `ILLEGAL_PATH`
- `DUPLICATE_PATH`
- `FILE_COUNT_EXCEEDED`
- `SINGLE_FILE_SIZE_EXCEEDED`
- `TOTAL_UNCOMPRESSED_SIZE_EXCEEDED`
- `EXTENSION_NOT_ALLOWED`
- `DANGEROUS_PATH`
- `CONTENT_TYPE_MISMATCH`
- `SKILL_MD_FRONTMATTER_REQUIRED`
- `SKILL_MD_FRONTMATTER_INVALID`
- `SKILL_MD_NAME_REQUIRED`
- `SKILL_MD_DESCRIPTION_REQUIRED`
- `SKILL_MD_VERSION_NOT_ALLOWED`

扫描器内部失败返回 `verdict=ERROR`，并给出不含敏感实现细节的错误码和关联 ID。

## 16. 性能与可用性

- 所有阈值通过服务端策略配置，调用者不可提高上限。
- 文本内容以固定大小分块扫描，保留跨块匹配所需重叠区。
- 对规则做一次编译并使用不可变快照处理单次请求。
- 以目标哈希和版本快照进行安全缓存。
- MCP 层无业务状态；扫描状态和报告由后端存储管理。
- 初始 SLO 应通过基准测试确定；建议分别统计小于 10MB、10–50MB 和 50–200MB 三档包的 P50/P95。
- 超时必须返回 `ERROR`，不能返回部分 `PASS`。

## 17. 可观测性

建议指标：

- 扫描次数及各 Verdict 数量；
- 按规则 ID 和严重度的命中次数；
- 扫描时长、读取字节数、文件数和超时数；
- `LIKELY_FALSE_POSITIVE` 与人工推翻比例；
- 规则版本、情报快照和恶意软件特征库新鲜度；
- 各扫描能力的 `DISABLED/DEGRADED` 次数；
- 上传链路因 MCP 不可用而失败的次数。

指标标签不得包含 Skill 正文、秘密值或高基数完整路径。

## 18. 测试策略

模块的外部接口也是主要测试面。MCP Adapter 和 CLI Adapter 应调用同一个 `SkillQualityScanner`，并对相同输入产生同一报告。

### 18.1 契约测试

- `inputSchema` 和 `outputSchema` 校验。
- 所有 Verdict、错误码和 Finding 字段稳定性。
- 文本摘要与 `structuredContent` 结论一致。

### 18.2 包扫描测试

- 根目录 `SKILL.md` 和唯一顶层目录两种合法结构。
- 缺失 `SKILL.md`、多个顶层目录、包根外危险路径。
- `../`、绝对路径、反斜杠、冒号、重复路径、文件/目录冲突。
- Unicode 等价路径和大小写冲突。
- ZIP 炸弹、虚假 entry 大小、超文件数、超单文件和超总大小。
- 文本伪装二进制、错误图片魔数、加密 ZIP、符号链接。
- macOS 垃圾文件不计数、不持久化、不扫描。

### 18.3 元数据与质量测试

- 缺少或无法闭合 front matter。
- YAML 非 Map、重复键、不安全类型。
- 缺少 `name`/`description`、存在 `version`、非法名称。
- ZIP 名称与 `name` 不一致。
- 缺失本地引用、模糊 description、附件超过 50MB。

### 18.4 安全回归测试

- 每个现有检测器至少包含一个命中和一个不命中样例。
- `df.info()` 不作为域名。
- <code>user: &#96;zh&#96;</code> 不作为用户名。
- `--password=mypassword` 必须命中。
- `writer.encrypt("userpassword", "ownerpassword")` 必须命中。
- 高熵阈值、锁文件和 integrity 字段跳过规则。
- 下载执行、凭据窃取、压缩上传、持久化和供应链组合行为。
- IOC 语法提取与离线恶意库命中。
- 报告和日志中不得出现原始秘密。

### 18.5 健壮性测试

- ZIP、YAML、Markdown 和 URL 解析器模糊测试。
- 并发、取消、超时、内存限制和 Worker 崩溃恢复。
- 情报库不可用、规则签名错误、报告存储失败。

## 19. 分阶段交付

### 阶段 1：MVP

- 一个 `scan_skill_quality` MCP Tool。
- ZIP、目录和单 `SKILL.md` 输入。
- 完整包扫描、元数据确定性规则和现有 15 类安全检测。
- 结构化报告、证据脱敏、策略裁决和测试语料。
- 内网离线运行，不执行任何 Skill 内容。

### 阶段 2：准确率与企业增强

- Markdown/AST 上下文分析。
- 离线 IOC Adapter、规则签名和新鲜度策略。
- 恶意文件/YARA/杀毒 Adapter。
- SBOM、依赖 CVE、包来源和签名校验。
- 人工复核、例外审批和误报反馈闭环。

### 阶段 3：平台化

- 上传平台正式门禁和报告持久化。
- 规则灰度、回放、指标看板和告警。
- 可选内部语义分析，并明确模型版本、数据边界和不可用策略。

## 20. 验收标准

- 四份参考文档中的确定性规则均有稳定规则 ID 和测试映射。
- MCP 与本地测试 Adapter 对相同输入返回一致 Verdict。
- `SKILL_MD_ONLY` 不读取或扫描同目录 ZIP。
- 包扫描失败后不执行安全扫描、不入库。
- 不执行包内脚本、不产生公网访问。
- 所有秘密证据在结果、日志和数据库中脱敏。
- 已知误报和漏报回归用例通过。
- 每份报告包含完整版本快照和覆盖状态。
- 扫描超时或能力异常不能返回 `PASS`。
- 生产策略无法由 MCP 调用参数降级。

## 21. 待确认事项

1. 生产环境实际的扩展名白名单及 `name` 正则。
2. `skill.upload.max-zip-bytes` 的正式值。
3. ZIP 文件名与中文 `name` 的规范化和比较方式。
4. MEDIUM 风险在不同内网等级下是 `REVIEW` 还是直接 `REJECT`。
5. 内网 IOC 数据源、更新频率和最大允许陈旧时间。
6. 恶意文件扫描器和语义分析是否纳入首期。
7. 报告表是扩展 `t_skill_security_scan` 还是新建质量扫描表。
8. 人工复核、例外审批、报告留存期限和责任角色。
