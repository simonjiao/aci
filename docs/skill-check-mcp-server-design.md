# Skill 检查 MCP Server 设计

| 项目 | 内容 |
|---|---|
| 文档状态 | Final |
| 生效日期 | 2026-08-21 |
| 设计对象 | Skill 检查 MCP Server、文件通道与临时存储 |
| Tool | `scan_skill_security` |
| 复用 Module | `SecurityScan`、`CheckRunner` 和 `SecurityAdapter` |
| 目标读者 | Skill 平台研发、安全研发、测试与运维人员 |

## 1. 设计结论

MCP Server 使用官方 Python MCP SDK 2、Streamable HTTP 和协议版本
`2026-07-28`。MCP 负责检查编排和进度通知；ZIP 输入与结果 ZIP 通过同一
ASGI 应用中的受保护 HTTP 路由流式传输。
服务端实现使用官方 `mcp.server.MCPServer`。

| 项目 | 最终选择 |
|---|---|
| 输入文件 | 每个 ZIP 单独流式上传，返回不可猜测的 `package_ref`。 |
| Tool 输入 | 一次提交一个或多个 `package_ref`，不携带 Base64、主机路径或外部 URL。 |
| 批次执行 | 按输入顺序逐包处理；单包失败后继续后续包。 |
| 进度 | MCP progress notification 报告批次校验、逐包开始、逐包完成或失败、结果生成。 |
| Tool 输出 | 结构化摘要和结果 ZIP 的 `ResourceLink`；不返回自由文本或内嵌 ZIP 字节。 |
| 默认存储 | 受控本地临时目录。 |
| 备选存储 | S3 兼容对象存储，配置后使用真实 Adapter。 |
| 认证 | MCP、上传、下载和删除统一使用静态 Bearer Key。 |
| 执行方式 | 请求内完成有上限的同步批次；输入和结果 Artifact 的内容及元数据保留至 TTL 或显式删除。 |

安全扫描规则、Finding 语义和证据处理由 `skill_security` Module 独占；
MCP Server 不修正规则、不生成额外安全判断，也不把处理失败表示为安全通过。
以下 Tool 输入、输出和进度契约属于 `scan_skill_security`；其它 Tool 分别定义
自身契约。

## 2. 结构与职责

~~~text
Client
  ├── POST /uploads ────────────────┐
  │                                  ▼
  │                           ArtifactStore
  │                           ├── Filesystem Adapter
  │                           └── S3 Adapter
  │                                  │
  ├── MCP scan_skill_security        │ package_ref
  │         │                        │
  │         ▼                        │
  │   BatchScanCoordinator ◄─────────┘
  │         │
  │         ▼
  │   CheckRunner → SecurityAdapter → SecurityScan
  │         │
  │         ▼
  │   SecurityBatchReportBuilder
  │         │
  │         ▼
  │   ArtifactStore → result_ref
  │
  └── GET /artifacts/{result_ref}
~~~

外部 seam 位于 MCP Tool Handler 与 `BatchScanCoordinator` 之间。MCP
`Context`、HTTP Request、认证 Header 和存储路径都不能进入 Coordinator、
CheckRunner 或检查 Module。

| Module | 职责 |
|---|---|
| ASGI Host | 组合认证、上传和下载路由，并挂载 MCP Streamable HTTP 应用。 |
| StaticBearerAuth | 在读取请求正文前完成统一认证。 |
| HostOriginGuard | 对 MCP 和自定义文件路由执行同一 Host/Origin allowlist。 |
| ArtifactStore | 保存、物化、下载、租约、删除和 TTL 清理。 |
| BatchScanCoordinator | 解析引用、顺序执行、隔离单包失败并产生中立进度事件。 |
| CheckRunner | 按既定检查计划执行 Check Adapter。 |
| SecurityAdapter | 调用安全扫描并返回 `security-scan.csv` 与 `security-metadata.json` Artifact。 |
| SecurityBatchReportBuilder | 校验并合并逐包 CheckResult Artifact，写入批次报告工作区。 |
| MCP Tool Handler | 校验 Tool Schema，将中立进度事件映射为 MCP 通知并返回结果链接。 |

## 3. ASGI 与 HTTP Interface

顶层使用 Starlette ASGI 应用。上传和下载路由必须位于 MCP `Mount` 之前；
顶层 lifespan 负责进入 MCP session manager、启动过期清理并在关闭时释放资源。

| 方法与路径 | 认证 | 成功结果 | 作用 |
|---|---|---|---|
| `POST /uploads` | Bearer | `201` + 上传元数据 | 流式保存一个 Skill ZIP。 |
| `GET /artifacts/{result_ref}` | Bearer | `200 application/zip` | 流式下载结果 ZIP。 |
| `DELETE /artifacts/{artifact_ref}` | Bearer | `204` | 提前释放输入或结果文件。 |
| `POST /mcp` | Bearer | SSE | MCP Streamable HTTP。 |

MCP 应用由官方 `MCPServer.streamable_http_app(stateless_http=True,
json_response=False)` 创建并挂载。Tool 调用以 SSE 依次返回 progress
notification 和最终 ToolResult；即使客户端未请求进度，最终结果也通过同一
SSE 响应返回。客户端须按 Streamable HTTP 要求同时接受 `application/json`
和 `text/event-stream`。

### 3.1 上传

请求一次只包含一个 ZIP：

~~~http
POST /uploads HTTP/1.1
Authorization: Bearer <static-key>
Content-Type: application/zip
Content-Disposition: attachment; filename="skill.zip"
Content-Length: 123456
~~~

上传路由必须使用 ASGI 流式 receive，不调用 `request.body()`。写入过程中同步
计算字节数和 SHA-256；超过单包或存储总上限时停止读取、删除未完成文件并返回
`413` 或 `507`。

~~~json
{
  "package_ref": "pkg_0123456789abcdef0123456789abcdef",
  "display_name": "skill.zip",
  "size_bytes": 123456,
  "sha256": "...",
  "expires_at": "2026-08-21T12:30:00Z"
}
~~~

约束：

- `Content-Disposition` 必须提供 5—255 字符的 ZIP 显示名称；名称以 `.zip`
  结尾且不含路径分隔符、NUL、控制字符或首尾空白，不参与存储路径。
- 服务端生成随机引用和对象键，不接受客户端指定引用。
- 完整写入和元数据校验成功后才发布 `package_ref`。
- 未完成文件使用独立临时名称，并通过原子提交转为可读取对象。
- 上传成功只说明字节已保存，不代表内容是有效或安全的 ZIP。

### 3.2 下载与删除

`GET /artifacts/{result_ref}` 校验引用类型、存在性和 TTL 后分块发送文件，支持
标准 `Content-Length` 和安全的 `Content-Disposition`。URL 不携带认证信息，
客户端使用同一个 Bearer Header。

删除正在扫描或下载的对象返回 `409`。格式非法、丢失、过期或已删除的引用统一
返回 `404`，不通过响应区分其历史状态，也不泄露存储路径。

## 4. MCP Tool Interface

### 4.1 Tool 元数据

~~~json
{
  "name": "scan_skill_security",
  "title": "检查 Skill 安全规则",
  "description": "顺序检查一个或多个已上传的 Skill ZIP，返回批次摘要和结果 ZIP。",
  "annotations": {
    "readOnlyHint": false,
    "destructiveHint": false,
    "idempotentHint": false,
    "openWorldHint": false
  }
}
~~~

Tool 会创建有 TTL 的结果 Artifact，因此不声明只读或幂等；它不会改变或删除
输入 ZIP。

### 4.2 输入 Schema

~~~json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["packages"],
  "properties": {
    "packages": {
      "type": "array",
      "minItems": 1,
      "maxItems": 100,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["package_ref"],
        "properties": {
          "package_ref": {
            "type": "string",
            "pattern": "^pkg_[0-9a-f]{32}$"
          },
          "source_id": {
            "type": ["string", "null"],
            "minLength": 1,
            "maxLength": 256
          }
        }
      }
    }
  }
}
~~~

配置可以把批次上限收紧，但不能超过 Schema 硬上限。重复 `package_ref`、结构
错误或可解析输入包总大小超过上限属于请求错误，Tool 不开始扫描。格式正确但
过期、丢失或无法读取的引用属于对应包的处理失败，不中止批次。

### 4.3 输出

Tool 不产生 TextContent。成功处理完批次后返回结构化摘要和一个受保护的结果
ResourceLink：

~~~json
{
  "structuredContent": {
    "processing_status": "PARTIAL_FAILURE",
    "conclusion": "REVIEW_REQUIRED",
    "total_packages": 10,
    "completed_packages": 9,
    "failed_packages": 1,
    "review_required_packages": 2,
    "finding_count": 38,
    "result_ref": "res_fedcba9876543210fedcba9876543210",
    "expires_at": "2026-08-21T13:00:00Z"
  },
  "content": [
    {
      "type": "resource_link",
      "name": "skill-security-result.zip",
      "uri": "https://skillqa.internal/artifacts/res_fedcba9876543210fedcba9876543210",
      "description": "使用与 MCP 相同的 Bearer Key 下载",
      "mimeType": "application/zip",
      "size": 45678
    }
  ]
}
~~~

`result_ref` 和过期时间属于运行元数据，不写入结果 ZIP。

## 5. 批次处理

### 5.1 执行流程

`BatchScanCoordinator` 按输入顺序执行：

1. 校验批次结构、引用唯一性、包数量和可解析输入包总大小。
2. 逐个为 `package_ref` 获取租约并物化为只读可定位流。
3. 对当前包调用 CheckRunner；Builder 校验其固定 Artifact 路径、媒体类型和格式，
   再把 CSV 行与 JSON 元数据写入受限的结果工作区。
4. 释放该包的 RunResult、输入流、scratch 文件和租约。
5. 捕获经过清理的单包错误，写入失败状态并继续下一包。
6. 从结果工作区生成 ZIP，流式保存为 `result_ref`。

只有一个包时也执行同一批次流程；ZIP 大小只影响传输分块数和资源限制，不改变
Tool 输入、进度、结果格式或下载方式。

同一批次不并行扫描 ZIP，避免解码内容、文本事实和报告同时占用多份内存。
报告 Builder 不在内存中累计全批次 Finding；不同批次的并发由服务级容量限制
控制。同步 CheckRunner 通过有上限的 worker thread 调用，不阻塞 ASGI event
loop；请求取消后不再调度下一包，并在当前调用返回后释放资源。开始扫描前为结果
工作区和结果 Artifact 取得容量配额。

### 5.2 单包与总体状态

每个包只有一种最终状态：

| 状态 | 含义 |
|---|---|
| `PASS` | 扫描完整且无 Finding。 |
| `REVIEW_REQUIRED` | 扫描完整且存在 Finding。 |
| `FAILED` | 未形成完整扫描结果；只记录清理后的错误码和说明。 |

总体状态和结论分开表示：

| 条件 | `processing_status` | `conclusion` |
|---|---|---|
| 全部成功且无 Finding | `COMPLETE` | `PASS` |
| 全部成功且存在 Finding | `COMPLETE` | `REVIEW_REQUIRED` |
| 部分包失败 | `PARTIAL_FAILURE` | `REVIEW_REQUIRED` |
| 全部包失败 | `FAILED` | `REVIEW_REQUIRED` |

失败包不生成 Finding。总体 `REVIEW_REQUIRED` 可能由真实 Finding 或结果不完整
触发，调用方通过 `processing_status`、包状态和 Finding 数区分原因。

### 5.3 进度

Coordinator 产生与 MCP 无关的中立事件，MCP Tool Handler 将其转换为
`Context.report_progress()`：

~~~text
批次校验完成，共 10 个 ZIP
开始处理第 1/10 个 ZIP
第 1/10 个 ZIP 扫描完成
开始处理第 2/10 个 ZIP
第 2/10 个 ZIP 处理失败，继续处理
...
结果文件生成完成
~~~

对于 `N` 个包，`total = 2N + 2`：批次校验完成时 `progress = 1`，第 `i` 个包
开始和结束时分别为 `2i`、`2i + 1`，结果生成完成时为 `2N + 2`。失败包的结束
事件使用相同进度值，保证进度单调且不会因失败回退。

消息只包含序号、总数和固定状态，不包含包名、存储引用、路径、Finding 或证据。
开始事件在解析引用和获取租约前发送，因此过期、丢失和读取失败的批次项也具有
完整的一始一终；完成事件只在完整扫描返回后发送，失败事件在错误已经清理后
发送。客户端未提供 progress token 时通知自动忽略，最终结果不变。

## 6. 结果 ZIP

结果 ZIP 固定包含：

~~~text
manifest.json
package-status.csv
security-scan.csv
security-metadata.json
~~~

| 文件 | 内容 |
|---|---|
| `manifest.json` | 批次处理状态、总体结论和文件清单。 |
| `package-status.csv` | 每个 ZIP 的顺序、显示名称、处理状态、Finding 数和清理后的错误。 |
| `security-scan.csv` | 所有成功扫描包的真实安全 Finding；失败包没有 Finding 行。 |
| `security-metadata.json` | 包摘要、规则覆盖、规则版本和规则 SHA-256。 |

`package-status.csv` 和 `security-scan.csv` 使用 UTF-8 BOM、固定表头、CRLF 和
CSV 公式注入防护。Builder 将两个 CSV 和 JSON 暂存为有大小上限的文件，再按
固定顺序写入 ZIP。失败信息与安全违规分表，避免把执行错误解释为规则命中。
结果不包含主机路径、随机引用、静态 Key 或对象存储凭据。

`package-status.csv` 固定列为“包序号、包名称、处理状态、检查结论、Finding
数量、错误代码、错误说明、来源标识、包大小、包 SHA-256”。人工关注列在前，
来源和哈希在后。`security-scan.csv` 使用 SecurityAdapter 的 18 列契约和
列序，不因批次接入改变 Finding 内容。Builder 只消费 CheckRunner 已返回的
Artifact，不直接调用 SecurityScan，也不通过隐式状态取得 ScanResult。

## 7. ArtifactStore

### 7.1 Interface

~~~text
ArtifactStore
  reserve(kind, maxBytes) -> CapacityLease
  put(kind, displayName, byteChunks, ttl, capacityLease) -> StoredArtifact
  stat(ref) -> ArtifactMetadata
  lease(ref) -> SeekableArtifact
  workspace(maxBytes) -> WorkspaceLease
  openDownload(ref) -> ByteStream
  delete(ref) -> None
  cleanupExpired(now) -> CleanupSummary
~~~

`kind` 只允许 `PACKAGE` 和 `RESULT`。引用由类型前缀和至少 128 位密码学随机值
组成；调用方不能从引用推导存储后端、主机路径或对象键。

租约保证对象在扫描或下载期间不被 TTL 清理。ArtifactStore 对调用方隐藏原子
写入、scratch 文件、对象键、分块大小和清理算法。上传在读取正文前取得容量
租约；批次在扫描前分别取得结果 Artifact 和工作区租约。提交后只计实际大小，
未使用配额以及所有失败、取消路径中的租约必须释放。

ArtifactStore 内部的 CapacityManager 是 root 与 scratch 配额的唯一所有者。
`max_result_workspace_bytes` 是单工作区上限，`max_scratch_bytes` 是全部工作区和
S3 物化文件的全局上限；Builder 和 S3 Adapter 只能写入租约提供的句柄，不能
自行创建 scratch 路径或维护计数。

### 7.2 Filesystem Adapter

Filesystem Adapter 用于本地临时存储部署：

- 根目录和 scratch 目录必须是绝对路径、不可为符号链接且权限仅授予服务账户。
- 存储名只使用服务端生成值；显示名称保存在受控元数据中。
- 先写 `.part`，同步完成并校验后原子改名。
- 元数据与内容提交保持一致；启动时清理孤立 `.part` 和已过期对象。
- 下载使用分块文件响应；扫描直接租约并打开已保存文件。
- 结果工作区位于 scratch 目录，受结果大小和服务总容量共同约束。

Filesystem Adapter 面向单实例部署。多个实例不能依赖各自本地引用互通。

### 7.3 S3 Adapter

S3 Adapter 支持 AWS S3、MinIO 和兼容实现：

- 上传和结果写入使用分块或 multipart upload；失败时中止未完成上传。
- 对象键由服务端生成，按配置前缀区分 package 和 result。
- Artifact 元数据作为伴随对象持久化；服务重启后，未过期且未删除的引用仍可解析。
- 扫描前把单个对象流式物化到本地 scratch；扫描后立即删除 scratch 文件。
- 下载由服务端代理并执行统一 Bearer 认证，不把存储凭据放入 URL。
- 租约保存在进程内；对象生命周期策略作为过期清理兜底。

配置接受 `type = "s3"` 时必须存在可工作的 S3 Adapter；缺少依赖、凭据或
Bucket 访问能力时启动失败，不能延迟到 Tool 调用时报错。
S3 Adapter 与 Filesystem Adapter 均按单服务实例部署；Artifact 租约与容量
不跨服务进程共享。

## 8. 认证与安全

### 8.1 静态 Bearer Key

所有受保护路由使用：

~~~http
Authorization: Bearer <static-key>
~~~

Key 只通过环境变量注入，取值为 32—512 个无空白可打印 ASCII 字符。比较使用
恒定时间算法。缺失、格式错误或不匹配统一返回 `401` 和
`WWW-Authenticate: Bearer`，不记录 Header 或 Key。

认证和 Host/Origin middleware 位于请求大小检查和路由之前，未授权请求不能占用
文件写入、扫描或对象存储资源。顶层 HostOriginGuard 覆盖 MCP、上传、下载和
删除路由；MCP transport 的 DNS rebinding 防护同时启用。配置只生成一份 SDK
`TransportSecuritySettings`；HostOriginGuard 委托 SDK 的 Host/Origin 匹配器，
MCP transport 接收同一设置。Host 必须匹配，Origin 缺省时允许、存在时必须
匹配；默认不读取 `X-Forwarded-*`。

单个全局 Key 提供服务级认证，不区分共享该 Key 的调用方。Artifact 引用仍必须
具有不可猜测性；该认证模型不提供用户级授权。

### 8.2 存储凭据

对象存储 Access Key、Secret Key 和可选 Session Token 与服务 Bearer Key
分离，只通过配置指定的环境变量读取。配置文件只保存环境变量名称，
错误、日志、进度和结果均不得包含凭据正文。

### 8.3 资源保护

资源限制在相应 seam 尽早执行：

| 限制 | 执行位置 |
|---|---|
| 未认证请求 | ASGI 认证 middleware，读取正文前。 |
| 非法 Host 或 Origin | ASGI HostOriginGuard，读取正文前。 |
| 上传单包大小 | 上传流累计计数。 |
| MCP 请求体大小 | ASGI/MCP transport。 |
| 批次包数与可解析输入包总大小 | Tool Schema 与 Coordinator。 |
| 并发上传、扫描和下载 | ASGI admission control。 |
| 存储总容量 | ArtifactStore。 |
| 结果工作区与物化文件 | scratch 累计计数与容量准入。 |
| ZIP 条目、文本读取和 Finding | SecurityScan `ScanPolicy`。 |

并发许可必须在读取大请求体之前取得；超限返回 `429`，不能把大请求排队保留在
内存中。所有流、租约和 scratch 文件在成功、错误和取消路径中都必须释放。

## 9. 配置

配置通过 Pydantic strict 模式校验，拒绝未知字段和隐式类型转换。相对规则路径
以配置文件目录为基准；存储和 scratch 路径必须是绝对路径。

### 9.1 本地临时目录

~~~toml
schema_version = "2"

[http]
host = "127.0.0.1"
port = 8000
mcp_path = "/mcp"
max_mcp_request_body_bytes = 1048576
public_base_url = "http://127.0.0.1:8000"
allowed_hosts = ["127.0.0.1:*", "localhost:*"]
allowed_origins = ["http://127.0.0.1:*", "http://localhost:*"]

[auth]
type = "static_bearer"
key_env = "SKILLQA_API_KEY"

[storage]
upload_ttl_seconds = 1800
result_ttl_seconds = 3600
cleanup_interval_seconds = 60
max_package_bytes = 536870912
max_result_bytes = 536870912
max_total_bytes = 8589934592
scratch_directory = "/var/lib/skillqa/scratch"
max_result_workspace_bytes = 536870912
max_scratch_bytes = 4294967296

[storage.backend]
type = "filesystem"
root = "/var/lib/skillqa/artifacts"

[capacity]
max_concurrent_uploads = 2
max_concurrent_scans = 2
max_concurrent_downloads = 4

[tools.scan_skill_security]
type = "skill-security"
rules_file = "security-rules.json"
max_packages_per_request = 100
max_total_package_bytes = 2147483648

[tools.scan_skill_security.policy]
max_entries_per_package = 1000
max_text_bytes_per_file = 65536
max_total_read_bytes = 67108864
max_findings = 10000
~~~

`storage.max_package_bytes` 同时用于上传限制和构造 SecurityScan `ScanPolicy`，
不在 Tool policy 中重复配置。`max_total_package_bytes + max_result_bytes` 不能
超过 `storage.max_total_bytes`；
实际执行仍须通过动态容量准入，给并发上传和既有 Artifact 留出空间。MCP 请求
只携带引用，因此使用独立的小型请求体上限。`public_base_url` 用于生成
ResourceLink，必须是无用户信息、查询串和片段的 HTTP(S) 绝对地址。
`max_result_workspace_bytes` 限制未压缩 CSV/JSON 的累计大小；
`max_scratch_bytes` 同时约束各批次工作区和当前物化输入。最终 ZIP 从工作区直接
流入 ArtifactStore，不在 scratch 中再保留一份完整副本。

### 9.2 S3 兼容对象存储

S3 兼容部署使用以下 backend 配置：

~~~toml
[storage.backend]
type = "s3"
endpoint_url = "https://minio.internal"
bucket = "skillqa-temp"
region = "us-east-1"
prefix = "artifacts/"
path_style = true
credential_provider = "static_env"
access_key_env = "SKILLQA_S3_ACCESS_KEY"
secret_key_env = "SKILLQA_S3_SECRET_KEY"
session_token_env = "SKILLQA_S3_SESSION_TOKEN"
~~~

`session_token_env` 对应的环境变量可以不存在；Access Key 和 Secret Key 必须
同时存在。静态凭据正文不能出现在 TOML。

## 10. 代码组织

~~~text
src/
  artifact_store/
    models.py              # 引用、元数据、租约和错误
    store.py               # ArtifactStore Interface
    capacity.py            # root 与 scratch 原子容量预留
    filesystem.py          # 本地 Adapter
    s3.py                  # S3 Adapter
    lifecycle.py           # TTL 和遗留文件清理
  skill_checks/
    security.py            # SecurityAdapter
    security_report.py     # 逐包写入的批次安全报告 Builder
  mcp_server/
    app.py                 # 顶层 Starlette 应用与 lifespan
    auth.py                # 静态 Bearer middleware
    http_security.py       # 全路由 Host/Origin allowlist
    config.py              # 严格配置和依赖装配
    registry.py            # 静态 Tool 注册
    services/
      security_batch.py    # 引用解析、逐包隔离、结果提交和中立进度
    routes/
      uploads.py           # 流式上传
      artifacts.py         # 流式下载和删除
    tools/
      security_scan.py     # Tool Schema、进度映射和结果链接
~~~

`artifact_store` 不依赖 MCP、CLI 或安全检查；`skill_check_runner` Interface
不包含 HTTP、MCP 或存储概念。`mcp_server.services` 只依赖
ArtifactStore Interface、CheckRunner 和报告 Builder，不接收 MCP `Context`；
Coordinator 从 WorkspaceLease 取得普通写入流再交给 Builder，因此
`skill_checks` 也不依赖 `artifact_store`。具体后端仅由 `mcp_server.config`
选择。CLI 使用独立文件输入 Interface，不依赖 `mcp_server`。

核心运行依赖使用官方 `mcp` SDK、Pydantic 2、Starlette 和 Uvicorn；S3 可选
依赖使用 `boto3`。配置选择 S3 但未安装该依赖时启动失败。S3 Adapter 的阻塞
I/O 也通过有上限的 worker thread 调用。
外部 SDK 的宽类型只允许在对应 Adapter 内通过窄 Protocol 收口，源码和测试
必须满足 mypy strict、Pydantic 插件和 Any 表达式 100%。

## 11. 错误表达

稳定错误码按失败边界划分：

| 边界 | 错误码 |
|---|---|
| Tool 请求 | `MCP_INPUT_INVALID`、`BATCH_LIMIT_EXCEEDED` |
| 单包处理 | `ARTIFACT_UNAVAILABLE`、`ARTIFACT_READ_FAILED`、`CHECK_EXECUTION_FAILED`、`CHECK_RESULT_INVALID` |
| 批次基础设施 | `STORAGE_UNAVAILABLE`、`CHECK_RESULT_WRITE_FAILED` |

单包错误码进入 `package-status.csv`；请求和基础设施错误码进入 MCP Tool error。
HTTP 文件通道使用稳定状态码和等价的清理后错误码。

| 层级 | 行为 |
|---|---|
| HTTP 认证或上传错误 | 稳定 HTTP 状态与清理后的短消息。 |
| Tool 请求结构错误 | MCP Tool error，不创建结果 Artifact。 |
| 单包引用或扫描错误 | 记录包状态 `FAILED`，继续批次。 |
| 存储后端整体不可用 | MCP Tool error，不返回部分结果。 |
| 结果 ZIP 生成或提交失败 | MCP Tool error，删除未完成结果。 |

底层异常链、Header、Key、凭据、主机路径、对象键、原始 ZIP 内容和未脱敏证据
不能进入 HTTP 响应、MCP error、进度、CSV 或 JSON。批次结束后只要结果
Artifact 成功生成，Tool 调用本身成功；包级失败通过结构化摘要和报告表达。

## 12. 验收

必须验证：

- 大文件上传按块读取，未使用 Base64，也未调用完整正文读取。
- 未认证请求在读取上传字节前返回 `401`，Key canary 不进入异常链或日志。
- 批次严格按输入顺序执行；单包损坏、过期、超限或扫描失败不影响后续包。
- progress 事件顺序正确，失败包没有完成事件，无回调客户端仍得到最终结果。
- `security-scan.csv` 只包含真实 Finding；所有失败均进入 `package-status.csv`。
- 结果通过受保护 ResourceLink 下载，ToolResult 不包含 ZIP Base64 或自由文本。
- TTL 不删除有效租约；上传取消、进程重启和结果生成失败不遗留 `.part`。
- Filesystem 与 S3 Adapter 通过同一 ArtifactStore 合同测试，包括 Adapter 重建后的
  引用解析和 TTL 行为。
- 两个固定真实 Skill ZIP 通过 HTTP 上传、MCP 批次扫描和结果下载端到端回归。
- `/mcp` 与文件路由使用相同 Host/Origin 正反用例；静态认证、并发、容量和所有
  资源上限有正反边界测试。
- 安装包、锁文件、Ruff、完整测试、mypy strict、Pydantic 插件和 Any 100% 通过。

## 13. 实现依据

- [Python MCP SDK：在 ASGI 应用中挂载 Streamable HTTP](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/run/asgi.md)
- [Python MCP SDK：进度、调用中通知与取消示例](https://github.com/modelcontextprotocol/python-sdk/blob/main/examples/stories/streaming/README.md)
- [MCP 2026-07-28：无会话 Streamable HTTP 与部署模型](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
