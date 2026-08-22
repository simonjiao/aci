# Skill 检查 MCP Server 设计

| 项目 | 内容 |
|---|---|
| 文档状态 | Final |
| 生效日期 | 2026-08-21 |
| 设计对象 | Skill 检查 MCP Server、文件通道与统一存储层 |
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
| 输入文件 | 每个 ZIP 单独流式上传，返回引用、显示名称、大小和 SHA-256 描述符。 |
| Tool 输入 | 一次提交一个或多个上传描述符，不携带 Base64、主机路径、存储 URI 或外部 URL。 |
| 批次执行 | 按输入顺序逐包处理；单包失败后继续后续包。 |
| 进度 | MCP progress notification 报告批次校验、逐包开始、逐包完成或失败、结果生成。 |
| Tool 输出 | 结构化摘要和结果 ZIP 的 `ResourceLink`；不返回自由文本或内嵌 ZIP 字节。 |
| 存储实现 | `FsspecArtifactStorage` 通过 fsspec 统一访问本地目录或 S3 兼容对象存储。 |
| 临时空间 | 上传、扫描物化和结果构建使用受限的本地 `ScratchWorkspace`。 |
| 认证 | MCP、上传和下载统一使用静态 Bearer Key。 |
| 执行方式 | 请求内完成有上限的同步批次；Artifact 保留周期由部署侧存储策略负责。 |

安全扫描规则、Finding 语义和证据处理由 `skill_security` Module 独占；
MCP Server 不修正规则、不生成额外安全判断，也不把处理失败表示为安全通过。
以下 Tool 输入、输出和进度契约属于 `scan_skill_security`；其它 Tool 分别定义
自身契约。

## 2. 结构与职责

~~~text
Client
  ├── POST /uploads ────────────────┐
  │                                  ▼
  │                         ScratchWorkspace
  │                                  │
  │                                  ▼
  │                         ArtifactStorage
  │                                  │
  │                         FsspecArtifactStorage
  │                         ├── file backend
  │                         └── s3 backend
  │                                  │
  ├── MCP scan_skill_security        │ package descriptor
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
  │   ArtifactStorage → result_ref
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
| ArtifactStorage | 通过 fsspec 发布、检查、物化和流式读取不可变 Artifact。 |
| ScratchWorkspace | 管理请求级临时文件、空间预算和确定性清理。 |
| BatchScanCoordinator | 解析引用、顺序执行、隔离单包失败并产生中立进度事件。 |
| CheckRunner | 按既定检查计划执行 Check Adapter。 |
| SecurityAdapter | 调用安全扫描并返回 `security-scan.csv` 与 `security-metadata.json` Artifact。 |
| SecurityBatchReportBuilder | 校验并合并逐包 CheckResult Artifact，写入批次报告工作区。 |
| MCP Tool Handler | 校验 Tool Schema，将中立进度事件映射为 MCP 通知并返回结果链接。 |

## 3. ASGI 与 HTTP Interface

顶层使用 Starlette ASGI 应用。上传和下载路由必须位于 MCP `Mount` 之前；
顶层 lifespan 负责进入 MCP session manager、创建存储依赖并在关闭时释放 fsspec
backend 持有的资源。

| 方法与路径 | 认证 | 成功结果 | 作用 |
|---|---|---|---|
| `POST /uploads` | Bearer | `201` + 上传元数据 | 流式保存一个 Skill ZIP。 |
| `GET /artifacts/{result_ref}` | Bearer | `200 application/zip` | 流式下载结果 ZIP。 |
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

上传路由必须使用 ASGI 流式 receive，不调用 `request.body()`。请求正文先写入
`ScratchWorkspace`，写入过程中计算字节数和 SHA-256；超过单包或 scratch 上限时
停止读取、删除未完成文件并返回 `413` 或 `507`。正文完整后调用
`ArtifactStorage.publish()`，发布成功才返回引用。

~~~json
{
  "package_ref": "pkg_0123456789abcdef0123456789abcdef",
  "display_name": "skill.zip",
  "size_bytes": 123456,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
~~~

约束：

- `Content-Disposition` 必须提供 5—255 字符的 ZIP 显示名称；名称以 `.zip`
  结尾且不含路径分隔符、NUL、控制字符或首尾空白，不参与存储路径。
- 服务端生成随机引用和对象键，不接受客户端指定引用。
- scratch 文件完整关闭且 Artifact 写入成功、大小复核一致后才发布 `package_ref`。
- 写入失败时删除 scratch 文件并尽力删除未完成对象；失败引用不会返回给客户端。
- 上传成功只说明字节已保存，不代表内容是有效或安全的 ZIP。

### 3.2 下载

`GET /artifacts/{result_ref}` 校验引用类型和存在性后，通过 ArtifactStorage 分块
发送文件，支持标准 `Content-Length` 和安全的 `Content-Disposition`。URL 不携带
认证信息，客户端使用同一个 Bearer Header。格式非法或对象不存在统一返回 `404`，
不泄露存储路径或 backend 异常。

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

Tool 会创建新的结果 Artifact，因此不声明只读或幂等；它不会改变或删除输入 ZIP。

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
        "required": ["package_ref", "display_name", "size_bytes", "sha256"],
        "properties": {
          "package_ref": {
            "type": "string",
            "pattern": "^pkg_[0-9a-f]{32}$"
          },
          "display_name": {
            "type": "string",
            "minLength": 5,
            "maxLength": 255
          },
          "size_bytes": {
            "type": "integer",
            "minimum": 1
          },
          "sha256": {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$"
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

客户端将上传响应中的四个字段原样放入 Tool 输入；`display_name` 使用与上传相同的
ZIP 文件名校验，仅用于结果展示，不参与对象键或安全判断。配置可以把批次上限收紧，
但不能超过 Schema 硬上限。重复
`package_ref`、结构错误或可解析输入包总大小超过上限属于请求错误，Tool 不开始
扫描。格式正确但丢失或无法读取的引用属于对应包的处理失败，不中止批次。

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
    "result_size_bytes": 45678,
    "result_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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

`result_ref`、结果大小和 SHA-256 属于运行元数据，不写入结果 ZIP。

## 5. 批次处理

### 5.1 执行流程

`BatchScanCoordinator` 按输入顺序执行：

1. 校验批次结构、引用唯一性和包数量；通过 ArtifactStorage 检查各引用，丢失或
   无法读取的条目标记为单包失败，其余条目按实际大小校验输入包总量。
2. 逐个把 `package_ref` 物化到当前 `ScratchWorkspace`，复核描述符中的大小和
   SHA-256，形成只读本地 ZIP。
3. 对当前包调用 CheckRunner；Builder 校验其固定 Artifact 路径、媒体类型和格式，
   再把 CSV 行与 JSON 元数据写入受限的结果工作区。
4. 释放该包的 RunResult、输入流和物化文件。
5. 捕获经过清理的单包错误，写入失败状态并继续下一包。
6. 从结果工作区生成本地结果 ZIP，调用 ArtifactStorage 发布并取得 `result_ref`。

只有一个包时也执行同一批次流程；ZIP 大小只影响传输分块数和资源限制，不改变
Tool 输入、进度、结果格式或下载方式。

同一批次不并行扫描 ZIP，避免解码内容、文本事实和报告同时占用多份内存。
报告 Builder 不在内存中累计全批次 Finding；不同批次的并发由服务级容量限制
控制。同步 CheckRunner 通过有上限的 worker thread 调用，不阻塞 ASGI event
loop；请求取消后不再调度下一包，并在当前调用返回后释放资源。开始扫描前为结果
工作区、单个物化包和最终 ZIP 取得 scratch 空间预算。

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
引用检查在批次预检阶段完成。进入每个包的处理分支时发送开始事件；预检已确定
不可用的条目随后立即发送失败事件，其余条目再执行物化和扫描。因此每个批次项均有
完整的一始一终。完成事件只在完整扫描返回后发送，失败事件在错误已经清理后发送。
客户端未提供 progress token 时通知自动忽略，最终结果不变。

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

## 7. ArtifactStorage

### 7.1 Interface

~~~text
ArtifactStorage
  publish(kind, preparedFile) -> StoredArtifact
  inspect(ref) -> ArtifactInfo
  materialize(descriptor, workspace) -> MaterializedArtifact
  stream(ref) -> ByteStream
~~~

`kind` 只允许 `PACKAGE` 和 `RESULT`。引用分别使用 `pkg_` 和 `res_` 前缀，后接
128 位密码学随机值；实现据此生成 `packages/<id>.zip` 或 `results/<id>.zip`，但
调用方不能提供对象键、存储 URI 或主机路径。Artifact 不可变，不覆盖已有对象。

上传描述符由 `package_ref`、`display_name`、`size_bytes` 和 `sha256` 组成，客户端
将其原样放入 Tool 输入；服务不维护引用数据库或元数据 sidecar。`inspect()` 读取
backend 的实际大小，`materialize()` 在复制到 scratch 时复核描述符中的大小和
SHA-256。显示名称只用于结果展示，不参与寻址。

对象缺失统一表现为 Artifact 不可用。

### 7.2 FsspecArtifactStorage

本地目录和 S3 兼容对象存储共用一个 `FsspecArtifactStorage` 实现。启动时根据严格
配置构造 fsspec filesystem 和根路径，生产环境只允许 `file` 与 `s3` protocol；
fsspec 对象、路径和 `storage_options` 不穿过 ArtifactStorage Interface。

一致性约束如下：

- `publish()` 只接受包含本地路径、大小和 SHA-256 的 `PreparedArtifact`；文件必须
  已完整关闭，且实际大小与描述一致。实现使用服务端生成的唯一对象键写入。
- 完整关闭目标并通过 `inspect()` 复核大小后才返回引用；失败时尽力删除未完成对象。
- 不使用 fsspec transaction 作为跨 backend 的原子性保证，也不依赖 rename、目录
  列举或 S3 ETag 表示 SHA-256。
- `materialize()` 和 `stream()` 分块传输；前者复核完整 SHA-256，后者在迭代结束或
  调用方取消时关闭读取流。
- 统一调用 fsspec 同步 Interface，并通过有上限的 worker thread 与 ASGI 隔离；不让
  backend 专属异步方法进入调用方。
- fsspec 或 s3fs 的底层异常只在本实现内映射为稳定的 ArtifactStorage 错误。

`file` backend 的根目录必须是绝对路径、不可为符号链接且只授予服务账户权限；未使用
共享文件系统时只适合单实例部署。`s3` backend 使用 s3fs，支持 AWS S3、MinIO 和兼容
实现；缺少依赖、凭据、Bucket 或前缀访问能力时启动失败。多个实例可以共享同一 S3
根路径，因为引用直接映射不可变对象且不依赖进程内状态。

### 7.3 ScratchWorkspace

~~~text
ScratchWorkspace
  open(maxBytes) -> Workspace
Workspace
  allocate(role, maxBytes) -> ScratchFile
~~~

ScratchWorkspace 使用服务私有的绝对本地目录。上传 `.part`、当前物化包、逐包报告、
最终结果 ZIP 都只能写入工作区提供的路径；Builder 和存储实现不能自行创建临时路径。
`role` 只允许上传、物化包、报告和结果四类。`open()` 在进程级
`max_scratch_bytes` 中预留工作区上限；`allocate()` 在该上限内预留文件空间并返回
服务生成的路径和有界二进制句柄。

Workspace 和 ScratchFile 均使用上下文管理器，关闭时按实际大小结算空间并释放未用
预留；工作区退出时删除全部内容。启动时只清理本服务命名空间中上次异常退出遗留的
scratch 目录，不扫描或管理 ArtifactStorage 根路径。

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
文件写入、扫描或对象存储资源。顶层 HostOriginGuard 覆盖 MCP、上传和下载路由；
MCP transport 的 DNS rebinding 防护同时启用。配置只生成一份 SDK
`TransportSecuritySettings`；HostOriginGuard 委托 SDK 的 Host/Origin 匹配器，
MCP transport 接收同一设置。Host 必须匹配，Origin 缺省时允许、存在时必须
匹配；默认不读取 `X-Forwarded-*`。

单个全局 Key 提供服务级认证，不区分共享该 Key 的调用方。Artifact 引用仍必须
具有不可猜测性；该认证模型不提供用户级授权。

### 8.2 存储凭据

S3 Access Key、Secret Key 和可选 Session Token 与服务 Bearer Key 分离，交由
s3fs 使用默认凭据链或从配置指定的环境变量读取。配置文件只保存凭据提供方式和
环境变量名称；错误、日志、进度和结果均不得包含凭据正文。

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
| 上传暂存、结果工作区与物化文件 | ScratchWorkspace 累计计数与空间准入。 |
| backend 配额耗尽或不可用 | ArtifactStorage 错误映射。 |
| ZIP 条目、文本读取和 Finding | SecurityScan `ScanPolicy`。 |

并发许可必须在读取大请求体之前取得；超限返回 `429`，不能把大请求排队保留在
内存中。所有流和 scratch 文件在成功、错误和取消路径中都必须释放。

## 9. 配置

配置通过 Pydantic strict 模式校验，拒绝未知字段和隐式类型转换。相对规则路径
以配置文件目录为基准；Filesystem root 和 scratch 目录必须是绝对路径且不能相同、
互相包含或通过符号链接重叠。

### 9.1 本地文件系统

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
max_package_bytes = 536870912
max_result_bytes = 536870912
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
不在 Tool policy 中重复配置。`max_scratch_bytes` 必须至少容纳一个结果工作区与
单个最大输入包或最大结果 ZIP 中较大者；并发操作仍须通过动态 scratch 空间准入。
MCP 请求只携带描述符，因此使用独立的小型请求体上限。`public_base_url` 用于生成
ResourceLink，必须是无用户信息、查询串和片段的 HTTP(S) 绝对地址。
`max_result_workspace_bytes` 限制未压缩 CSV/JSON 的累计大小；
`max_scratch_bytes` 同时约束上传暂存、各批次报告、当前物化输入和最终 ZIP。最终
ZIP 发布成功后立即从 scratch 删除。

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
同时存在。也可以将 `credential_provider` 设置为 `default_chain` 并省略三个凭据
环境变量字段。静态凭据正文不能出现在 TOML。

Filesystem 与 S3 配置使用 Pydantic 判别联合，不能接受任意 fsspec protocol 或未
声明的 `storage_options`。工厂把已校验配置转换为 `file://` 或 `s3://` filesystem；
客户端输入不能选择 backend、Bucket、前缀或 endpoint。部署必须在存储侧为
`packages/` 和 `results/` 配置满足使用周期的空间及保留策略，本服务不执行对象回收。

## 10. 代码组织

~~~text
src/
  artifact_storage/
    models.py              # 引用、描述符、物化结果和稳定错误
    storage.py             # ArtifactStorage Interface
    fsspec_storage.py      # file/s3 统一实现与底层错误收口
    scratch.py             # ScratchWorkspace 与进程级空间预算
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
      security_batch.py    # 描述符校验、逐包隔离、结果提交和中立进度
    routes/
      uploads.py           # 流式上传
      artifacts.py         # 结果 Artifact 流式下载
    tools/
      security_scan.py     # Tool Schema、进度映射和结果链接
~~~

`artifact_storage` 不依赖 MCP、CLI 或安全检查；`skill_check_runner` Interface
不包含 HTTP、MCP 或存储概念。`mcp_server.services` 只依赖
ArtifactStorage Interface、ScratchWorkspace、CheckRunner 和报告 Builder，不接收
MCP `Context`；Coordinator 把普通本地路径或写入流交给 Builder，因此
`skill_checks` 也不依赖 `artifact_storage`。具体 fsspec backend 仅由
`mcp_server.config` 选择。CLI 使用独立文件输入 Interface，不依赖 `mcp_server`。

核心运行依赖使用官方 `mcp` SDK、Pydantic 2、Starlette、Uvicorn 和 fsspec；S3
可选依赖使用与 fsspec 版本兼容的 s3fs。配置选择 S3 但未安装该依赖时启动失败。
fsspec 与 s3fs 的宽类型只允许在 `fsspec_storage.py` 内通过窄 Protocol 和显式转换
收口；源码和测试必须满足 mypy strict、Pydantic 插件和 Any 表达式 100%。

## 11. 错误表达

稳定错误码按失败边界划分：

| 边界 | 错误码 |
|---|---|
| Tool 请求 | `MCP_INPUT_INVALID`、`BATCH_LIMIT_EXCEEDED` |
| 单包处理 | `ARTIFACT_UNAVAILABLE`、`ARTIFACT_READ_FAILED`、`ARTIFACT_INTEGRITY_FAILED`、`CHECK_EXECUTION_FAILED`、`CHECK_RESULT_INVALID` |
| 批次基础设施 | `STORAGE_UNAVAILABLE`、`SCRATCH_LIMIT_EXCEEDED`、`CHECK_RESULT_WRITE_FAILED` |

单包错误码进入 `package-status.csv`；请求和基础设施错误码进入 MCP Tool error。
HTTP 文件通道使用稳定状态码和等价的清理后错误码。

`inspect()` 或 `materialize()` 针对当前引用返回的不存在、读取失败和完整性错误分别
映射为三个 `ARTIFACT_*` 单包错误。存储初始化失败，以及上传或结果发布等不能归属于
某个输入包的 backend 错误映射为 `STORAGE_UNAVAILABLE`；配置和凭据错误在启动时失败。

| 层级 | 行为 |
|---|---|
| HTTP 认证或上传错误 | 稳定 HTTP 状态与清理后的短消息。 |
| Tool 请求结构错误 | MCP Tool error，不创建结果 Artifact。 |
| 单包引用或扫描错误 | 记录包状态 `FAILED`，继续批次。 |
| 存储初始化失败 | 服务启动失败，不接受请求。 |
| 结果 ZIP 生成或发布失败 | MCP Tool error，不返回结果引用并清理 scratch。 |

底层异常链、Header、Key、凭据、主机路径、对象键、原始 ZIP 内容和未脱敏证据
不能进入 HTTP 响应、MCP error、进度、CSV 或 JSON。批次结束后只要结果
Artifact 成功生成，Tool 调用本身成功；包级失败通过结构化摘要和报告表达。

## 12. 验收

必须验证：

- 大文件上传按块读取，未使用 Base64，也未调用完整正文读取。
- 未认证请求在读取上传字节前返回 `401`，Key canary 不进入异常链或日志。
- 批次严格按输入顺序执行；单包损坏、丢失、完整性错误、超限或扫描失败不影响后续包。
- progress 事件顺序正确，失败包没有完成事件，无回调客户端仍得到最终结果。
- `security-scan.csv` 只包含真实 Finding；所有失败均进入 `package-status.csv`。
- 结果通过受保护 ResourceLink 下载，ToolResult 不包含 ZIP Base64 或自由文本。
- 上传取消、物化失败和结果生成失败会清理 scratch；发布失败不返回引用，并尝试清理
  未完成对象。
- `file` 与 `s3` backend 通过同一 ArtifactStorage 合同测试，包括实现重建后的引用
  解析、发布后大小复核、物化完整性校验、流式读取和底层异常映射。
- scratch 的单工作区上限、进程总预算、异常退出遗留目录清理和并发准入均有边界测试。
- 两个固定真实 Skill ZIP 通过 HTTP 上传、MCP 批次扫描和结果下载端到端回归。
- S3 合同和端到端测试使用真实 MinIO，不以 memory filesystem 代替对象存储语义。
- `/mcp` 与文件路由使用相同 Host/Origin 正反用例；静态认证、并发、scratch 和所有
  资源上限有正反边界测试。
- 安装包、锁文件、Ruff、完整测试、mypy strict、Pydantic 插件和 Any 100% 通过。

## 13. 实现依据

- [Python MCP SDK：在 ASGI 应用中挂载 Streamable HTTP](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/run/asgi.md)
- [Python MCP SDK：进度、调用中通知与取消示例](https://github.com/modelcontextprotocol/python-sdk/blob/main/examples/stories/streaming/README.md)
- [MCP 2026-07-28：无会话 Streamable HTTP 与部署模型](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [fsspec：统一 filesystem 构造与 Interface](https://filesystem-spec.readthedocs.io/en/latest/api.html)
- [fsspec：transaction 与 backend 相关的一致性语义](https://filesystem-spec.readthedocs.io/en/latest/features.html#transactions)
- [fsspec：同步与异步执行模型](https://filesystem-spec.readthedocs.io/en/latest/async.html)
- [s3fs：S3、凭据与兼容对象存储](https://s3fs.readthedocs.io/en/stable/)
