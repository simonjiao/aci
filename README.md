# Skill Security

面向 Skill ZIP 包的确定性静态安全扫描 Module。公开入口为 `compile_rules()` 和
`SecurityScan.scan()`；返回结构化结果，不执行包内内容、不访问网络、不生成报告文件。

## 开发检查

```bash
uv sync --locked
uv run --locked pre-commit install
uv run --locked pre-commit run --all-files
uv run --locked ruff check src tests
uv run --locked python -m unittest discover -s tests
```

该 hook 仅作用于当前 clone，且可被 Git 显式跳过；不可绕过的门禁需要 CI 或服务端策略。

规则位于 `config/security-rules.json`。接口、行为和安全边界详见
[设计文档](docs/detectors/skill-security-scan-module-design.md)。

## CLI

```bash
uv run --locked skillqa check --config config/skillqa.toml --output result.zip skill.zip
```

输入可为 ZIP 文件或目录；目录按名称扫描直接子级的 `.zip`（不递归），支持相对路径。
结果 ZIP 中的 `security-scan.csv` 用于人工复核，`security-metadata.json` 保存扫描元数据。

退出码依次表示：`0` 通过、`1` 需要复核、`2` 参数、配置或输出错误、`3` 扫描失败。

## MCP

```bash
export SKILLQA_API_KEY='<至少 32 位的静态密钥>'
uv run --locked skillqa-mcp --config config/mcp.toml
```

服务在 `http://127.0.0.1:8000/mcp` 提供 Streamable HTTP。Tool
`scan_skill_security` 接收一个 ZIP 的文件名和 Base64 内容，返回结果摘要和受保护的
`ResourceLink`。客户端使用同一个 Bearer Key 从该链接流式下载结果 ZIP；结果存储可
配置为本地文件系统或安装 `s3` extra 后使用 S3 兼容对象存储。
