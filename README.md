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
