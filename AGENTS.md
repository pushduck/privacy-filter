# AGENTS.md

给 AI 编码助手（Claude Code、Codex、Cursor 等）的项目说明。用户文档见 [README.zh-CN.md](README.zh-CN.md)。

## 项目概览

Go 实现的 PII / 密钥脱敏工具，fork 自 `packyme/privacy-filter`。纯正则、无模型、无 CGO。

- `filter/`：核心检测与替换，对外 API 是 `New`、`NewFromTOML`、`Redact`、`Stats`。改这里就是改检测行为。三层：`pii.go`、`secrets.go`、`proxy.go`（mihomo / Clash 配置、分享链接、订阅；与其他层重叠时优先）。
- `internal/webui/`：脱敏对比网页，`index.html` 通过 go:embed 内嵌，网关挂在 `/_pf/ui/`、HTTP 服务挂在 `/ui/`。
- `rules/`：`gitleaks.toml` 通过 `embed.go` 编译进二进制。
- `internal/gateway/`：LLM API 脱敏网关。`walk` 按 `contentKeys` / `skipKeys` 遍历 JSON，`proxy` 负责反向代理，`logging.go` 负责分级请求日志。
- `internal/rulesload/`：各 cmd 共用的规则加载入口。新增 cmd 时用 `rulesload.Load()`，不要自己调 `filter.New`。
- `internal/httpapi/`、`internal/grpcapi/`：薄封装，不放业务逻辑。
- `cmd/{gateway,server,http,grpc}`：只做参数解析和启动，产物名为 `pf-<目录名>`。

## 常用命令

```bash
make build    # 编译到 bin/
make test     # go test ./...
make vet      # go vet + gofmt 检查，CI 同款；提交前必须通过
make dist     # 交叉编译 6 个平台到 dist/（scripts/dist.sh）
```

只验证个别平台能否编译：`PLATFORMS="windows/amd64" scripts/dist.sh test`

## 约定

- 模块路径是 `privacyfilter`（沿用上游）。import 写 `privacyfilter/...`，不要改成 GitHub 路径。
- 代码注释、日志、错误信息用中文，与上游风格保持一致。
- 必须 `CGO_ENABLED=0` 能交叉编译到 linux / darwin / windows × amd64 / arm64。不要引入需要 CGO 或平台专有的依赖。
- `filter` 包只允许依赖 `BurntSushi/toml`，新依赖放在 `internal/` 或 `cmd/`。
- 改检测逻辑时，在 `filter/cases_test.go`、`filter_test.go` 或 `proxy_test.go`（代理配置层）补用例；改网关的字段规则时，在 `internal/gateway/gateway_test.go` 补用例。
- 发布方式是推送 `v*` 标签，由 `.github/workflows/release.yml` 构建并发布。不要手动上传产物。
- 本 fork 不维护 Docker。仓库里的 `Dockerfile` / `compose.yml` 是上游原样文件，不在 CI 中构建。

## 安全要求（网关）

- **fail-closed**：请求体无法解析、编码不支持时拒绝转发，绝不放行原文。
- 日志：默认级别（`basic` / `request`）**不得记录原文或命中文本**；原文只允许在用户显式开启 `hits` / `full` 时输出。**任何级别都不得记录请求头**（请求头里有 API Key）。日志文件权限保持 `0600`。
- 日志实现在 `internal/gateway/logging.go`。一次请求的多行日志要拼成一次 `Print` 输出，避免并发请求的日志交错。
- `skipKeys` 中的字段（signature、图片 data、id、tools schema 等）一旦被改写，上游会直接报错。新增协议适配时，先确认哪些字段必须原样保留。
- 未命中时必须转发原始字节，不要重新序列化。
- 对比网页接口会把命中原文返回给浏览器，不写日志、不加载外部资源，只要求 `Content-Type: application/json`（防跨站简单请求）。
- 默认只监听 `127.0.0.1`。

## 同步上游

```bash
git fetch upstream && git merge upstream/main
```

冲突多发在 `cmd/*/main.go`：上游仍用 `filter.New(path)`，本 fork 改成了 `rulesload.Load()`。合并时保留本 fork 的写法。

## 提交信息

格式为 `<type>(<范围>):<中文说明>`，例如 `feat(gateway):支持自定义上游`、`fix(filter):修复手机号边界`、`chore(ci):...`。
