# Privacy Filter — 隐私过滤（Go）

[English](README.md) | **简体中文**

在文本进入 LLM 之前，过滤掉用户的敏感信息（PII / 密钥）。
纯 Go、无模型、无 GPU、无 CGO：单个静态二进制，任意长度的文本都在毫秒级完成。

> 本仓库 fork 自 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)，在上游基础上新增：
> - **`pf-gateway` 通用 LLM API 脱敏网关**：任何支持自定义 Base URL 的客户端都能接入，不和具体工具绑定。
> - **规则内嵌进二进制**：单文件即可运行，不再依赖工作目录下的 `rules/`。
> - **多平台发布**：GitHub Actions 自动构建 linux / macOS / windows × amd64 / arm64 可执行文件。

---

## 四种用法

| 用法 | 入口 | 适合 |
|---|---|---|
| **脱敏网关** | `pf-gateway`（`cmd/gateway`） | 本地或团队给 Claude Code、Codex、Cline、Cherry Studio、SDK 脚本等统一加一层脱敏 |
| **核心包** | `import "privacyfilter/filter"` | 自研网关直接调用，一次函数调用，没有 HTTP 跳转 |
| **HTTP 服务** | `pf-http`（`cmd/http`） | 其他语言通过 REST 调用 |
| **gRPC 服务** | `pf-grpc`（`cmd/grpc`），接口见 `proto/filter.proto` | 其他语言通过 gRPC 调用 |

另有 `pf-server`（`cmd/server`），在同一个进程里同时提供 HTTP 和 gRPC。

---

## 两层检测

| 层 | 负责 | 技术 |
|---|---|---|
| 结构化 PII | 邮箱、手机号、身份证、银行卡（Luhn 校验）、IP | 正则 |
| 密钥 / 凭证 | API key、token、私钥、句子里的口令、未知高熵随机串 | gitleaks 规则集（关键词预筛）+ 上下文正则 + 香农熵兜底 |

各层产出 `(起点, 终点, 占位符)` 区间，合并去重叠后单遍重建文本。
占位符带类型（`[邮箱] [电话] [身份证] [银行卡] [IP] [密钥]`），不可逆，不能还原。

> 不识别人名、地名、机构名。这类识别需要 NER 模型，在 CPU 上处理长文本要数秒，已按需求移除。
> 高危身份信息（身份证、银行卡、密钥等）全部由正则覆盖。

---

## 安装

### 下载可执行文件（推荐）

到 [Releases](../../releases) 下载对应平台的压缩包：

| 平台 | 文件 |
|---|---|
| Linux x86_64 / ARM64 | `privacy-filter_<版本>_linux_amd64.tar.gz` / `_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `privacy-filter_<版本>_darwin_amd64.tar.gz` / `_darwin_arm64.tar.gz` |
| Windows x64 / ARM64 | `privacy-filter_<版本>_windows_amd64.zip` / `_windows_arm64.zip` |

压缩包内含 `pf-gateway`、`pf-server`、`pf-http`、`pf-grpc` 四个可执行文件，规则已内嵌，可单独拷走使用。
`checksums.txt` 提供 SHA-256 校验值。

macOS 首次运行如果被 Gatekeeper 拦截，执行：`xattr -d com.apple.quarantine ./pf-gateway`

### 源码安装

```bash
git clone https://github.com/pushduck/privacy-filter.git && cd privacy-filter
make build        # 产物在 bin/
```

> 模块名是 `privacyfilter`（沿用上游），不是 GitHub 路径，所以不支持 `go install …@latest`。

---

## 用法

### 1. 脱敏网关 `pf-gateway`

```bash
./pf-gateway                     # 默认监听 127.0.0.1:8787
```

客户端把官方 Base URL 换成网关地址。API Key 照常填写，网关只透传、不保存：

| 上游 | 网关 Base URL |
|---|---|
| Anthropic | `http://127.0.0.1:8787/anthropic` |
| OpenAI | `http://127.0.0.1:8787/openai/v1` |
| Gemini | `http://127.0.0.1:8787/gemini` |
| DeepSeek | `http://127.0.0.1:8787/deepseek` |
| OpenRouter | `http://127.0.0.1:8787/openrouter/v1` |

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic claude      # Claude Code
OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1 codex          # Codex CLI / OpenAI SDK
```

Cherry Studio、Cline、Continue、ChatBox 等：在供应商设置里把 API 地址改成上表中的地址。

**自定义上游**（中转站、公司内部模型服务等）：会与内置上游合并，同名时覆盖内置。

```bash
./pf-gateway -routes "corp=https://llm.example.com,relay=https://api.relay.com"
# 客户端：https://llm.example.com/v1  →  http://127.0.0.1:8787/corp/v1
./pf-gateway -no-default-routes -routes "corp=https://llm.example.com"   # 只用自定义上游
```

上游需要走代理时，设置 `HTTPS_PROXY=http://127.0.0.1:7890` 即可，Go 会自动读取。

**纯文本脱敏**（脚本、剪贴板等）：

```bash
pbpaste | curl -s --data-binary @- http://127.0.0.1:8787/_pf/redact | pbcopy
curl http://127.0.0.1:8787/_pf/health
```

**日志**

```bash
pf-gateway -log console,~/Library/Logs/pf-gateway.log -log-level hits    # 同时输出到控制台和文件
pf-gateway -log /tmp/pf.log -log-level full -log-max-len 500            # 只写文件，打印字段全文
```

| 级别 `-log-level` | 内容 | 含敏感原文 |
|---|---|---|
| `basic`（默认） | 有命中的请求打一行：命中类型与数量；上游返回 4xx/5xx 或连接失败时也会记录 | 否 |
| `request` | 每个请求一行：路由 → 上游完整地址、`model`、是否 `stream`、User-Agent、请求体大小（脱敏前→后）、命中统计、扫描耗时，以及上游状态码和首字节耗时 | 否 |
| `hits` | 在 `request` 基础上，列出每处命中：类型、原文、JSON 路径（如 `messages[3].content[0].text`），以及前后各 24 字的「原文 / 替换」对照 | **是** |
| `full` | 在 `hits` 基础上，打印每个被改写字段的完整原文和替换后文本，长度受 `-log-max-len` 限制（默认 2000 字，0 表示不截断） | **是** |

- Claude Code 等客户端每轮都会重发全部历史。`hits` / `full` 级别默认只打印**新出现的命中**，摘要中以「新增 N」标出；加 `-log-repeat` 可每次都完整打印。
- 日志文件以追加方式写入，权限为 `0600`，不会自动轮转。`hits` / `full` 级别会把密钥原文写进日志，排查完问题请及时调回 `basic` 并删除日志。
- 任何级别都不记录请求头（含 API Key）。

**脱敏范围与安全策略**

- 只改写请求体中的对话内容，即 `content / text / prompt / input / instructions / system / output / arguments / parts` 等子树里的字符串。兼容 Anthropic Messages、OpenAI Chat / Responses、Gemini 等格式。
- 不改动协议字段：`tools` schema、`model`、各类 `id`、thinking `signature`、图片 base64、`url` 等，避免请求被破坏。
- 未命中时转发原始字节；请求体不是合法 JSON，或使用了不支持的 `Content-Encoding` 时，直接拒绝转发（fail-closed）。
- 响应（含 SSE 流）原样透传，模型回复不做脱敏。
- 默认日志只记录命中类型和数量，不记录原文（需要排查时见上文「日志」）。默认只监听本机。

**局限**

- 脱敏不可逆：模型看到的是 `[密钥]` 这类占位符。如果让 AI 改写含密钥的文件，它可能把占位符写回文件。
- 走厂商自家后端、不能改 Base URL 的产品（网页版 ChatGPT / Claude、Cursor 内置模型等）无法接入。

### 2. 核心包（推荐自研网关使用）

```go
import (
    "privacyfilter/filter"
    "privacyfilter/rules"
)

// 启动时创建一次，并发安全，可全局复用
f, err := filter.NewFromTOML(rules.GitleaksTOML)  // 使用内嵌规则
// 或 filter.New("rules/gitleaks.toml")         // 读文件；传 "" 用内置兜底规则

res := f.Redact(userPrompt)
forwardToLLM(res.Redacted)
```

`filter.Result` 包含：`Redacted`（脱敏后文本）、`Hit`、`Count`、`Entities`（命中明细，含类型与字节偏移）。

> 从你自己的网关模块引用本包：放进同一个 monorepo，或在网关的 go.mod 里加
> `replace privacyfilter => ../privacy-filter`。`filter` 包只依赖 `BurntSushi/toml`。

### 3. HTTP 服务

```bash
./pf-http                    # 默认 :8088
curl http://127.0.0.1:8088/health
curl -X POST http://127.0.0.1:8088/redact -H 'Content-Type: application/json' \
  -d '{"text":"我的邮箱是 a@b.com，密码是 Hunter2xy"}'
# {"redacted":"我的邮箱是 [邮箱]，密码是 [密钥]","hit":true,"count":2,"entities":[...],"elapsed_ms":0.08}
```

接口：`GET /health`、`POST /redact`、`POST /redact/batch`（请求体 `{"texts":[...]}`，返回结果数组）。

### 4. gRPC 服务

```bash
./pf-grpc                    # 默认 :8089
```

服务名 `filter.v1.PrivacyFilter`，方法 `Redact` / `RedactBatch`，定义见 `proto/filter.proto`。

---

## 配置

| 变量 / 参数 | 默认 | 适用 | 说明 |
|---|---|---|---|
| `PF_LISTEN` / `-listen` | `127.0.0.1:8787` | gateway | 监听地址；要给局域网用改成 `0.0.0.0:8787` |
| `PF_ROUTES` / `-routes` | 空 | gateway | 自定义上游，`名称=URL`，逗号分隔，与内置上游合并 |
| `PF_NO_DEFAULT_ROUTES=1` / `-no-default-routes` | 关 | gateway | 不加载内置上游 |
| `PF_LOG` / `-log` | `console` | gateway | 日志输出：`console`、`stdout`、文件路径，逗号分隔可写多个 |
| `PF_LOG_LEVEL` / `-log-level` | `basic` | gateway | `basic` / `request` / `hits` / `full`，见上文「日志」 |
| `PF_LOG_MAX_LEN` / `-log-max-len` | `2000` | gateway | `full` 级别下单个字段最多打印的字符数，0 表示不截断 |
| `PF_LOG_REPEAT=1` / `-log-repeat` | 关 | gateway | 重复打印历史消息中已出现过的命中 |
| `PF_PORT` | `8088` | http / server | HTTP 监听端口 |
| `PF_GRPC_PORT` | `8089` | grpc / server | gRPC 监听端口 |
| `PF_GITLEAKS_TOML` | 空（用内嵌规则） | 全部 | 外部 gitleaks 规则文件路径；加载失败时退回内嵌规则 |

---

## 开发

需要 Go（版本见 `go.mod`）。常用命令：

```bash
make build        # 编译本机平台全部可执行文件到 bin/
make test         # go test ./...
make vet          # go vet + gofmt 检查（CI 同款）
make dist         # 交叉编译 6 个平台并打包到 dist/（脚本：scripts/dist.sh）
make rules        # 从 gitleaks 上游更新 rules/gitleaks.toml（更新后需重新编译）
make run-gateway  # go run ./cmd/gateway
```

只编译部分平台：`PLATFORMS="linux/amd64 darwin/arm64" scripts/dist.sh v0.0.1`

重新生成 gRPC 代码：

```bash
protoc -I. --go_out=. --go_opt=module=privacyfilter \
       --go-grpc_out=. --go-grpc_opt=module=privacyfilter proto/filter.proto
```

### 目录结构

```
privacy-filter/
├── filter/                  核心包：Filter / New / NewFromTOML / Redact；pii.go、secrets.go
├── rules/                   gitleaks.toml + embed.go（go:embed 内嵌进二进制）
├── internal/
│   ├── gateway/             LLM API 脱敏网关（JSON 遍历脱敏 + 反向代理）
│   ├── httpapi/  grpcapi/   HTTP / gRPC 薄封装
│   └── rulesload/           各 cmd 共用的规则加载（PF_GITLEAKS_TOML 或内嵌）
├── cmd/
│   ├── gateway/             pf-gateway
│   ├── server/              pf-server（HTTP + gRPC 同进程）
│   ├── http/  grpc/         pf-http / pf-grpc
├── proto/  gen/filterpb/    gRPC 定义与生成代码
├── scripts/                 dist.sh（交叉编译打包）、fetch_rules.sh（更新规则）
├── .github/workflows/       ci.yml、release.yml
├── Makefile
└── AGENTS.md                给 AI 编码助手的项目说明
```

### 发布

```bash
git tag v1.0.0 && git push origin v1.0.0
```

推送 `v*` 标签后，`release.yml` 会先跑测试，再交叉编译 linux / darwin / windows × amd64 / arm64，上传到 GitHub Release（附 `checksums.txt`）。

也可以在 Actions 页面手动触发 Release 工作流：只构建产物（以 artifact 形式下载），不发布。

### 同步上游

```bash
git remote add upstream https://github.com/packyme/privacy-filter.git   # 只需一次
git fetch upstream && git merge upstream/main
```

---

## 性能（本机 benchmark，合成的高密度 PII 文本，属最坏情况）

| 文本长度 | 耗时 |
|---|---|
| ~50 B | ~0.01ms |
| ~2 KB | ~0.46ms |
| ~32 KB | ~9ms |

两层检测都是 O(n)。真实 prompt 中 PII 没这么密集，会更快。

---

## 备注

- gitleaks 规则在 Go 下全部原生编译（Go 的 `regexp` 即 RE2，与 gitleaks 同源）。
- Go `regexp` 是线性时间，没有灾难性回溯（ReDoS）风险。
- gitleaks 不支持前后向断言，手机号、身份证等的数字边界在匹配后手工校验。
- 高熵兜底已排除 hex 哈希（如 git SHA）和 UUID，但仍可能误伤长 base64 串，可调阈值或加白名单。
- 若用 HTTP/gRPC 服务对接：建议设 150–300ms 超时，失败时 fail-closed（拒绝请求，而不是放行原文）。

## License

MIT，见 [LICENSE](LICENSE)。上游版权归原作者所有。
