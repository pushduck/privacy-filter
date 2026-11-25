# Privacy Filter (Go)

**English** | [简体中文](README.zh-CN.md)

Strip sensitive user data (PII / secrets) from text before it reaches an LLM.
Pure Go, no model, no GPU, no CGO — a single static binary, millisecond latency on text of any length.

> This repository is a fork of [packyme/privacy-filter](https://github.com/packyme/privacy-filter). Additions:
> - **`pf-gateway`, a generic LLM API redaction gateway** — works with any client that lets you set a custom Base URL.
> - **Rules embedded in the binary** — a single file runs anywhere, no `rules/` directory required.
> - **Multi-platform releases** — GitHub Actions builds linux / macOS / windows × amd64 / arm64 executables.

---

## Four ways to use it

| Mode | Entry point | Use case |
|---|---|---|
| **Redaction gateway** | `pf-gateway` (`cmd/gateway`) | Put one redaction layer in front of Claude Code, Codex, Cline, Cherry Studio, SDK scripts, … |
| **Core package** | `import "privacyfilter/filter"` | Call it straight from your own Go gateway — one function call, no HTTP hop |
| **HTTP service** | `pf-http` (`cmd/http`) | REST access from any language |
| **gRPC service** | `pf-grpc` (`cmd/grpc`), interface in `proto/filter.proto` | gRPC access from any language |

`pf-server` (`cmd/server`) serves HTTP and gRPC from a single process.

---

## Three detection layers

| Layer | Covers | Technique |
|---|---|---|
| Structured PII | Email, phone, national ID, bank card (Luhn-checked), IP | Regex |
| Secrets / credentials | API keys, tokens, private keys, passwords written in prose, unknown high-entropy strings | gitleaks ruleset (keyword pre-filter) + contextual regex + Shannon-entropy fallback |
| Proxy configs | mihomo / Clash configs, sing-box / Xray JSON, node share links, subscription URLs and base64 subscription bodies | Line-based YAML/JSON field scan + share-link parsing |

Each layer emits `(start, end, placeholder)` spans; the spans are merged and de-overlapped (the proxy layer wins on overlap), then the text is rebuilt in a single pass.
Placeholders are typed — `[邮箱]` (email), `[电话]` (phone), `[身份证]` (national ID), `[银行卡]` (bank card), `[IP]`, `[密钥]` (secret), `[服务器]` (server), `[域名]` (SNI / host), `[用户名]` (username), `[订阅链接]` (subscription URL), `[订阅内容]` (subscription body), `[节点]` (opaque node link) — and irreversible.

> No person / place / organization name recognition — that needs an NER model, which costs seconds of CPU time on long text. Known fixed names or code names can be configured via "Custom matching".

---

## Install

### Download a binary (recommended)

Grab the archive for your platform from [Releases](../../releases):

| Platform | File |
|---|---|
| Linux x86_64 / ARM64 | `privacy-filter_<version>_linux_amd64.tar.gz` / `_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `privacy-filter_<version>_darwin_amd64.tar.gz` / `_darwin_arm64.tar.gz` |
| Windows x64 / ARM64 | `privacy-filter_<version>_windows_amd64.zip` / `_windows_arm64.zip` |

Each archive contains `pf-gateway`, `pf-server`, `pf-http` and `pf-grpc`. Rules are embedded, so each binary can be copied anywhere on its own.
`checksums.txt` lists SHA-256 sums.

If macOS Gatekeeper blocks the first run: `xattr -d com.apple.quarantine ./pf-gateway`

### From source

```bash
git clone https://github.com/pushduck/privacy-filter.git && cd privacy-filter
make build        # outputs to bin/
```

> The module path is `privacyfilter` (kept from upstream), not the GitHub path, so `go install …@latest` is not supported.

---

## Usage

### 1. Redaction gateway `pf-gateway`

```bash
./pf-gateway                     # listens on 127.0.0.1:8787 by default
```

Point your client's Base URL at the gateway. Keep using your normal API key — the gateway passes it through and never stores it:

| Upstream | Gateway Base URL |
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

**Custom upstreams** (relays, in-house model services, …) are merged with the built-ins; a matching name overrides the built-in one.

```bash
./pf-gateway -routes "corp=https://llm.example.com,relay=https://api.relay.com"
# client: https://llm.example.com/v1  →  http://127.0.0.1:8787/corp/v1
./pf-gateway -no-default-routes -routes "corp=https://llm.example.com"   # custom upstreams only
```

If upstreams must go through a proxy, set `HTTPS_PROXY=http://127.0.0.1:7890`.

**Plain-text redaction** (scripts, clipboard, …):

```bash
pbpaste | curl -s --data-binary @- http://127.0.0.1:8787/_pf/redact | pbcopy
curl http://127.0.0.1:8787/_pf/health
```

**Comparison web page**: open `http://127.0.0.1:8787/_pf/ui/`, paste text (or drop a file) on the left and see the redacted result on the right as you type. Switch to "原文标注" (annotated original) to see each replaced span and its type; the hit list below jumps to each hit. Built-in samples cover general text, mihomo configs, share links / subscriptions and sing-box JSON. The page loads no external resources and its API writes no logs; it returns matched originals to the browser, so keep it on localhost.

**Logging**

```bash
pf-gateway -log console,~/Library/Logs/pf-gateway.log -log-level hits    # console + file
pf-gateway -log /tmp/pf.log -log-level full -log-max-len 500            # file only, full field text
```

| `-log-level` | Content | Contains raw secrets |
|---|---|---|
| `basic` (default) | One line per request with hits: hit types and counts. Upstream 4xx/5xx and connection errors are also logged | No |
| `request` | One line per request: route → full upstream URL, `model`, `stream`, User-Agent, body size (before → after), hit stats, scan time, plus upstream status and time to first byte | No |
| `hits` | Everything in `request`, plus each hit: type, original text, JSON path (e.g. `messages[3].content[0].text`), and an original / replaced snippet with 24 chars of context on each side | **Yes** |
| `full` | Everything in `hits`, plus the full original and redacted text of every rewritten field, capped by `-log-max-len` (default 2000 chars, 0 = no limit) | **Yes** |

- Clients like Claude Code resend the whole history every turn. At `hits` / `full`, only **new hits** are printed by default (the summary shows the new count); add `-log-repeat` to print every hit every time.
- Log files are appended to with mode `0600` and are not rotated. `hits` / `full` write raw secrets to the log — switch back to `basic` and delete the log once you're done debugging.
- Request headers (including API keys) are never logged at any level.

**What gets redacted, and safety behavior**

- Only conversation content in the request body is rewritten: strings under `content / text / prompt / input / instructions / system / output / arguments / parts`. This covers Anthropic Messages, OpenAI Chat / Responses, Gemini and similar formats.
- Protocol fields are never touched — `tools` schemas, `model`, ids, thinking `signature`, image base64, `url`, … — so requests stay valid.
- With no hits, the original bytes are forwarded unchanged. Invalid JSON or an unsupported `Content-Encoding` is rejected, never forwarded raw (fail-closed).
- Responses (including SSE streams) pass through untouched; model replies are not redacted.
- By default, logs record hit types and counts only, never the original text (see "Logging" for debugging). Listens on localhost by default.

**Limitations**

- Redaction is irreversible: the model sees placeholders like `[密钥]`. If you ask an AI to rewrite a file that contains secrets, it may write the placeholder back into the file.
- Products that use the vendor's own backend and don't allow a custom Base URL (ChatGPT / Claude web apps, Cursor's built-in models, …) can't use the gateway.

### Proxy config redaction (mihomo / Clash)

When you paste a mihomo config, node links or a subscription into an AI chat, server addresses, credentials and subscription URLs are replaced, while node names, ports, protocols, transport options and rules are kept so the model can still reason about the config:

```yaml
proxies:
  - name: "香港 01"            # node name kept
    type: vless
    server: [服务器]
    port: 443
    uuid: [密钥]
    servername: [域名]
    reality-opts:
      public-key: [密钥]
      short-id: [密钥]
  - {name: jp, type: ss, server: [服务器], port: 8388, cipher: aes-256-gcm, password: "[密钥]"}
proxy-providers:
  airport:
    type: http
    url: "[订阅链接]"
    health-check:
      url: https://cp.cloudflare.com/generate_204   # non-subscription URL kept
```

| Content | When | Result |
|---|---|---|
| Share links `vless:// vmess:// ss:// ssr:// trojan:// hysteria2:// hy2:// tuic:// anytls:// wireguard:// socks5://` … | Any text | `scheme://[密钥]@[服务器]:port?…&sni=[域名]&pbk=[密钥]…#name`; fully base64 links (vmess / ssr / legacy ss) become `[节点]`; localhost / loopback hosts are kept |
| Subscription URLs | Any text | URLs with panel / converter patterns (`/api/v1/client/subscribe`, `/link/`, `/sub?target=clash`, `flag=clash`, `clash=1`, …) become `[订阅链接]` |
| base64 subscription bodies | Any text | Long base64 strings that decode to share links become `[订阅内容]` |
| Config fields | Only when the text has `proxies:` / `proxy-providers:` / `listeners:` sections or node types like `type: vless` | `server` → `[服务器]`; `password uuid psk private-key public-key short-id auth-str obfs-password token secret pre-shared-key …` → `[密钥]`; `servername sni host` → `[域名]`; `username` → `[用户名]`; `proxy-providers.*.url` → `[订阅链接]`; also `authentication`, `users`, `ca/cert/key: |` blocks |

Handles block style, flow style `{k: v}`, commented-out fields (`# password: xxx`), block scalars (`|`, `>`), block lists, and sing-box / Xray JSON fields such as `"server_name"`, `"public_key"`, `"id"`. Plain YAML `server:` / `host:` / `key:` fields are left alone unless the proxy-config markers above are present.

### Custom matching (names, code names, other fixed words)

Regex can't detect personal names. Put your name, initials, project code names and so on in a config file; matches are replaced with the given value, or with the same number of `*` characters when `replace` is omitted (`天穹计划` → `****`). JSON or YAML; a single word, a word list, or a rule list:

```yaml
# custom.yaml
- match: [yeshuwei, ysw, 叶书伟]   # string or array
  replace: "[姓名]"                 # optional; defaults to an equal-length * mask
- 天穹计划                          # bare word = equal-length mask
- match: ACME
  case_sensitive: true             # case-insensitive by default
  allow_partial: true              # ASCII words match whole words by default (ysw doesn't hit ysww / user_ysw)
```

```json
["yeshuwei", "ysw", {"match": "叶书伟", "replace": "[姓名]"}]
```

```bash
PF_CUSTOM_RULES=./custom.yaml ./pf-gateway        # or ./pf-gateway -custom ./custom.yaml
PF_CUSTOM_RULES=a.yaml,b.json ./pf-http          # comma-separated for multiple files
```

- Literal matching (not regex); no word-boundary check for CJK.
- Takes priority over other layers, except when the word lies entirely inside another hit (email, secret…), where the outer hit is redacted as a whole so nothing around it leaks.
- If a config file can't be read or parsed (including misspelled fields) the program **exits** instead of running with incomplete rules; startup logs show the word count only, never the words.

### 2. Core package

```go
import (
    "privacyfilter/filter"
    "privacyfilter/rules"
)

// Create once at startup; concurrency-safe.
f, err := filter.NewFromTOML(rules.GitleaksTOML)  // embedded rules
// or filter.New("rules/gitleaks.toml")         // from file; "" = built-in fallback rules

res := f.Redact(userPrompt)
forwardToLLM(res.Redacted)
```

`filter.Result`: `Redacted`, `Hit`, `Count`, `Entities` (type and byte offsets).

> To use the package from your own module, put it in the same monorepo or add
> `replace privacyfilter => ../privacy-filter` to your go.mod. `filter` depends only on `BurntSushi/toml`.

### 3. HTTP service

```bash
./pf-http                    # default :8088
curl -X POST http://127.0.0.1:8088/redact -H 'Content-Type: application/json' \
  -d '{"text":"我的邮箱是 a@b.com，密码是 Hunter2xy"}'
# {"redacted":"我的邮箱是 [邮箱]，密码是 [密钥]","hit":true,"count":2,"entities":[...],"elapsed_ms":0.08}
```

The comparison web page is served at `http://127.0.0.1:8088/ui/` (also by `pf-server`).

Endpoints: `GET /health`, `POST /redact`, `POST /redact/batch` (body `{"texts":[...]}`, returns an array of results).

### 4. gRPC service

```bash
./pf-grpc                    # default :8089
```

Service `filter.v1.PrivacyFilter`, methods `Redact` / `RedactBatch`, defined in `proto/filter.proto`.

---

## Configuration

| Env var / flag | Default | Applies to | Description |
|---|---|---|---|
| `PF_LISTEN` / `-listen` | `127.0.0.1:8787` | gateway | Listen address; use `0.0.0.0:8787` to serve your LAN |
| `PF_ROUTES` / `-routes` | empty | gateway | Custom upstreams, `name=URL`, comma-separated, merged with the built-ins |
| `PF_NO_DEFAULT_ROUTES=1` / `-no-default-routes` | off | gateway | Don't load the built-in upstreams |
| `PF_LOG` / `-log` | `console` | gateway | Log targets: `console`, `stdout`, or file paths, comma-separated |
| `PF_LOG_LEVEL` / `-log-level` | `basic` | gateway | `basic` / `request` / `hits` / `full`, see "Logging" above |
| `PF_LOG_MAX_LEN` / `-log-max-len` | `2000` | gateway | Max characters printed per field at `full`; 0 = no limit |
| `PF_LOG_REPEAT=1` / `-log-repeat` | off | gateway | Re-print hits already seen in earlier requests |
| `PF_PORT` | `8088` | http / server | HTTP listen port |
| `PF_GRPC_PORT` | `8089` | grpc / server | gRPC listen port |
| `PF_GITLEAKS_TOML` | empty (embedded rules) | all | External gitleaks rules file; falls back to the embedded rules if it fails to load |
| `PF_CUSTOM_RULES` / `-custom` | empty | all (`-custom` gateway only) | Custom matching config files (JSON/YAML), comma-separated; exits on load failure, see "Custom matching" |

---

## Development

Requires Go (version in `go.mod`).

```bash
make build        # build all binaries for the host platform into bin/
make test         # go test ./...
make vet          # go vet + gofmt check (same as CI)
make dist         # cross-compile 6 platforms and package into dist/ (scripts/dist.sh)
make rules        # refresh rules/gitleaks.toml from gitleaks upstream (rebuild afterwards)
make run-gateway  # go run ./cmd/gateway
```

Build only some platforms: `PLATFORMS="linux/amd64 darwin/arm64" scripts/dist.sh v0.0.1`

Regenerate gRPC code:

```bash
protoc -I. --go_out=. --go_opt=module=privacyfilter \
       --go-grpc_out=. --go-grpc_opt=module=privacyfilter proto/filter.proto
```

### Layout

```
privacy-filter/
├── filter/                  core package: Filter / New / NewFromTOML / Redact; pii.go, secrets.go, proxy.go
├── rules/                   gitleaks.toml + embed.go (go:embed into the binaries)
├── internal/
│   ├── gateway/             LLM API redaction gateway (JSON walk + reverse proxy)
│   ├── webui/               comparison web page (embedded index.html)
│   ├── httpapi/  grpcapi/   thin HTTP / gRPC wrappers
│   └── rulesload/           shared rule loading (PF_GITLEAKS_TOML or embedded)
├── cmd/
│   ├── gateway/             pf-gateway
│   ├── server/              pf-server (HTTP + gRPC in one process)
│   ├── http/  grpc/         pf-http / pf-grpc
├── proto/  gen/filterpb/    gRPC definition and generated code
├── scripts/                 dist.sh (cross-compile + package), fetch_rules.sh (update rules)
├── .github/workflows/       ci.yml, release.yml
├── Makefile
└── AGENTS.md                project notes for AI coding agents
```

### Releasing

```bash
git tag v1.0.0 && git push origin v1.0.0
```

Pushing a `v*` tag makes `release.yml` run the tests, cross-compile linux / darwin / windows × amd64 / arm64, and upload the archives plus `checksums.txt` to a GitHub Release.
You can also trigger the Release workflow manually from the Actions tab; it then only builds and uploads the archives as a workflow artifact.

### Syncing upstream

```bash
git remote add upstream https://github.com/packyme/privacy-filter.git   # once
git fetch upstream && git merge upstream/main
```

---

## Performance (local benchmark, synthetic high-density PII text — worst case)

| Text length | Latency |
|---|---|
| ~50 B | ~0.01ms |
| ~2 KB | ~0.46ms |
| ~32 KB | ~9ms |

All layers are O(n). Real prompts are faster.

---

## Notes

- All gitleaks rules compile natively in Go (Go's `regexp` is RE2, the same engine gitleaks uses).
- Go `regexp` runs in linear time — no ReDoS risk.
- gitleaks has no look-around, so digit boundaries for phone / national ID are checked after matching.
- The entropy fallback skips hex hashes (e.g. git SHAs) and UUIDs, but may still flag long base64 strings — tune the threshold or add an allowlist.
- When integrating via HTTP/gRPC: use a 150–300ms timeout and fail closed (reject rather than forward raw text).

## License

MIT, see [LICENSE](LICENSE). Upstream copyright belongs to the original authors.
