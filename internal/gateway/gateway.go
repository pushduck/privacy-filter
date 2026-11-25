// Package gateway 实现通用 LLM API 脱敏网关：对请求体中的对话内容脱敏后反向代理到上游。
//
// 客户端把 Base URL 指向 http://<网关>/<路由名>，网关按路由名选上游，
// 只改写请求体里的对话文本，响应（含 SSE 流）原样透传。与具体客户端、厂商协议无关。
package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"privacyfilter/filter"
)

// DefaultRoutes 是内置上游。PF_ROUTES 中的同名路由会覆盖它们。
var DefaultRoutes = map[string]string{
	"anthropic":  "https://api.anthropic.com",
	"openai":     "https://api.openai.com",
	"gemini":     "https://generativelanguage.googleapis.com",
	"deepseek":   "https://api.deepseek.com",
	"openrouter": "https://openrouter.ai/api",
}

// contentKeys 下的字符串（含整棵子树）视为对话内容，需要脱敏。
var contentKeys = toSet("content", "text", "prompt", "input", "instructions",
	"system", "output", "arguments", "query", "parts", "systemInstruction")

// skipKeys 是协议元数据或二进制，永不改动也不深入：
// 改了会破坏请求（thinking signature、图片 base64、工具 schema、各类 id 等）。
var skipKeys = toSet("tools", "functions", "tool_choice", "response_format",
	"model", "id", "type", "role", "name", "signature", "data", "media_type",
	"mime_type", "mimeType", "url", "image_url", "file_id", "inlineData",
	"inline_data", "cache_control", "tool_use_id", "tool_call_id", "call_id",
	"encrypted_content", "metadata", "stop_sequences", "stop")

func toSet(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// Change 是一个被改写的字符串字段。
type Change struct {
	Path     string          // JSON 路径，例如 messages[3].content[0].text
	Before   string          // 原文
	After    string          // 脱敏后
	Entities []filter.Entity // 命中明细（偏移基于 Before）
}

// Stats 记录一次请求的命中情况与请求元信息。
type Stats struct {
	Count   int
	Types   map[string]int
	Changes []Change
	Model   string // 顶层 model 字段（若有）
	Stream  bool   // 顶层 stream 字段（若有）
}

func (s *Stats) String() string {
	keys := make([]string, 0, len(s.Types))
	for k := range s.Types {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s×%d", k, s.Types[k])
	}
	return strings.Join(parts, " ")
}

// walk 递归遍历 JSON；inContent 表示当前位于对话内容子树中，path 为当前 JSON 路径。
func walk(f *filter.Filter, v any, inContent bool, path string, st *Stats) any {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if skipKeys[k] {
				continue
			}
			p := k
			if path != "" {
				p = path + "." + k
			}
			x[k] = walk(f, child, inContent || contentKeys[k], p, st)
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = walk(f, child, inContent, fmt.Sprintf("%s[%d]", path, i), st)
		}
		return x
	case string:
		if !inContent || x == "" {
			return x
		}
		r := f.Redact(x)
		if !r.Hit {
			return x
		}
		st.Count += r.Count
		for _, e := range r.Entities {
			st.Types[e.Type]++
		}
		st.Changes = append(st.Changes, Change{Path: path, Before: x, After: r.Redacted, Entities: r.Entities})
		return r.Redacted
	}
	return v
}

// RedactJSON 对 JSON 请求体中的对话内容脱敏。
// 未命中时原样返回输入字节，保证与原请求逐字节一致。
func RedactJSON(f *filter.Filter, body []byte) ([]byte, *Stats, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // 保留大整数精度
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, err
	}
	st := &Stats{Types: map[string]int{}}
	if top, ok := v.(map[string]any); ok {
		st.Model, _ = top["model"].(string)
		st.Stream, _ = top["stream"].(bool)
	}
	v = walk(f, v, false, "", st)
	if st.Count == 0 {
		return body, st, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), st, nil
}

// ParseRoutes 解析 "名称=URL,名称=URL" 形式的路由表。
func ParseRoutes(spec string) (map[string]*url.URL, error) {
	routes := map[string]*url.URL{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, raw, ok := strings.Cut(item, "=")
		name = strings.Trim(strings.TrimSpace(name), "/")
		if !ok || name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("路由格式应为 名称=URL，名称不能含 /：%q", item)
		}
		u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("无效上游 URL：%q", raw)
		}
		routes[name] = u
	}
	return routes, nil
}

// BuildRoutes 合并内置路由与自定义路由；withDefaults 为 false 时只用自定义路由。
func BuildRoutes(custom string, withDefaults bool) (map[string]*url.URL, error) {
	var spec []string
	if withDefaults {
		for name, u := range DefaultRoutes {
			spec = append(spec, name+"="+u)
		}
	}
	routes, err := ParseRoutes(strings.Join(spec, ","))
	if err != nil {
		return nil, err
	}
	extra, err := ParseRoutes(custom)
	if err != nil {
		return nil, err
	}
	for k, v := range extra {
		routes[k] = v
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("没有任何上游路由")
	}
	return routes, nil
}

// Handler 返回网关的 http.Handler：/<路由名>/... 反向代理，另含 /_pf/health 与 /_pf/redact。
func Handler(f *filter.Filter, routes map[string]*url.URL, opts Options) http.Handler {
	lg := newReqLogger(opts)
	mux := http.NewServeMux()
	names := make([]string, 0, len(routes))
	for name, up := range routes {
		mux.Handle("/"+name+"/", proxy(f, name, up, lg))
		names = append(names, name)
	}
	sort.Strings(names)

	n, _ := f.Stats()
	mux.HandleFunc("GET /_pf/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "rules": n, "routes": names})
	})
	// 纯文本脱敏：pbpaste | curl --data-binary @- http://127.0.0.1:8787/_pf/redact
	mux.HandleFunc("POST /_pf/redact", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, f.Redact(string(b)).Redacted)
	})
	return mux
}

func proxy(f *filter.Filter, name string, up *url.URL, lg *reqLogger) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up) // 同时改写 Host 头
			pr.Out.URL.Path = up.Path + strings.TrimPrefix(pr.In.URL.Path, "/"+name)
			pr.Out.URL.RawPath = ""
		},
		FlushInterval: -1, // SSE 流式响应即时下发
		ModifyResponse: func(resp *http.Response) error {
			lg.response(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			lg.upstreamError(r, err)
			http.Error(w, "pf-gateway: 上游请求失败："+err.Error(), http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := lg.begin(r, name, up)
		r = r.WithContext(withRecord(r.Context(), rec))
		if r.Body != nil && r.ContentLength != 0 {
			body, err := readBody(r)
			if err != nil {
				lg.reject(rec, err.Error())
				http.Error(w, "pf-gateway: "+err.Error(), http.StatusUnsupportedMediaType)
				return
			}
			rec.sizeIn = len(body)
			if len(body) > 0 && isJSON(r) {
				t0 := time.Now()
				out, st, err := RedactJSON(f, body)
				rec.redactDur = time.Since(t0)
				if err != nil { // fail-closed：解析不了就不转发原文
					lg.reject(rec, "请求体不是合法 JSON")
					http.Error(w, "pf-gateway: 请求体不是合法 JSON，已拒绝转发", http.StatusBadRequest)
					return
				}
				rec.stats = st
				body = out
			} else if len(body) > 0 {
				rec.note = "非 JSON 请求体（" + r.Header.Get("Content-Type") + "），原样转发"
			}
			rec.sizeOut = len(body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.Header.Del("Content-Encoding")
		}
		lg.request(rec)
		rp.ServeHTTP(w, r)
	})
}

func isJSON(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return ct == "" || strings.Contains(ct, "json")
}

func readBody(r *http.Request) ([]byte, error) {
	var rd io.Reader = r.Body
	switch enc := strings.ToLower(r.Header.Get("Content-Encoding")); enc {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		rd = gz
	default:
		return nil, fmt.Errorf("不支持的 Content-Encoding：%s", enc)
	}
	return io.ReadAll(rd)
}
