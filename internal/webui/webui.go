// Package webui 提供一个本地网页，用来对照查看输入原文与脱敏结果。
//
// 页面与接口都是相对路径，可挂在任意前缀下（网关为 /_pf/ui/，HTTP 服务为 /ui/）：
//
//	GET  <前缀>/              页面
//	POST <前缀>/api/redact    {"text": "..."} → 脱敏结果 + 分段标注 + 命中明细
//
// 接口会把命中原文返回给浏览器，只应监听在本机。本包不写任何日志。
package webui

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"privacyfilter/filter"
)

//go:embed index.html
var indexHTML []byte

// maxBody 是单次请求的文本上限。
const maxBody = 8 << 20

type request struct {
	Text string `json:"text"`
}

// segment 是原文的一段：Label 为空表示未命中的普通文本。
type segment struct {
	Text  string `json:"text"`
	Label string `json:"label,omitempty"`
}

type entity struct {
	Type string `json:"type"`
	Text string `json:"text"`
	Line int    `json:"line"`
}

type response struct {
	Redacted  string         `json:"redacted"`
	Count     int            `json:"count"`
	Types     map[string]int `json:"types"`
	Segments  []segment      `json:"segments"`
	Entities  []entity       `json:"entities"`
	ElapsedMs float64        `json:"elapsed_ms"`
}

// Handler 返回网页与接口的 http.Handler，调用方用 http.StripPrefix 挂载。
func Handler(f *filter.Filter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("POST /api/redact", func(w http.ResponseWriter, r *http.Request) {
		// 要求 JSON：跨站页面无法在不触发 CORS 预检的情况下伪造该请求
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "Content-Type 须为 application/json", http.StatusUnsupportedMediaType)
			return
		}
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
			http.Error(w, "请求体应为 {\"text\": \"...\"}，且不超过 8MB", http.StatusBadRequest)
			return
		}
		writeJSON(w, build(f, req.Text))
	})
	return mux
}

func build(f *filter.Filter, text string) response {
	t0 := time.Now()
	res := f.Redact(text)
	elapsed := time.Since(t0)

	out := response{
		Redacted:  res.Redacted,
		Count:     res.Count,
		Types:     map[string]int{},
		Segments:  make([]segment, 0, 2*len(res.Entities)+1),
		Entities:  make([]entity, 0, len(res.Entities)),
		ElapsedMs: float64(elapsed.Microseconds()) / 1000.0,
	}
	prev, line := 0, 1
	for _, e := range res.Entities {
		if e.Start > prev {
			out.Segments = append(out.Segments, segment{Text: text[prev:e.Start]})
		}
		line += strings.Count(text[prev:e.Start], "\n")
		out.Segments = append(out.Segments, segment{Text: e.Text, Label: e.Type})
		out.Entities = append(out.Entities, entity{Type: e.Type, Text: e.Text, Line: line})
		out.Types[e.Type]++
		line += strings.Count(e.Text, "\n")
		prev = e.End
	}
	if prev < len(text) {
		out.Segments = append(out.Segments, segment{Text: text[prev:]})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
