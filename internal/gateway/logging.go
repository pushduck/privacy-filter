package gateway

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"privacyfilter/filter"
)

// LogLevel 控制请求日志的详细程度。
type LogLevel int

const (
	LogBasic   LogLevel = iota // 只记录有命中的请求：类型与数量（默认）
	LogRequest                 // 每个请求一行：模型、体积、命中、上游状态与耗时
	LogHits                    // + 每处命中的原文与替换上下文（含敏感原文）
	LogFull                    // + 每个被改写字段的完整原文与替换后文本（含敏感原文）
)

var logLevelNames = map[string]LogLevel{"basic": LogBasic, "request": LogRequest, "hits": LogHits, "full": LogFull}

// ParseLogLevel 解析 basic / request / hits / full。
func ParseLogLevel(s string) (LogLevel, error) {
	if s == "" {
		return LogBasic, nil
	}
	if l, ok := logLevelNames[strings.ToLower(strings.TrimSpace(s))]; ok {
		return l, nil
	}
	return 0, fmt.Errorf("未知日志级别 %q，可选 basic / request / hits / full", s)
}

// Options 是网关的日志配置。零值即默认行为。
type Options struct {
	Logger *log.Logger // nil 时使用标准库默认 logger
	Level  LogLevel
	MaxLen int  // full 级别下单个字段最多打印的字符数，<=0 不截断
	Repeat bool // hits/full 级别下，是否重复打印之前请求里已出现过的命中（历史消息）
}

const contextRunes = 24 // hits 级别命中前后各显示的字符数

// record 是一次代理请求的日志上下文。
type record struct {
	id        uint64
	start     time.Time
	method    string
	path      string
	route     string
	upstream  string
	ua        string
	remote    string
	sizeIn    int
	sizeOut   int
	redactDur time.Duration
	stats     *Stats
	note      string
}

type recordKey struct{}

func withRecord(ctx context.Context, r *record) context.Context {
	return context.WithValue(ctx, recordKey{}, r)
}

func recordFrom(ctx context.Context) *record {
	r, _ := ctx.Value(recordKey{}).(*record)
	return r
}

type reqLogger struct {
	opts Options
	seq  atomic.Uint64

	mu   sync.Mutex
	seen map[uint64]struct{} // 已打印过的命中，用于去重历史消息
}

const maxSeen = 200_000

func newReqLogger(opts Options) *reqLogger {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	return &reqLogger{opts: opts, seen: map[uint64]struct{}{}}
}

func (l *reqLogger) begin(r *http.Request, route string, up *url.URL) *record {
	return &record{
		id:       l.seq.Add(1),
		start:    time.Now(),
		method:   r.Method,
		path:     r.URL.Path,
		route:    route,
		upstream: up.String() + strings.TrimPrefix(r.URL.Path, "/"+route),
		ua:       r.UserAgent(),
		remote:   r.RemoteAddr,
	}
}

func (l *reqLogger) reject(rec *record, reason string) {
	l.opts.Logger.Printf("#%d %s %s 拒绝转发：%s", rec.id, rec.method, rec.path, reason)
}

// request 在转发前输出请求摘要与命中明细。
func (l *reqLogger) request(rec *record) {
	st := rec.stats
	hit := st != nil && st.Count > 0
	if l.opts.Level == LogBasic {
		if hit {
			l.opts.Logger.Printf("#%d %s %s 脱敏 %d 处：%s", rec.id, rec.method, rec.path, st.Count, st)
		}
		if rec.note != "" {
			l.opts.Logger.Printf("#%d %s %s %s", rec.id, rec.method, rec.path, rec.note)
		}
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s %s → %s", rec.id, rec.method, rec.path, rec.upstream)
	if st != nil && st.Model != "" {
		fmt.Fprintf(&b, " model=%s", st.Model)
	}
	if st != nil && st.Stream {
		b.WriteString(" stream")
	}
	if rec.ua != "" {
		fmt.Fprintf(&b, " ua=%q", rec.ua)
	}
	if rec.sizeIn > 0 {
		fmt.Fprintf(&b, " 体积 %s→%s", humanSize(rec.sizeIn), humanSize(rec.sizeOut))
	}

	var fresh []Change // 需要打印明细的字段（去重后）
	newCount := 0
	if hit {
		for _, c := range st.Changes {
			var keep []filter.Entity
			for _, e := range c.Entities {
				if l.opts.Repeat || l.markNew(c.Before, e.Start) {
					keep = append(keep, e)
				}
			}
			newCount += len(keep)
			if len(keep) > 0 {
				fresh = append(fresh, Change{Path: c.Path, Before: c.Before, After: c.After, Entities: keep})
			}
		}
		fmt.Fprintf(&b, " 脱敏 %d 处", st.Count)
		if !l.opts.Repeat && l.opts.Level >= LogHits {
			fmt.Fprintf(&b, "（新增 %d）", newCount)
		}
		fmt.Fprintf(&b, "：%s 扫描 %s", st, rec.redactDur.Round(10*time.Microsecond))
	} else if st != nil {
		fmt.Fprintf(&b, " 无命中 扫描 %s", rec.redactDur.Round(10*time.Microsecond))
	}
	if rec.note != "" {
		b.WriteString(" " + rec.note)
	}

	if l.opts.Level >= LogHits {
		for _, c := range fresh {
			for _, e := range c.Entities {
				before, after := snippet(c.Before, c.Entities, e)
				fmt.Fprintf(&b, "\n#%d   %s %q  @ %s", rec.id, e.Type, e.Text, c.Path)
				fmt.Fprintf(&b, "\n#%d       原文：%s", rec.id, before)
				fmt.Fprintf(&b, "\n#%d       替换：%s", rec.id, after)
			}
			if l.opts.Level >= LogFull {
				fmt.Fprintf(&b, "\n#%d   ── 字段 %s 原文（%d 字）──\n%s", rec.id, c.Path, utf8.RuneCountInString(c.Before), l.truncate(c.Before))
				fmt.Fprintf(&b, "\n#%d   ── 字段 %s 替换后 ──\n%s", rec.id, c.Path, l.truncate(c.After))
			}
		}
	}
	l.opts.Logger.Print(b.String())
}

// response 在收到上游响应头时输出状态与首字节耗时。
func (l *reqLogger) response(resp *http.Response) {
	if l.opts.Level < LogRequest {
		if resp.StatusCode >= 400 {
			if rec := recordFrom(resp.Request.Context()); rec != nil {
				l.opts.Logger.Printf("#%d ← 上游 %d %s", rec.id, resp.StatusCode, rec.path)
			}
		}
		return
	}
	if rec := recordFrom(resp.Request.Context()); rec != nil {
		l.opts.Logger.Printf("#%d ← %d %s 首字节 %s", rec.id, resp.StatusCode, resp.Header.Get("Content-Type"),
			time.Since(rec.start).Round(time.Millisecond))
	}
}

func (l *reqLogger) upstreamError(r *http.Request, err error) {
	id := uint64(0)
	if rec := recordFrom(r.Context()); rec != nil {
		id = rec.id
	}
	l.opts.Logger.Printf("#%d ✗ 上游请求失败 %s：%v", id, r.URL.String(), err)
}

// markNew 记录一处命中，返回它是否第一次出现。
func (l *reqLogger) markNew(field string, start int) bool {
	h := fnv.New64a()
	h.Write([]byte(field))
	fmt.Fprintf(h, "\x00%d", start)
	k := h.Sum64()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[k]; ok {
		return false
	}
	if len(l.seen) >= maxSeen {
		l.seen = map[uint64]struct{}{}
	}
	l.seen[k] = struct{}{}
	return true
}

func (l *reqLogger) truncate(s string) string {
	if l.opts.MaxLen <= 0 || utf8.RuneCountInString(s) <= l.opts.MaxLen {
		return s
	}
	r := []rune(s)
	return string(r[:l.opts.MaxLen]) + fmt.Sprintf("…（已截断，共 %d 字）", len(r))
}

// snippet 返回命中 e 前后若干字符的原文片段与对应的替换后片段（换行显示为 ⏎）。
func snippet(text string, all []filter.Entity, e filter.Entity) (before, after string) {
	lo := backRunes(text, e.Start, contextRunes)
	hi := fwdRunes(text, e.End, contextRunes)
	var b strings.Builder
	pos := lo
	for _, o := range all { // all 按起点升序且互不重叠
		if o.Start < lo || o.End > hi {
			continue
		}
		b.WriteString(text[pos:o.Start])
		b.WriteString(o.Type)
		pos = o.End
	}
	b.WriteString(text[pos:hi])
	pre, suf := "", ""
	if lo > 0 {
		pre = "…"
	}
	if hi < len(text) {
		suf = "…"
	}
	clean := strings.NewReplacer("\r\n", "⏎", "\n", "⏎", "\r", "⏎").Replace
	return pre + clean(text[lo:hi]) + suf, pre + clean(b.String()) + suf
}

func backRunes(s string, i, n int) int {
	for ; n > 0 && i > 0; n-- {
		_, sz := utf8.DecodeLastRuneInString(s[:i])
		i -= sz
	}
	return i
}

func fwdRunes(s string, i, n int) int {
	for ; n > 0 && i < len(s); n-- {
		_, sz := utf8.DecodeRuneInString(s[i:])
		i += sz
	}
	return i
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}
