package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"privacyfilter/filter"
	"privacyfilter/rules"
)

func newFilter(t *testing.T) *filter.Filter {
	t.Helper()
	f, err := filter.NewFromTOML(rules.GitleaksTOML)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRedactJSONAnthropic(t *testing.T) {
	f := newFilter(t)
	const sig = "EqQBCkgIARABGAIiQL3xYzAbCdEfGhIjKlMnOp9988776655"
	const img = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
	body := `{"model":"m","system":[{"type":"text","text":"管理员邮箱 admin@corp.com"}],
	"tools":[{"name":"t","description":"联系 a@b.com","input_schema":{}}],
	"messages":[
	 {"role":"user","content":"手机 13812345678"},
	 {"role":"assistant","content":[{"type":"thinking","thinking":"x","signature":"` + sig + `"}]},
	 {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01","content":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
	  {"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + img + `"}}]}]}`

	out, st, err := RedactJSON(f, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"admin@corp.com", "13812345678", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(s, leak) {
			t.Errorf("未脱敏：%s", leak)
		}
	}
	for _, keep := range []string{sig, img, "联系 a@b.com", "toolu_01"} {
		if !strings.Contains(s, keep) {
			t.Errorf("不应改动的字段被改了：%s", keep)
		}
	}
	if st.Count < 3 {
		t.Errorf("命中数 %d，期望 >= 3", st.Count)
	}
}

func TestRedactJSONUntouched(t *testing.T) {
	f := newFilter(t)
	body := []byte(`{"messages": [ {"role":"user","content":"你好"} ], "max_tokens": 12345678901234567890}`)
	out, st, err := RedactJSON(f, body)
	if err != nil {
		t.Fatal(err)
	}
	if st.Count != 0 || string(out) != string(body) {
		t.Errorf("未命中时应逐字节透传，得到 %s", out)
	}
}

func TestBuildRoutes(t *testing.T) {
	r, err := BuildRoutes("corp=https://llm.corp.com/api/,openai=http://127.0.0.1:1", true)
	if err != nil {
		t.Fatal(err)
	}
	if r["corp"].String() != "https://llm.corp.com/api" || r["openai"].String() != "http://127.0.0.1:1" || r["anthropic"] == nil {
		t.Errorf("路由合并结果不符：%v", r)
	}
	r, _ = BuildRoutes("corp=https://llm.corp.com", false)
	if len(r) != 1 {
		t.Errorf("no-default 时应只有自定义路由：%v", r)
	}
	for _, bad := range []string{"noeq", "x=ftp://a", "a/b=https://x"} {
		if _, err := ParseRoutes(bad); err == nil {
			t.Errorf("应拒绝 %q", bad)
		}
	}
}

func TestProxyEndToEnd(t *testing.T) {
	var got string
	var gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, gotPath = string(b), r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ok\n\n")
	}))
	defer up.Close()

	u, _ := url.Parse(up.URL + "/base")
	gw := httptest.NewServer(Handler(newFilter(t), map[string]*url.URL{"mine": u}, Options{}))
	defer gw.Close()

	resp, err := http.Post(gw.URL+"/mine/v1/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"身份证 11010519491231002X"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "data: ok\n\n" {
		t.Errorf("响应应原样透传，得到 %q", b)
	}
	if gotPath != "/base/v1/chat/completions" {
		t.Errorf("上游路径 %q", gotPath)
	}
	if strings.Contains(got, "11010519491231002X") || !strings.Contains(got, "[身份证]") {
		t.Errorf("上游收到未脱敏内容：%s", got)
	}

	resp, _ = http.Post(gw.URL+"/mine/x", "application/json", strings.NewReader(`{bad`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("坏 JSON 应 fail-closed 返回 400，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp, _ = http.Get(gw.URL + "/_pf/health")
	var h map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&h)
	resp.Body.Close()
	if h["status"] != "ok" {
		t.Errorf("health：%v", h)
	}
}

func TestRequestLogging(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)

	post := func(gw *httptest.Server, body string) {
		resp, err := http.Post(gw.URL+"/mine/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	turn1 := `{"model":"m-1","stream":true,"messages":[{"role":"user","content":"我的邮箱 a@b.com 谢谢"}]}`
	turn2 := `{"model":"m-1","messages":[{"role":"user","content":"我的邮箱 a@b.com 谢谢"},{"role":"user","content":"手机 13812345678"}]}`

	var buf bytes.Buffer
	gw := httptest.NewServer(Handler(newFilter(t), map[string]*url.URL{"mine": u},
		Options{Logger: log.New(&buf, "", 0), Level: LogHits}))
	defer gw.Close()
	post(gw, turn1)
	post(gw, turn2)
	out := buf.String()
	for _, want := range []string{
		"model=m-1", "stream", "← 418",
		`[邮箱] "a@b.com"  @ messages[0].content`,
		"原文：我的邮箱 a@b.com 谢谢", "替换：我的邮箱 [邮箱] 谢谢",
		"（新增 1）", `[电话] "13812345678"  @ messages[1].content`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("日志缺少 %q：\n%s", want, out)
		}
	}
	if n := strings.Count(out, `"a@b.com"`); n != 1 {
		t.Errorf("历史消息中的命中应去重，实际打印 %d 次：\n%s", n, out)
	}

	buf.Reset()
	gw2 := httptest.NewServer(Handler(newFilter(t), map[string]*url.URL{"mine": u},
		Options{Logger: log.New(&buf, "", 0), Level: LogBasic}))
	defer gw2.Close()
	post(gw2, turn1)
	if strings.Contains(buf.String(), "a@b.com") {
		t.Errorf("basic 级别不得记录原文：%s", buf.String())
	}
	if !strings.Contains(buf.String(), "脱敏 1 处：[邮箱]×1") || !strings.Contains(buf.String(), "← 上游 418") {
		t.Errorf("basic 级别摘要不符：%s", buf.String())
	}
}

func TestSnippet(t *testing.T) {
	text := "前缀前缀前缀前缀前缀前缀前缀前缀前缀前缀前缀前缀前缀 key=AKIAIOSFODNN7EXAMPLE\n后面"
	r := newFilter(t).Redact(text)
	if !r.Hit {
		t.Fatal("应命中")
	}
	before, after := snippet(text, r.Entities, r.Entities[0])
	if !strings.HasPrefix(before, "…") || !strings.Contains(before, "AKIAIOSFODNN7EXAMPLE⏎后面") || strings.Contains(after, "AKIA") {
		t.Errorf("片段不符：%q / %q", before, after)
	}
}

// 对话里粘贴的 mihomo 配置应被代理配置层脱敏；/_pf/ui/ 页面可访问。
func TestProxyConfigInMessageAndWebUI(t *testing.T) {
	f := newFilter(t)
	yaml := "proxies:\\n  - name: a\\n    type: trojan\\n    server: node." + "example.net\\n    password: " + "p4ss" + "w0rd-x\\n"
	body := `{"model":"m","messages":[{"role":"user","content":"帮我看看这个配置：\n` + yaml + `"}]}`
	out, st, err := RedactJSON(f, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "example.net") || strings.Contains(s, "w0rd-x") || st.Types["[服务器]"] != 1 {
		t.Errorf("代理配置未脱敏: %s %v", s, st.Types)
	}

	h := Handler(f, map[string]*url.URL{}, Options{})
	for path, want := range map[string]int{"/_pf/ui": http.StatusFound, "/_pf/ui/": http.StatusOK} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s = %d，期望 %d", path, rec.Code, want)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_pf/ui/api/redact", strings.NewReader(`{"text":"server: x"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"segments"`) {
		t.Errorf("POST /_pf/ui/api/redact = %d %s", rec.Code, rec.Body.String())
	}
}
