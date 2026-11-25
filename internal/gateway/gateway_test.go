package gateway

import (
	"encoding/json"
	"io"
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
	gw := httptest.NewServer(Handler(newFilter(t), map[string]*url.URL{"mine": u}))
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
