package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacyfilter/filter"
)

func newFilter(t *testing.T) *filter.Filter {
	t.Helper()
	f, err := filter.New("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBuildSegments(t *testing.T) {
	f := newFilter(t)
	text := strings.Join([]string{"proxies:", "  - name: a", "    type: ss", "    server: node." + "example.net", "    port: 443"}, "\n")
	r := build(f, text)

	// 分段拼回去必须等于原文；替换标签后必须等于脱敏结果
	var orig, red strings.Builder
	for _, s := range r.Segments {
		orig.WriteString(s.Text)
		if s.Label != "" {
			red.WriteString(s.Label)
		} else {
			red.WriteString(s.Text)
		}
	}
	if orig.String() != text {
		t.Errorf("分段未还原原文: %q", orig.String())
	}
	if red.String() != r.Redacted {
		t.Errorf("分段与脱敏结果不一致:\n%q\n%q", red.String(), r.Redacted)
	}
	if r.Count != 1 || len(r.Entities) != 1 || r.Entities[0].Line != 4 || r.Types["[服务器]"] != 1 {
		t.Errorf("命中明细不符: %+v", r.Entities)
	}
}

func TestHandler(t *testing.T) {
	srv := httptest.NewServer(http.StripPrefix("/ui", Handler(newFilter(t))))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("页面: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	resp, err = http.Post(srv.URL+"/ui/api/redact", "application/json", strings.NewReader(`{"text":"邮箱 a@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out response
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Count != 1 || out.Redacted != "邮箱 [邮箱]" {
		t.Errorf("接口结果不符: %+v", out)
	}

	// 非 JSON 拒绝（防跨站简单请求）
	resp, err = http.Post(srv.URL+"/ui/api/redact", "text/plain", strings.NewReader(`{"text":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain 应被拒绝，得到 %d", resp.StatusCode)
	}
}
