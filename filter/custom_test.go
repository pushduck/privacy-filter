package filter

import "testing"

func newCustomFilter(t *testing.T, rules ...CustomRule) *Filter {
	t.Helper()
	f, err := newFilter(t).WithCustom(rules)
	if err != nil {
		t.Fatalf("WithCustom: %v", err)
	}
	return f
}

func TestCustomReplace(t *testing.T) {
	f := newCustomFilter(t,
		CustomRule{Match: []string{"yeshuwei", "ysw", "叶书伟"}, Replace: "[姓名]"},
		CustomRule{Match: []string{"天穹计划"}},
	)
	cases := []struct{ in, want string }{
		{"作者 yeshuwei 写的", "作者 [姓名] 写的"},
		{"YeShuWei / ysw / 叶书伟", "[姓名] / [姓名] / [姓名]"},
		{"叶书伟的项目", "[姓名]的项目"},
		{"关于天穹计划的进展", "关于****的进展"},
		{"ysww 与 xysw 不是名字", "ysww 与 xysw 不是名字"}, // 英文词边界
		{"user_ysw 不算，ysw_1 也不算", "user_ysw 不算，ysw_1 也不算"},
		{"路径 /home/ysw/code", "路径 /home/[姓名]/code"},
	}
	for _, c := range cases {
		r := f.Redact(c.in)
		if r.Redacted != c.want {
			t.Errorf("%q\n  want %q\n  got  %q", c.in, c.want, r.Redacted)
		}
	}
}

func TestCustomMaskLength(t *testing.T) {
	f := newCustomFilter(t, CustomRule{Match: []string{"secretproj"}})
	if got := f.Redact("secretproj ok").Redacted; got != "********** ok" {
		t.Errorf("got %q", got)
	}
}

func TestCustomOptions(t *testing.T) {
	f := newCustomFilter(t, CustomRule{Match: []string{"Abc"}, Replace: "X", CaseSensitive: true, AllowPartial: true})
	if got := f.Redact("abc Abc zAbcz").Redacted; got != "abc X zXz" {
		t.Errorf("got %q", got)
	}
}

func TestCustomPriority(t *testing.T) {
	f := newCustomFilter(t, CustomRule{Match: []string{"yeshuwei"}, Replace: "[姓名]"})
	// 姓名完全落在邮箱内：整段按邮箱脱敏，不泄露域名
	mail := "yeshuwei" + "@" + "example.com"
	if got := f.Redact("mail " + mail).Redacted; got != "mail [邮箱]" {
		t.Errorf("got %q", got)
	}
	// 邮箱之外的同名照常按自定义替换
	if got := f.Redact("yeshuwei: " + mail).Redacted; got != "[姓名]: [邮箱]" {
		t.Errorf("got %q", got)
	}
	// 未配置自定义规则时行为不变
	if got := newFilter(t).Redact("yeshuwei").Redacted; got != "yeshuwei" {
		t.Errorf("got %q", got)
	}
}
