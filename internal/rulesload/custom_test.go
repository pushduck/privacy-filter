package rulesload

import (
	"reflect"
	"testing"

	"privacyfilter/filter"
)

func TestParseCustom(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []filter.CustomRule
	}{
		{"YAML 单词", "yeshuwei", []filter.CustomRule{{Match: []string{"yeshuwei"}}}},
		{"JSON 单词", `"ysw"`, []filter.CustomRule{{Match: []string{"ysw"}}}},
		{"JSON 清单", `["yeshuwei","ysw"]`, []filter.CustomRule{{Match: []string{"yeshuwei"}}, {Match: []string{"ysw"}}}},
		{"JSON 单条规则", `{"match":["yeshuwei","叶书伟"],"replace":"[姓名]"}`,
			[]filter.CustomRule{{Match: []string{"yeshuwei", "叶书伟"}, Replace: "[姓名]"}}},
		{"YAML 规则清单混写", `
- match: [yeshuwei, ysw]
  replace: "[姓名]"
  case_sensitive: true
- match: 叶书伟
  allow_partial: true
- 天穹计划
`, []filter.CustomRule{
			{Match: []string{"yeshuwei", "ysw"}, Replace: "[姓名]", CaseSensitive: true},
			{Match: []string{"叶书伟"}, AllowPartial: true},
			{Match: []string{"天穹计划"}},
		}},
		{"rules 包装", "rules:\n  - match: ysw\n    replace: Y\n", []filter.CustomRule{{Match: []string{"ysw"}, Replace: "Y"}}},
		{"空文件", "  \n", nil},
	}
	for _, c := range cases {
		got, err := ParseCustom([]byte(c.in))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n  want %+v\n  got  %+v", c.name, c.want, got)
		}
	}
}

func TestParseCustomErrors(t *testing.T) {
	for _, in := range []string{
		`{"macth":"ysw"}`,   // 字段名写错
		`{"replace":"x"}`,   // 缺 match
		`{"match":[]}`,      // match 为空
		`[{"match": "a"}, `, // 语法错误
	} {
		if _, err := ParseCustom([]byte(in)); err == nil {
			t.Errorf("%q 应报错", in)
		}
	}
}
