package filter

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// 自定义匹配层：用户给出的固定词（姓名、缩写、项目代号等），命中即替换为指定值；
// 未指定替换值时替换为等长（按字符数）的掩码符号。优先级高于其他所有检测层。

// MaskChar 是未配置替换值时使用的掩码符号。
const MaskChar = "*"

// CustomRule 是一条自定义匹配规则：Match 中任一词命中都替换为 Replace。
type CustomRule struct {
	Match         []string // 要匹配的词，按字面匹配（非正则）
	Replace       string   // 替换值；为空时替换为等长掩码
	CaseSensitive bool     // 区分大小写；默认不区分
	// AllowPartial 允许命中英文单词内部（如 ysw 命中 ysww）。默认要求词边界：
	// 词首/词尾为字母数字时，相邻字符不能也是字母数字。中文等非 ASCII 字符不受此限制。
	AllowPartial bool
}

type customTerm struct {
	re           *regexp.Regexp
	replace      string
	checkL       bool // 词首为 ASCII 字母数字，需校验左边界
	checkR       bool // 词尾为 ASCII 字母数字，需校验右边界
	allowPartial bool
}

type customMatcher struct {
	terms []customTerm
}

func isASCIIWordChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func newCustomMatcher(rules []CustomRule) (*customMatcher, error) {
	m := &customMatcher{}
	for i, r := range rules {
		for _, w := range r.Match {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			expr := regexp.QuoteMeta(w)
			if !r.CaseSensitive {
				expr = "(?i)" + expr
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("自定义规则 #%d 词 %q 编译失败：%w", i+1, w, err)
			}
			m.terms = append(m.terms, customTerm{
				re:           re,
				replace:      r.Replace,
				checkL:       isASCIIWordChar(w[0]),
				checkR:       isASCIIWordChar(w[len(w)-1]),
				allowPartial: r.AllowPartial,
			})
		}
	}
	return m, nil
}

func (m *customMatcher) detect(text string) []span {
	if m == nil {
		return nil
	}
	var spans []span
	for _, t := range m.terms {
		for _, loc := range t.re.FindAllStringIndex(text, -1) {
			s, e := loc[0], loc[1]
			if !t.allowPartial {
				if t.checkL && s > 0 && isASCIIWordChar(text[s-1]) {
					continue
				}
				if t.checkR && e < len(text) && isASCIIWordChar(text[e]) {
					continue
				}
			}
			label := t.replace
			if label == "" {
				label = strings.Repeat(MaskChar, utf8.RuneCountInString(text[s:e]))
			}
			spans = append(spans, span{s, e, label})
		}
	}
	return spans
}

// WithCustom 返回带自定义匹配规则的新 Filter（共享已编译的密钥规则），原 Filter 不变。
func (f *Filter) WithCustom(rules []CustomRule) (*Filter, error) {
	cm, err := newCustomMatcher(rules)
	if err != nil {
		return nil, err
	}
	return &Filter{secrets: f.secrets, custom: cm}, nil
}

// CustomStats 返回已加载的自定义匹配词数。
func (f *Filter) CustomStats() int {
	if f.custom == nil {
		return 0
	}
	return len(f.custom.terms)
}
