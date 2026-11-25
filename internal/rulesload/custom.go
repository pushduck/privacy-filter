package rulesload

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"privacyfilter/filter"
)

// 自定义匹配配置文件（JSON 或 YAML，YAML 是 JSON 的超集，统一按 YAML 解析）。支持以下写法：
//
//	yeshuwei                          # 单个词，替换为等长掩码
//	[yeshuwei, ysw]                   # 词清单
//	{match: yeshuwei, replace: "[姓名]"} # 单条规则
//	[{match: [yeshuwei, ysw, 叶书伟], replace: "[姓名]"}, ysw2]  # 规则清单，可与纯词混写
//	{rules: [...]}                    # 同上，包一层 rules
//
// 规则字段：match（字符串或字符串数组，必填）、replace（可省略）、
// case_sensitive（默认 false）、allow_partial（默认 false，即英文词需完整匹配）。

type customRuleDoc struct {
	Match         any    `yaml:"match"`
	Replace       string `yaml:"replace"`
	CaseSensitive bool   `yaml:"case_sensitive"`
	AllowPartial  bool   `yaml:"allow_partial"`
}

// LoadCustomFile 读取并解析一个自定义匹配配置文件。
func LoadCustomFile(path string) ([]filter.CustomRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := ParseCustom(data)
	if err != nil {
		return nil, fmt.Errorf("%s：%w", path, err)
	}
	return rules, nil
}

// ParseCustom 解析自定义匹配配置内容（JSON 或 YAML）。
func ParseCustom(data []byte) ([]filter.CustomRule, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("解析失败：%w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, nil
	}
	n := root.Content[0]
	// {rules: [...]} 包装
	if n.Kind == yaml.MappingNode && len(n.Content) == 2 && n.Content[0].Value == "rules" {
		n = n.Content[1]
	}
	if n.Kind == yaml.SequenceNode {
		var out []filter.CustomRule
		for i, item := range n.Content {
			r, err := parseCustomItem(item)
			if err != nil {
				return nil, fmt.Errorf("第 %d 项：%w", i+1, err)
			}
			out = append(out, r)
		}
		return out, nil
	}
	r, err := parseCustomItem(n)
	if err != nil {
		return nil, err
	}
	return []filter.CustomRule{r}, nil
}

func parseCustomItem(n *yaml.Node) (filter.CustomRule, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.TrimSpace(n.Value) == "" {
			return filter.CustomRule{}, fmt.Errorf("第 %d 行：匹配词为空", n.Line)
		}
		return filter.CustomRule{Match: []string{n.Value}}, nil
	case yaml.MappingNode:
		var doc customRuleDoc
		// 拒绝未知字段，避免字段名写错导致规则悄悄失效、原文外泄
		var raw map[string]any
		if err := n.Decode(&raw); err != nil {
			return filter.CustomRule{}, fmt.Errorf("第 %d 行：%w", n.Line, err)
		}
		for k := range raw {
			switch k {
			case "match", "replace", "case_sensitive", "allow_partial":
			default:
				return filter.CustomRule{}, fmt.Errorf("第 %d 行：未知字段 %q", n.Line, k)
			}
		}
		if err := n.Decode(&doc); err != nil {
			return filter.CustomRule{}, fmt.Errorf("第 %d 行：%w", n.Line, err)
		}
		words, err := toWords(doc.Match)
		if err != nil {
			return filter.CustomRule{}, fmt.Errorf("第 %d 行：%w", n.Line, err)
		}
		return filter.CustomRule{
			Match:         words,
			Replace:       doc.Replace,
			CaseSensitive: doc.CaseSensitive,
			AllowPartial:  doc.AllowPartial,
		}, nil
	default:
		return filter.CustomRule{}, fmt.Errorf("第 %d 行：不支持的写法", n.Line)
	}
}

func toWords(v any) ([]string, error) {
	var words []string
	switch x := v.(type) {
	case string:
		words = []string{x}
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				s = fmt.Sprint(e) // 数字等标量也按字面匹配
			}
			words = append(words, s)
		}
	case nil:
		return nil, fmt.Errorf("缺少 match")
	default:
		words = []string{fmt.Sprint(x)}
	}
	var out []string
	for _, w := range words {
		if strings.TrimSpace(w) != "" {
			out = append(out, w)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("match 为空")
	}
	return out, nil
}
