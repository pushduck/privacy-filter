// Package rulesload 为各 cmd 统一创建 Filter：
// 设置了 PF_GITLEAKS_TOML 则读该文件，否则使用编译进二进制的规则；
// 设置了 PF_CUSTOM_RULES 则额外加载自定义匹配配置。
package rulesload

import (
	"log"
	"os"
	"strings"

	"privacyfilter/filter"
	"privacyfilter/rules"
)

// Load 创建 Filter 并打印规则统计。外部规则文件加载失败时退回内嵌规则；
// 自定义匹配配置取自环境变量 PF_CUSTOM_RULES。
func Load() *filter.Filter {
	return LoadWith(os.Getenv("PF_CUSTOM_RULES"))
}

// LoadWith 同 Load，自定义匹配配置由参数指定（多个文件用逗号分隔，空串表示不加载）。
// 自定义配置加载失败时直接退出：用户明确要求隐藏的词不能因配置出错而放行。
func LoadWith(customPaths string) *filter.Filter {
	var (
		f   *filter.Filter
		err error
		src = "内嵌规则"
	)
	if p := os.Getenv("PF_GITLEAKS_TOML"); p != "" {
		if f, err = filter.New(p); err != nil {
			log.Printf("加载 %s 失败：%v —— 改用内嵌规则", p, err)
		} else {
			src = p
		}
	}
	if f == nil {
		if f, err = filter.NewFromTOML(rules.GitleaksTOML); err != nil {
			log.Printf("解析内嵌规则失败：%v —— 改用内置兜底规则", err)
			f, _ = filter.New("")
		}
	}
	n, skipped := f.Stats()
	log.Printf("就绪：gitleaks 规则 %d 条（跳过 %d 条不兼容），来源：%s", n, skipped, src)

	var custom []filter.CustomRule
	var files []string
	for _, p := range strings.Split(customPaths, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		rs, err := LoadCustomFile(p)
		if err != nil {
			log.Fatalf("加载自定义匹配配置失败：%v", err)
		}
		custom = append(custom, rs...)
		files = append(files, p)
	}
	if len(files) > 0 {
		if f, err = f.WithCustom(custom); err != nil {
			log.Fatalf("加载自定义匹配配置失败：%v", err)
		}
		// 不打印匹配词本身，日志里不出现要隐藏的内容
		log.Printf("就绪：自定义匹配词 %d 个，来源：%s", f.CustomStats(), strings.Join(files, ","))
	}
	return f
}
