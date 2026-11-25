// Package rulesload 为各 cmd 统一创建 Filter：
// 设置了 PF_GITLEAKS_TOML 则读该文件，否则使用编译进二进制的规则。
package rulesload

import (
	"log"
	"os"

	"privacyfilter/filter"
	"privacyfilter/rules"
)

// Load 创建 Filter 并打印规则统计。外部规则文件加载失败时退回内嵌规则。
func Load() *filter.Filter {
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
	return f
}
