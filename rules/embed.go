// Package rules 把 gitleaks.toml 编译进二进制，使可执行文件单文件即可运行。
package rules

import _ "embed"

// GitleaksTOML 是构建时 rules/gitleaks.toml 的内容。
//
//go:embed gitleaks.toml
var GitleaksTOML []byte
