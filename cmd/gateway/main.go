// 通用 LLM API 脱敏网关。逻辑全部在 internal/gateway。
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"privacyfilter/internal/gateway"
	"privacyfilter/internal/rulesload"
)

var version = "dev" // 发布构建时由 -ldflags "-X main.version=..." 注入

func main() {
	showVersion := flag.Bool("version", false, "打印版本并退出")
	listen := flag.String("listen", envOr("PF_LISTEN", "127.0.0.1:8787"), "监听地址（环境变量 PF_LISTEN）")
	routes := flag.String("routes", os.Getenv("PF_ROUTES"), "自定义上游，名称=URL，逗号分隔（环境变量 PF_ROUTES）")
	noDefaults := flag.Bool("no-default-routes", envBool("PF_NO_DEFAULT_ROUTES"), "不加载内置上游（环境变量 PF_NO_DEFAULT_ROUTES=1）")
	logTo := flag.String("log", envOr("PF_LOG", "console"),
		"日志输出：console、文件路径，或逗号分隔多个，如 console,/tmp/pf.log（环境变量 PF_LOG）")
	logLevel := flag.String("log-level", envOr("PF_LOG_LEVEL", "basic"),
		"日志级别：basic（命中摘要）| request（每个请求）| hits（+命中原文）| full（+字段全文）（环境变量 PF_LOG_LEVEL）")
	logMaxLen := flag.Int("log-max-len", envInt("PF_LOG_MAX_LEN", 2000), "full 级别下单个字段最多打印字符数，0 不截断（环境变量 PF_LOG_MAX_LEN）")
	logRepeat := flag.Bool("log-repeat", envBool("PF_LOG_REPEAT"), "hits/full 级别下重复打印历史消息中已出现过的命中（环境变量 PF_LOG_REPEAT=1）")
	flag.Parse()

	if *showVersion {
		fmt.Println("pf-gateway", version)
		return
	}

	out, closeLog, err := openLogOutput(*logTo)
	if err != nil {
		log.Fatal(err)
	}
	defer closeLog()
	log.SetOutput(out)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	level, err := gateway.ParseLogLevel(*logLevel)
	if err != nil {
		log.Fatal(err)
	}
	table, err := gateway.BuildRoutes(*routes, !*noDefaults)
	if err != nil {
		log.Fatal(err)
	}
	f := rulesload.Load()

	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	log.Printf("pf-gateway %s 监听 http://%s，日志级别 %s → %s", version, *listen, strings.ToLower(*logLevel), *logTo)
	if level >= gateway.LogHits {
		log.Printf("⚠ 当前日志级别会记录被脱敏的敏感原文，请妥善保管日志，用完及时删除")
	}
	for _, name := range names {
		log.Printf("  http://%s/%s  →  %s", strings.Replace(*listen, "0.0.0.0", "127.0.0.1", 1), name, table[name])
	}
	opts := gateway.Options{Level: level, MaxLen: *logMaxLen, Repeat: *logRepeat}
	log.Fatal(http.ListenAndServe(*listen, gateway.Handler(f, table, opts)))
}

// openLogOutput 按 "console,/path/a.log" 打开日志目标。日志文件以 0600 权限追加写入。
func openLogOutput(spec string) (io.Writer, func(), error) {
	var ws []io.Writer
	var files []*os.File
	for _, t := range strings.Split(spec, ",") {
		t = strings.TrimSpace(t)
		switch strings.ToLower(t) {
		case "":
			continue
		case "console", "stderr":
			ws = append(ws, os.Stderr)
		case "stdout":
			ws = append(ws, os.Stdout)
		default:
			// 逗号后的 ~ 不会被 shell 展开，这里自行处理
			if t == "~" || strings.HasPrefix(t, "~/") || strings.HasPrefix(t, `~\`) {
				home, err := os.UserHomeDir()
				if err != nil {
					return nil, nil, fmt.Errorf("无法展开 ~：%w", err)
				}
				t = filepath.Join(home, t[1:])
			}
			if dir := filepath.Dir(t); dir != "." {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return nil, nil, fmt.Errorf("创建日志目录失败：%w", err)
				}
			}
			fh, err := os.OpenFile(t, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return nil, nil, fmt.Errorf("打开日志文件失败：%w", err)
			}
			files = append(files, fh)
			ws = append(ws, fh)
		}
	}
	if len(ws) == 0 {
		return nil, nil, fmt.Errorf("-log 没有有效的输出目标：%q", spec)
	}
	return io.MultiWriter(ws...), func() {
		for _, fh := range files {
			_ = fh.Close()
		}
	}, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

func envInt(key string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return n
	}
	return def
}
