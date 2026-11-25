// 通用 LLM API 脱敏网关。逻辑全部在 internal/gateway。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"privacyfilter/internal/gateway"
	"privacyfilter/internal/rulesload"
)

var version = "dev" // 发布构建时由 -ldflags "-X main.version=..." 注入

func main() {
	showVersion := flag.Bool("version", false, "打印版本并退出")
	listen := flag.String("listen", envOr("PF_LISTEN", "127.0.0.1:8787"), "监听地址（环境变量 PF_LISTEN）")
	routes := flag.String("routes", os.Getenv("PF_ROUTES"), "自定义上游，名称=URL，逗号分隔（环境变量 PF_ROUTES）")
	noDefaults := flag.Bool("no-default-routes", os.Getenv("PF_NO_DEFAULT_ROUTES") == "1", "不加载内置上游（环境变量 PF_NO_DEFAULT_ROUTES=1）")
	flag.Parse()

	if *showVersion {
		fmt.Println("pf-gateway", version)
		return
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
	log.Printf("pf-gateway %s 监听 http://%s", version, *listen)
	for _, name := range names {
		log.Printf("  http://%s/%s  →  %s", strings.Replace(*listen, "0.0.0.0", "127.0.0.1", 1), name, table[name])
	}
	log.Fatal(http.ListenAndServe(*listen, gateway.Handler(f, table)))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
