// 单独的 HTTP 服务。逻辑全部在 internal/httpapi。
package main

import (
	"log"
	"net/http"
	"os"

	"privacyfilter/internal/httpapi"
	"privacyfilter/internal/rulesload"
)

func main() {
	addr := ":" + envOr("PF_PORT", "8088")

	f := rulesload.Load()

	log.Printf("HTTP 监听 %s", addr)
	log.Fatal(http.ListenAndServe(addr, httpapi.Handler(f)))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
