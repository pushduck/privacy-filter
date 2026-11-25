// 单独的 gRPC 服务。逻辑全部在 internal/grpcapi。
package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"privacyfilter/internal/grpcapi"
	"privacyfilter/internal/rulesload"
)

func main() {
	addr := ":" + envOr("PF_GRPC_PORT", "8089")

	f := rulesload.Load()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听 %s 失败：%v", addr, err)
	}
	s := grpc.NewServer()
	grpcapi.Register(s, f)

	log.Printf("gRPC 监听 %s", addr)
	log.Fatal(s.Serve(lis))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
