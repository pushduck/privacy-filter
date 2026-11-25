VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt dist rules clean run-gateway

## build: 编译本机平台的全部可执行文件到 bin/
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pf-gateway ./cmd/gateway
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pf-server  ./cmd/server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pf-http    ./cmd/http
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/pf-grpc    ./cmd/grpc

## test: 跑全部测试
test:
	go test ./...

## vet: 静态检查 + gofmt 检查
vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "以下文件未 gofmt："; gofmt -l .; exit 1)

## fmt: 格式化代码
fmt:
	gofmt -w .

## dist: 交叉编译 linux/darwin/windows × amd64/arm64 并打包到 dist/
dist:
	scripts/dist.sh $(VERSION)

## rules: 更新 gitleaks 规则集（更新后需重新编译，规则会内嵌进二进制）
rules:
	scripts/fetch_rules.sh

## run-gateway: 本地启动脱敏网关
run-gateway:
	go run ./cmd/gateway

clean:
	rm -rf bin dist
