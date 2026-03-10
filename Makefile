BINARY     := compliancevet
BUILD_DIR  := bin
MAIN       := ./cmd/compliancevet
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -ldflags "-X github.com/ComplianceVet/compliancevet/cli.Version=$(VERSION)"

.PHONY: all build install test lint clean example help

## デフォルト
all: build

## ビルド
build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(MAIN)
	@echo "Built: $(BUILD_DIR)/$(BINARY) ($(VERSION))"

## $GOPATH/bin にインストール
install:
	go install $(LDFLAGS) $(MAIN)

## テスト実行
test:
	go test -race -count=1 ./...

## テスト（詳細出力）
test-v:
	go test -race -count=1 -v ./...

## 静的解析
lint:
	go vet ./...

## ビルドアーティファクトの削除
clean:
	rm -rf $(BUILD_DIR)

## 動作確認サンプル（/tmp/cv-test/ が必要）
example:
	@echo "=== Text output (all benchmarks) ==="
	go run $(MAIN) scan /tmp/cv-test/ || true
	@echo ""
	@echo "=== Table output (CIS only) ==="
	go run $(MAIN) scan --benchmark cis -o table /tmp/cv-test/ || true
	@echo ""
	@echo "=== HTML report ==="
	go run $(MAIN) scan -o html /tmp/cv-test/ > /tmp/cv-report.html 2>&1 || true
	@echo "Report saved: /tmp/cv-report.html"

## ヘルプ
help:
	@echo "ComplianceVet Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  build     バイナリをビルド → bin/compliancevet"
	@echo "  install   \$$GOPATH/bin にインストール"
	@echo "  test      テスト実行"
	@echo "  lint      go vet で静的解析"
	@echo "  clean     ビルドアーティファクトを削除"
	@echo "  example   動作確認サンプルを実行"
