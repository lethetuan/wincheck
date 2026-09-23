# Makefile cho WinCheck (Wails + React).
# Yêu cầu: Go, Node.js/npm, Wails CLI (github.com/wailsapp/wails/v2/cmd/wails@v2.12.0).
# Người dùng Windows có thể dùng build.ps1 thay thế.

.PHONY: all build dev test cover vet clean

all: test build

build:
	wails build
	@echo "✔ Đã build build/bin/WinCheck.exe"

# Chế độ phát triển với hot-reload frontend
dev:
	wails dev

test:
	go test ./...

cover:
	go test -cover ./...

vet:
	go vet ./...

clean:
	rm -rf build/bin frontend/dist frontend/node_modules
