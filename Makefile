.PHONY: build install test lint clean help

# Параметры сборки
BINARY_NAME=go-audit
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"
GO_FILES=$(shell find . -name "*.go" -type f)

# Исполняемый файл
BINARY_PATH=./bin/$(BINARY_NAME)

# Основная цель по умолчанию
.DEFAULT_GOAL := help

# Цель: build - собирает исполняемый файл
build: ## Собирает исполняемый файл GoSecCheck
	@echo "Сборка $(BINARY_NAME) версии $(VERSION)"
	@mkdir -p bin
	@go build $(LDFLAGS) -o $(BINARY_PATH) ./cmd/goaudit

# Цель: install - устанавливает GoSecCheck в $GOPATH/bin
install: build ## Устанавливает GoSecCheck в $GOPATH/bin
	@echo "Установка $(BINARY_NAME) в GOPATH"
	@go install $(LDFLAGS) ./cmd/gosecheck

# Цель: test - запускает тесты
test: ## Запускает тесты
	@echo "Запуск тестов"
	@go test -v ./...

# Цель: cover - запускает тесты с покрытием кода
cover: ## Запускает тесты с покрытием кода
	@echo "Запуск тестов с покрытием кода"
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out

# Цель: lint - проверяет код с помощью golangci-lint
lint: ## Проверяет код с помощью golangci-lint
	@echo "Проверка кода линтером"
	@golangci-lint run

# Цель: fmt - форматирует код
fmt: ## Форматирует Go код
	@echo "Форматирование кода"
	@gofmt -s -w $(GO_FILES)

# Цель: vet - запускает go vet
vet: ## Запускает go vet
	@echo "Запуск go vet"
	@go vet ./...

# Цель: clean - удаляет артефакты сборки
clean: ## Удаляет артефакты сборки
	@echo "Очистка рабочей директории"
	@rm -rf bin
	@rm -f coverage.out

# Цель: run - собирает и запускает линтер на текущем каталоге
run: build ## Собирает и запускает GoSecCheck на текущем каталоге
	@echo "Запуск $(BINARY_NAME) на текущем каталоге"
	@$(BINARY_PATH) -recursive .

# Цель: release - подготавливает релиз для различных платформ
release: ## Собирает релизные версии для различных платформ
	@echo "Сборка релизных версий для различных платформ"
	@mkdir -p release
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o release/$(BINARY_NAME)_linux_amd64 ./cmd/gosecheck
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o release/$(BINARY_NAME)_darwin_amd64 ./cmd/gosecheck
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o release/$(BINARY_NAME)_windows_amd64.exe ./cmd/gosecheck

# Цель: help - выводит справку
help: ## Выводит список доступных команд с описанием
	@echo "Доступные команды:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'