package analyzer

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"go-audit/internal/rules"
	"go-audit/pkg/config"
	"go-audit/pkg/report"
)

// TestNew проверяет создание нового анализатора
func TestNew(t *testing.T) {
	cfg := config.DefaultConfig()
	analyzer := New(cfg)

	if analyzer == nil {
		t.Fatal("Ошибка при создании нового анализатора: получен nil")
	}

	if analyzer.config != cfg {
		t.Error("Конфигурация в анализаторе не соответствует предоставленной конфигурации")
	}

	// Проверяем, что все правила инициализированы
	if len(analyzer.rules) == 0 {
		t.Error("Анализатор создан без правил")
	}

	// Проверяем, что все основные правила присутствуют
	expectedRuleTypes := []string{
		"*rules.SQLInjectionRule",
		"*rules.HardcodedSecretsRule",
		"*rules.InsecureHTTPRule",
		"*rules.MissingErrorCheckRule",
		"*rules.InsecureCryptoRule",
		"*rules.InsecureUserInputRule",
	}

	for _, rule := range analyzer.rules {
		found := false
		for i, expectedType := range expectedRuleTypes {
			// Здесь должна быть проверка типа, но для упрощения используем ID правила
			if rule.ID() == rules.NewSQLInjectionRule().ID() && expectedType == "*rules.SQLInjectionRule" {
				found = true
				// Удаляем проверенный тип из списка для следующих правил
				expectedRuleTypes = append(expectedRuleTypes[:i], expectedRuleTypes[i+1:]...)
				break
			} else if rule.ID() == rules.NewHardcodedSecretsRule().ID() && expectedType == "*rules.HardcodedSecretsRule" {
				found = true
				expectedRuleTypes = append(expectedRuleTypes[:i], expectedRuleTypes[i+1:]...)
				break
			} else if rule.ID() == rules.NewInsecureHTTPRule().ID() && expectedType == "*rules.InsecureHTTPRule" {
				found = true
				expectedRuleTypes = append(expectedRuleTypes[:i], expectedRuleTypes[i+1:]...)
				break
			} else if rule.ID() == rules.NewMissingErrorCheckRule().ID() && expectedType == "*rules.MissingErrorCheckRule" {
				found = true
				expectedRuleTypes = append(expectedRuleTypes[:i], expectedRuleTypes[i+1:]...)
				break
			} else if rule.ID() == rules.NewInsecureCryptoRule().ID() && expectedType == "*rules.InsecureCryptoRule" {
				found = true
				expectedRuleTypes = append(expectedRuleTypes[:i], expectedRuleTypes[i+1:]...)
				break
			} else if rule.ID() == rules.NewInsecureUserInputRule().ID() && expectedType == "*rules.InsecureUserInputRule" {
				found = true
				expectedRuleTypes = append(expectedRuleTypes[:i], expectedRuleTypes[i+1:]...)
				break
			}
		}

		if !found {
			t.Errorf("Неожиданное правило с ID: %s", rule.ID())
		}
	}

	if len(expectedRuleTypes) > 0 {
		t.Errorf("Не все ожидаемые правила были инициализированы: %v", expectedRuleTypes)
	}
}

// TestAnalyzeFiles проверяет анализ файлов
func TestAnalyzeFiles(t *testing.T) {
	// Создаем временную директорию для тестовых файлов
	tempDir, err := ioutil.TempDir("", "gosecheck-test")
	if err != nil {
		t.Fatalf("Ошибка создания временной директории: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Создаем тестовые файлы
	testFiles := map[string]string{
		"safe.go": `
package main

import "fmt"

func main() {
	fmt.Println("Безопасный код")
}`,
		"unsafe.go": `
package main

import (
	"database/sql"
	"fmt"
)

func main() {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	
	username := "admin"
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	db.Query(query)
	
	fmt.Println("Выполнение запроса:", query)
}`,
		"excluded.go": `
package test

import "os/exec"

func runCommand(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}`,
	}

	var filePaths []string
	for fileName, content := range testFiles {
		filePath := filepath.Join(tempDir, fileName)
		err := ioutil.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Ошибка создания тестового файла %s: %v", fileName, err)
		}
		filePaths = append(filePaths, filePath)
	}

	// Создаем конфигурацию, которая исключает excluded.go
	cfg := config.DefaultConfig()
	cfg.Exclude = append(cfg.Exclude, "excluded.go")

	analyzer := New(cfg)

	// Анализируем файлы
	issues, err := analyzer.AnalyzeFiles(filePaths)
	if err != nil {
		t.Fatalf("Ошибка анализа файлов: %v", err)
	}

	// Ожидаем, что unsafe.go имеет проблемы, а safe.go и excluded.go - нет
	foundUnsafeIssues := false

	for _, issue := range issues {
		if filepath.Base(issue.FilePath) == "unsafe.go" {
			foundUnsafeIssues = true
		} else if filepath.Base(issue.FilePath) == "excluded.go" {
			t.Error("Найдены проблемы в исключенном файле excluded.go")
		} else if filepath.Base(issue.FilePath) == "safe.go" {
			t.Error("Найдены проблемы в безопасном файле safe.go")
		}
	}

	if !foundUnsafeIssues {
		t.Error("Не обнаружены проблемы в небезопасном файле unsafe.go")
	}
}

// TestAnalyzeFileWithDisabledRules проверяет, что анализатор не использует отключенные правила
func TestAnalyzeFileWithDisabledRules(t *testing.T) {
	fileContent := `
package main

import (
	"database/sql"
	"fmt"
)

func main() {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	
	username := "admin"
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	db.Query(query)
	
	fmt.Println("Выполнение запроса:", query)
}
`
	// Создаем временный файл
	tempFile, err := ioutil.TempFile("", "gosecheck-*.go")
	if err != nil {
		t.Fatalf("Ошибка создания временного файла: %v", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write([]byte(fileContent))
	if err != nil {
		t.Fatalf("Ошибка записи во временный файл: %v", err)
	}
	tempFile.Close()

	// Анализируем файл со всеми правилами
	cfg := config.DefaultConfig()
	analyzer := New(cfg)
	issues, err := analyzer.AnalyzeFiles([]string{tempFile.Name()})
	if err != nil {
		t.Fatalf("Ошибка анализа файла: %v", err)
	}

	totalIssues := len(issues)
	if totalIssues == 0 {
		t.Fatal("Не обнаружены проблемы в файле, хотя они должны быть")
	}

	// Отключаем правило SQL-инъекций
	cfg.DisabledRules = append(cfg.DisabledRules, "SEC001") // ID правила SQL-инъекций
	analyzer = New(cfg)

	issuesWithDisabledRule, err := analyzer.AnalyzeFiles([]string{tempFile.Name()})
	if err != nil {
		t.Fatalf("Ошибка анализа файла: %v", err)
	}

	// Проверяем, что с отключенным правилом найдено меньше проблем
	if len(issuesWithDisabledRule) >= totalIssues {
		t.Errorf("Ожидалось меньше проблем после отключения правила, до: %d, после: %d",
			totalIssues, len(issuesWithDisabledRule))
	}

	// Проверяем, что нет проблем с ID отключенного правила
	for _, issue := range issuesWithDisabledRule {
		if issue.RuleID == "SEC001" {
			t.Error("Найдена проблема от отключенного правила")
		}
	}
}

// TestConcurrentAnalysis проверяет параллельный анализ файлов
func TestConcurrentAnalysis(t *testing.T) {
	// Создаем множество тестовых файлов для проверки параллельного анализа
	tempDir, err := ioutil.TempDir("", "gosecheck-concurrent")
	if err != nil {
		t.Fatalf("Ошибка создания временной директории: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Шаблон для создания множества файлов
	fileTemplate := `
package test%d

import (
	"database/sql"
	"fmt"
)

func main() {
	username := "user%d"
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	db, _ := sql.Open("mysql", "user:password@/dbname")
	db.Query(query)
	
	fmt.Println("Файл №%d")
}
`

	// Создаем 20 файлов для теста параллельного анализа
	var filePaths []string
	for i := 0; i < 20; i++ {
		fileName := filepath.Join(tempDir, fmt.Sprintf("file%d.go", i))
		content := fmt.Sprintf(fileTemplate, i, i, i)
		err := ioutil.WriteFile(fileName, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Ошибка создания тестового файла: %v", err)
		}
		filePaths = append(filePaths, fileName)
	}

	// Анализируем файлы
	cfg := config.DefaultConfig()
	analyzer := New(cfg)

	issues, err := analyzer.AnalyzeFiles(filePaths)
	if err != nil {
		t.Fatalf("Ошибка параллельного анализа файлов: %v", err)
	}

	// В каждом файле должна быть хотя бы одна проблема (SQL инъекция)
	issuesByFile := make(map[string]int)
	for _, issue := range issues {
		issuesByFile[issue.FilePath]++
	}

	for _, filePath := range filePaths {
		if issuesByFile[filePath] == 0 {
			t.Errorf("Не найдены проблемы в файле %s", filePath)
		}
	}
}

// Мок правила для тестирования
type mockRule struct {
	id          string
	description string
	severity    report.Severity
	issues      []report.Issue
}

func (r *mockRule) ID() string {
	return r.id
}

func (r *mockRule) Description() string {
	return r.description
}

func (r *mockRule) Severity() report.Severity {
	return r.severity
}

func (r *mockRule) Check(*rules.Context) []report.Issue {
	return r.issues
}
