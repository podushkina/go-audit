package rules

import (
	"go/parser"
	"go/token"
	"testing"

	"go-audit/pkg/config"
	"go-audit/pkg/report"
)

// TestSQLInjectionRule проверяет работу правила для SQL-инъекций
func TestSQLInjectionRule(t *testing.T) {
	testCases := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name: "unsafe sql query with concatenation",
			code: `
package main

import (
	"database/sql"
	_ "github.com/lib/pq"
)

func unsafeQuery(db *sql.DB, username string) {
	// Небезопасный запрос - использование конкатенации строк
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	db.Query(query)

	// Безопасный запрос - использование подготовленных запросов
	safeQuery := "SELECT * FROM users WHERE username = $1"
	db.Query(safeQuery, username)
}
`,
			expected: 1,
		},
		{
			name: "direct unsafe call",
			code: `
package main

import "database/sql"

func directUnsafeCall(db *sql.DB, input string) {
	db.Exec("DELETE FROM users WHERE id = " + input)
}
`,
			expected: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := testRule(t, NewSQLInjectionRule(), tc.code)

			if len(issues) != tc.expected {
				t.Errorf("Ожидалось %d проблем, получено %d", tc.expected, len(issues))
				for i, issue := range issues {
					t.Logf("Проблема %d: %s в строке %d", i+1, issue.Message, issue.Line)
				}
			}
		})
	}
}

// TestHardcodedSecretsRule проверяет работу правила для жестко закодированных секретов
func TestHardcodedSecretsRule(t *testing.T) {
	testCases := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name: "hardcoded secrets",
			code: `
package main

import "os"

func main() {
	// Небезопасно - жестко закодированные секреты
	apiKey := "1234567890abcdef1234567890abcdef"
	password := "SuperSecretPassword123"
	
	// Более безопасные варианты
	configApiKey := os.Getenv("API_KEY")
	configPassword := loadPasswordFromConfig()
}

func loadPasswordFromConfig() string {
	return "configured"
}
`,
			expected: 2,
		},
		{
			name: "secrets in struct",
			code: `
package main

type Config struct {
	Secret string
	APIKey string
}

func init() {
	cfg := Config{
		Secret: "secretValue12345",
		APIKey: "abcdef1234567890",
	}
}
`,
			expected: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := testRule(t, NewHardcodedSecretsRule(), tc.code)

			if len(issues) != tc.expected {
				t.Errorf("Ожидалось %d проблем, получено %d", tc.expected, len(issues))
				for i, issue := range issues {
					t.Logf("Проблема %d: %s в строке %d", i+1, issue.Message, issue.Line)
				}
			}
		})
	}
}

// TestInsecureHTTPRule проверяет работу правила для небезопасных HTTP-настроек
func TestInsecureHTTPRule(t *testing.T) {
	code := `
package main

import (
	"crypto/tls"
	"net/http"
)

func createInsecureServer() {
	// Небезопасная конфигурация TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	
	// Небезопасный HTTP-сервер
	http.ListenAndServe(":8080", nil)
	
	// Использование небезопасного HTTP URL
	http.Get("http://example.com/api")
}
`

	issues := testRule(t, NewInsecureHTTPRule(), code)

	// Ожидается не менее 3 проблем - небезопасные настройки TLS, использование HTTP сервера без TLS, и HTTP URL
	if len(issues) < 3 {
		t.Errorf("Ожидалось не менее 3 проблем, получено %d", len(issues))
		for i, issue := range issues {
			t.Logf("Проблема %d: %s в строке %d", i+1, issue.Message, issue.Line)
		}
	}
}

// TestMissingErrorCheckRule проверяет работу правила для отсутствия проверок ошибок
func TestMissingErrorCheckRule(t *testing.T) {
	code := `
package main

import (
	"os"
	"io/ioutil"
	"fmt"
)

func processFile(filename string) {
	// Ошибка не проверяется
	file, _ := os.Open(filename)
	
	// Правильная проверка ошибки
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	
	// Ошибка игнорируется при вызове функции
	file.Close()
	
	// Ещё один вызов без проверки ошибки
	os.Remove(filename)
}

func criticalOperationsWithoutCheck() {
	f, _ := os.Create("test.txt")
	f.Write([]byte("data"))
	f.Close()
}
`

	issues := testRule(t, NewMissingErrorCheckRule(), code)

	// Должны быть найдены 4 проблемы:
	// 1. os.Open с игнорированием ошибки
	// 2. file.Close без проверки ошибки
	// 3. os.Remove без проверки ошибки
	// 4. f.Write без проверки ошибки в criticalOperationsWithoutCheck
	expectedIssues := 4
	if len(issues) != expectedIssues {
		t.Errorf("Ожидалось %d проблем, получено %d", expectedIssues, len(issues))
		for i, issue := range issues {
			t.Logf("Проблема %d: %s в строке %d", i+1, issue.Message, issue.Line)
		}
	}
}

// TestInsecureCryptoRule проверяет работу правила для небезопасных криптографических функций
func TestInsecureCryptoRule(t *testing.T) {
	code := `
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/des"
	"crypto/rc4"
	"crypto/rand"
	"golang.org/x/crypto/bcrypt"
)

func insecureCrypto() {
	// Небезопасные хеш-функции
	md5.New()
	sha1.New()
	
	// Устаревшие шифры
	key := []byte("12345678")
	des.NewCipher(key)
	rc4.NewCipher(key)
	
	// Низкая стоимость для bcrypt
	pwd := []byte("password")
	bcrypt.GenerateFromPassword(pwd, 4) // Слишком низкая стоимость
}
`

	issues := testRule(t, NewInsecureCryptoRule(), code)

	expectedIssues := 5 // md5, sha1, des, rc4, bcrypt с низкой стоимостью
	if len(issues) < expectedIssues {
		t.Errorf("Ожидалось не менее %d проблем, получено %d", expectedIssues, len(issues))
		for i, issue := range issues {
			t.Logf("Проблема %d: %s в строке %d", i+1, issue.Message, issue.Line)
		}
	}
}

// TestInsecureUserInputRule проверяет работу правила для небезопасной обработки пользовательского ввода
func TestInsecureUserInputRule(t *testing.T) {
	code := `
package main

import (
	"net/http"
	"os/exec"
	"html/template"
	"io/ioutil"
	"os"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Небезопасное использование пользовательского ввода в команде
	command := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", command).Run()
	
	// Небезопасное использование в HTML (потенциальная XSS)
	username := r.FormValue("username")
	html := "<div>" + username + "</div>"
	w.Write([]byte(html))
	
	// Небезопасное использование в файловых операциях
	filename := r.URL.Query().Get("file")
	os.Open(filename)
	
	// Небезопасное использование шаблона
	userInput := r.FormValue("input")
	tmpl := template.New("example")
	tmpl.Parse("{{." + userInput + "}}")
}
`

	rule := NewInsecureUserInputRule()
	issues := testRule(t, rule, code)

	// Должны быть найдены минимум 3 проблемы:
	// 1. Инъекция команды через r.URL.Query
	// 2. XSS через r.FormValue в HTML
	// 3. Инъекция пути через r.URL.Query для os.Open
	expectedIssues := 3
	if len(issues) < expectedIssues {
		t.Errorf("Ожидалось не менее %d проблем, получено %d", expectedIssues, len(issues))
		for i, issue := range issues {
			t.Logf("Проблема %d: %s в строке %d", i+1, issue.Message, issue.Line)
		}
	}
}

// testRule вспомогательная функция для тестирования правил
func testRule(t *testing.T, rule Rule, code string) []report.Issue {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", code, parser.ParseComments)
	if err != nil {
		t.Fatalf("Ошибка парсинга тестового кода: %v", err)
	}

	ctx := &Context{
		FileSet:     fset,
		File:        f,
		Config:      config.DefaultConfig(),
		FilePath:    "test.go",
		FileDir:     ".",
		FileContent: []byte(code),
		Package:     f.Name.Name,
	}

	return rule.Check(ctx)
}
