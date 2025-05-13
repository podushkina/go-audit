package rules

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"go-audit/pkg/report"
)

// HardcodedSecretsRule проверяет код на наличие жестко закодированных секретов
type HardcodedSecretsRule struct {
	BaseRule
	// Регулярные выражения для поиска различных типов секретов
	apiKeyRegex     *regexp.Regexp
	passwordRegex   *regexp.Regexp
	tokenRegex      *regexp.Regexp
	credentialRegex *regexp.Regexp
	sensitiveNames  map[string]bool
}

// NewHardcodedSecretsRule создает новое правило для проверки жестко закодированных секретов
func NewHardcodedSecretsRule() *HardcodedSecretsRule {
	return &HardcodedSecretsRule{
		BaseRule: BaseRule{
			id:          "SEC002",
			description: "Обнаружен жестко закодированный секрет или пароль",
			severity:    report.SeverityHigh,
		},
		apiKeyRegex:     regexp.MustCompile(`(?i)(api_?key|app_?key|token|secret|jwt|authorization)[\s]*=[\s]*['"][\w\d\+\/=]{8,}['"]`),
		passwordRegex:   regexp.MustCompile(`(?i)(password|passwd|pass|pwd)[\s]*=[\s]*['"][^'"]{3,}['"]`),
		tokenRegex:      regexp.MustCompile(`(?i)(auth.?token|oauth|bearer|jwt)[\s]*=[\s]*['"][^'"]{8,}['"]`),
		credentialRegex: regexp.MustCompile(`(?i)(credential|auth)[\s]*=[\s]*['"][^'"]{8,}['"]`),
		sensitiveNames: map[string]bool{
			"password":       true,
			"passwd":         true,
			"pass":           true,
			"pwd":            true,
			"apikey":         true,
			"api_key":        true,
			"secret":         true,
			"secretkey":      true,
			"secret_key":     true,
			"token":          true,
			"accesstoken":    true,
			"access_token":   true,
			"auth":           true,
			"authentication": true,
			"credential":     true,
			"jwt":            true,
			"private":        true,
			"privatekey":     true,
			"private_key":    true,
		},
	}
}

// Check реализует интерфейс Rule
func (r *HardcodedSecretsRule) Check(ctx *Context) []report.Issue {
	var issues []report.Issue

	// Проверяем содержимое строковых литералов на предмет потенциальных секретов
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			// Проверяем объявления переменных
			for i, name := range node.Names {
				if r.isSensitiveName(name.Name) && i < len(node.Values) {
					// Проверяем значение переменной с чувствительным именем
					if value, ok := node.Values[i].(*ast.BasicLit); ok && value.Kind == token.STRING {
						if r.isLikelySecret(value.Value) {
							issues = append(issues, r.NewIssue(node.Pos(), ctx,
								"Потенциальный жестко закодированный секрет в переменной "+name.Name))
						}
					}
				}
			}

		case *ast.AssignStmt:
			// Проверяем присваивания переменных
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					continue
				}

				if ident, ok := lhs.(*ast.Ident); ok && r.isSensitiveName(ident.Name) {
					if value, ok := node.Rhs[i].(*ast.BasicLit); ok && value.Kind == token.STRING {
						if r.isLikelySecret(value.Value) {
							issues = append(issues, r.NewIssue(node.Pos(), ctx,
								"Потенциальный жестко закодированный секрет в присваивании "+ident.Name))
						}
					}
				}
			}

		case *ast.KeyValueExpr:
			// Проверяем ключ-значение в составных литералах (структурах и картах)
			if key, ok := node.Key.(*ast.Ident); ok && r.isSensitiveName(key.Name) {
				if value, ok := node.Value.(*ast.BasicLit); ok && value.Kind == token.STRING {
					if r.isLikelySecret(value.Value) {
						issues = append(issues, r.NewIssue(node.Pos(), ctx,
							"Потенциальный жестко закодированный секрет в поле структуры или карте "+key.Name))
					}
				}
			}

		case *ast.BasicLit:
			// Проверяем строковые литералы на содержание секретов
			if node.Kind == token.STRING {
				// Проверяем на наличие секретов в строковом литерале
				if r.containsSecretPattern(node.Value) {
					issues = append(issues, r.NewIssue(node.Pos(), ctx,
						"Потенциальный жестко закодированный секрет в строковом литерале"))
				}
			}
		}

		return true
	})

	return issues
}

// isSensitiveName проверяет, является ли имя переменной чувствительным
func (r *HardcodedSecretsRule) isSensitiveName(name string) bool {
	lowerName := strings.ToLower(name)

	// Проверяем прямое соответствие
	if r.sensitiveNames[lowerName] {
		return true
	}

	// Проверяем, содержит ли имя чувствительные слова
	for sensitive := range r.sensitiveNames {
		if strings.Contains(lowerName, sensitive) {
			return true
		}
	}

	return false
}

// isLikelySecret проверяет, похоже ли значение на секрет
func (r *HardcodedSecretsRule) isLikelySecret(value string) bool {
	// Убираем кавычки
	value = strings.Trim(value, `"'`)

	// Пустые значения или очень короткие строки не являются секретами
	if len(value) < 3 {
		return false
	}

	// Очевидные тестовые значения
	if value == "password" || value == "123456" || value == "test" || value == "example" {
		return false
	}

	// Проверяем, содержит ли значение шаблоны конфигурационных переменных
	if strings.Contains(value, "${") || strings.Contains(value, "$(") || strings.HasPrefix(value, "{{") {
		return false
	}

	// Проверяем, похоже ли значение на URL или путь к файлу
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "/") {
		return false
	}

	// Проверяем, выглядит ли значение как секрет
	// Большинство секретов длиннее 8 символов и содержат сочетание букв/цифр
	if len(value) >= 8 && containsAlphaAndNumeric(value) {
		return true
	}

	return false
}

// containsSecretPattern проверяет, содержит ли строка шаблоны секретов
func (r *HardcodedSecretsRule) containsSecretPattern(value string) bool {
	return r.apiKeyRegex.MatchString(value) ||
		r.passwordRegex.MatchString(value) ||
		r.tokenRegex.MatchString(value) ||
		r.credentialRegex.MatchString(value)
}

// containsAlphaAndNumeric проверяет, содержит ли строка как буквы, так и цифры
func containsAlphaAndNumeric(s string) bool {
	hasAlpha := false
	hasNumeric := false

	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
		}
		if c >= '0' && c <= '9' {
			hasNumeric = true
		}
		if hasAlpha && hasNumeric {
			return true
		}
	}

	return false
}
