package rules

import (
	"go/ast"
	"go/token"
	_ "go/types"
	"regexp"
	"strings"

	"go-audit/pkg/report"
)

// SQLInjectionRule проверяет код на потенциальные SQL-инъекции
type SQLInjectionRule struct {
	BaseRule
	// Регулярные выражения для поиска SQL-запросов
	sqlQueryRegex *regexp.Regexp
}

// NewSQLInjectionRule создает новое правило для проверки SQL-инъекций
func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{
		BaseRule: BaseRule{
			id:          "SEC001",
			description: "Потенциальная SQL-инъекция обнаружена",
			severity:    report.SeverityCritical,
		},
		sqlQueryRegex: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\s+`),
	}
}

// Check реализует интерфейс Rule
func (r *SQLInjectionRule) Check(ctx *Context) []report.Issue {
	var issues []report.Issue

	// Находим все вызовы функций, которые могут содержать SQL
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		// Проверяем вызовы методов, таких как db.Query, db.Exec и т.д.
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				methodName := selExpr.Sel.Name

				// Методы, которые могут быть уязвимы к SQL-инъекциям
				if isVulnerableSQLMethod(methodName) && len(callExpr.Args) > 0 {
					// Проверяем первый аргумент, который должен быть SQL-запросом
					if isRiskySQLQuery(callExpr.Args[0], r.sqlQueryRegex) {
						issues = append(issues, r.NewIssue(callExpr.Pos(), ctx,
							"Возможная SQL-инъекция: используйте подготовленные запросы с параметрами"))
					}
				}
			}
		}

		// Также проверяем строковые литералы на наличие SQL-запросов
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if r.sqlQueryRegex.MatchString(lit.Value) {
				// Проверяем, не используются ли строковые конкатенации в родительском выражении
				if parent, ok := getParent(ctx.File, lit); ok {
					if binExpr, ok := parent.(*ast.BinaryExpr); ok && binExpr.Op == token.ADD {
						issues = append(issues, r.NewIssue(lit.Pos(), ctx,
							"Использование конкатенации строк в SQL-запросе может привести к SQL-инъекции"))
					}
				}
			}
		}

		return true
	})

	return issues
}

// isVulnerableSQLMethod проверяет, является ли метод уязвимым к SQL-инъекциям
func isVulnerableSQLMethod(methodName string) bool {
	vulnerableMethods := map[string]bool{
		"Query":           true,
		"QueryRow":        true,
		"Exec":            true,
		"Prepare":         true,
		"QueryContext":    true,
		"QueryRowContext": true,
		"ExecContext":     true,
		"PrepareContext":  true,
	}
	return vulnerableMethods[methodName]
}

// isRiskySQLQuery проверяет, является ли аргумент рискованным SQL-запросом
func isRiskySQLQuery(arg ast.Expr, sqlRegex *regexp.Regexp) bool {
	switch expr := arg.(type) {
	case *ast.BasicLit:
		// Если это строковый литерал
		if expr.Kind == token.STRING {
			return false // Строковые литералы безопасны
		}
	case *ast.BinaryExpr:
		// Строковая конкатенация (+) может быть опасной
		if expr.Op == token.ADD {
			return true
		}
	case *ast.Ident:
		// Использование простых переменных может быть опасным
		return true
	case *ast.CallExpr:
		// Безопасными считаются вызовы функций типа fmt.Sprintf,
		// но только если они используют placeholder-ы (%d, %s) без прямой подстановки
		if selExpr, ok := expr.Fun.(*ast.SelectorExpr); ok {
			if selExpr.Sel.Name == "Sprintf" {
				if len(expr.Args) > 0 {
					if strLit, ok := expr.Args[0].(*ast.BasicLit); ok && strLit.Kind == token.STRING {
						// Если в шаблоне нет параметров, считаем это безопасным
						if !strings.Contains(strLit.Value, "%") {
							return false
						}
						// Если есть только безопасные параметры (%d, %t, %v), считаем это безопасным
						if regexp.MustCompile(`%[dtv]`).MatchString(strLit.Value) &&
							!regexp.MustCompile(`%[^dtv]`).MatchString(strLit.Value) {
							return false
						}
					}
				}
			}
		}
		return true
	}
	return false
}

// getParent находит родительский узел для данного узла в AST
func getParent(file *ast.File, node ast.Node) (ast.Node, bool) {
	var parent ast.Node
	var found bool

	ast.Inspect(file, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}

		// Проверяем все дочерние узлы текущего узла
		children := childNodes(n)
		for _, child := range children {
			if child == node {
				parent = n
				found = true
				return false
			}
		}
		return true
	})

	return parent, found
}

// childNodes возвращает все дочерние узлы для данного узла AST
func childNodes(n ast.Node) []ast.Node {
	if n == nil {
		return nil
	}

	var children []ast.Node

	ast.Inspect(n, func(node ast.Node) bool {
		if node != n && node != nil {
			children = append(children, node)
			return false
		}
		return true
	})

	return children
}
