package rules

import (
	"go/ast"
	"regexp"
	"strings"

	"go-audit/pkg/report"
)

// InsecureUserInputRule проверяет код на небезопасную обработку пользовательского ввода
type InsecureUserInputRule struct {
	BaseRule
	// Паттерны для определения источников пользовательского ввода
	userInputSources []string
	// Опасные функции для пользовательского ввода
	unsafeFunctions map[string]bool
	// Регулярные выражения для определения потенциальных инъекций в команды системы
	commandInjectionRegex *regexp.Regexp
	// Регулярные выражения для определения потенциальных XSS уязвимостей
	xssRegex *regexp.Regexp
}

// NewInsecureUserInputRule создает новое правило для проверки небезопасной обработки пользовательского ввода
func NewInsecureUserInputRule() *InsecureUserInputRule {
	return &InsecureUserInputRule{
		BaseRule: BaseRule{
			id:          "SEC006",
			description: "Небезопасная обработка пользовательского ввода",
			severity:    report.SeverityHigh,
		},
		userInputSources: []string{
			"r.URL", "r.Form", "r.PostForm", "r.MultipartForm", "r.FormValue",
			"r.PostFormValue", "r.QueryParam", "r.Query", "r.Param", "r.Body",
			"json.Unmarshal", "json.Decode", "xml.Unmarshal", "xml.Decode",
			"ioutil.ReadAll", "bufio.Scanner", "bufio.Reader",
		},
		unsafeFunctions: map[string]bool{
			"exec.Command":       true,
			"os.StartProcess":    true,
			"syscall.Exec":       true,
			"template.HTML":      true,
			"template.JS":        true,
			"template.CSS":       true,
			"template.HTMLAttr":  true,
			"template.JSStr":     true,
			"os.Open":            true,
			"ioutil.WriteFile":   true,
			"os.Create":          true,
			"http.Get":           true,
			"http.Post":          true,
			"http.Do":            true,
			"filepath.Abs":       true,
			"filepath.Join":      true,
			"io.Copy":            true,
			"strconv.Atoi":       true,
			"strconv.ParseInt":   true,
			"strconv.ParseFloat": true,
			"strconv.ParseBool":  true,
		},
		commandInjectionRegex: regexp.MustCompile(`(?i)(sh|bash|cmd|powershell|exec|system|popen|run|spawn)`),
		xssRegex:              regexp.MustCompile(`(?i)(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|new\s+Function\()`),
	}
}

// Check реализует интерфейс Rule
func (r *InsecureUserInputRule) Check(ctx *Context) []report.Issue {
	var issues []report.Issue

	// Проверяем, есть ли импорты веб-фреймворков
	hasWebFramework := r.hasWebFramework(ctx)
	if !hasWebFramework {
		// Если нет веб-фреймворка, то меньше шансов на проблемы с пользовательским вводом
		return issues
	}

	// Карта для отслеживания переменных, которые содержат пользовательский ввод
	userInputVars := make(map[string]bool)

	// Первый проход: определяем переменные, содержащие пользовательский ввод
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Проверяем присваивания, где справа находится источник пользовательского ввода
			for i, rhs := range node.Rhs {
				if i >= len(node.Lhs) {
					continue
				}

				if r.isUserInputSource(rhs) {
					if ident, ok := node.Lhs[i].(*ast.Ident); ok {
						userInputVars[ident.Name] = true
					}
				}
			}

		case *ast.ValueSpec:
			// Проверяем объявления переменных
			for i, val := range node.Values {
				if i >= len(node.Names) {
					continue
				}

				if r.isUserInputSource(val) {
					userInputVars[node.Names[i].Name] = true
				}
			}
		}

		return true
	})

	// Второй проход: ищем небезопасное использование пользовательского ввода
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			// Проверяем вызовы функций, которые могут быть небезопасными с пользовательским вводом
			if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if r.isUnsafeFunction(sel) {
					// Проверяем, передается ли пользовательский ввод в небезопасную функцию
					for _, arg := range callExpr.Args {
						if r.containsUserInput(arg, userInputVars) {
							// Определяем тип проблемы безопасности
							var message string
							switch {
							case strings.Contains(sel.Sel.Name, "Command") || r.commandInjectionRegex.MatchString(sel.Sel.Name):
								message = "Потенциальная инъекция команды: пользовательский ввод используется в командной строке"
							case strings.Contains(sel.Sel.Name, "HTML") || strings.Contains(sel.Sel.Name, "JS") || r.xssRegex.MatchString(sel.Sel.Name):
								message = "Потенциальная XSS уязвимость: пользовательский ввод используется без экранирования"
							case strings.Contains(sel.Sel.Name, "Open") || strings.Contains(sel.Sel.Name, "File") || strings.Contains(sel.Sel.Name, "Create"):
								message = "Потенциальная инъекция пути к файлу: пользовательский ввод используется в операциях с файлами"
							default:
								message = "Небезопасное использование пользовательского ввода в функции " + sel.Sel.Name
							}

							issues = append(issues, r.NewIssue(callExpr.Pos(), ctx, message))
						}
					}
				}
			}
		}

		return true
	})

	return issues
}

// hasWebFramework проверяет, используется ли веб-фреймворк в коде
func (r *InsecureUserInputRule) hasWebFramework(ctx *Context) bool {
	// Если есть импорт веб-фреймворка, возвращаем true
	for _, imp := range ctx.File.Imports {
		if imp.Path != nil {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "net/http") ||
				strings.Contains(path, "github.com/gin-gonic") ||
				strings.Contains(path, "github.com/gorilla") ||
				strings.Contains(path, "github.com/labstack/echo") ||
				strings.Contains(path, "github.com/go-chi") {
				return true
			}
		}
	}

	// Также проверяем, есть ли в коде функции обработки HTTP-запросов
	var hasHttpHandler bool
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			if funcDecl.Type != nil && funcDecl.Type.Params != nil {
				for _, field := range funcDecl.Type.Params.List {
					if _, ok := field.Type.(*ast.SelectorExpr); ok {
						// Строим строковое представление для определения типа http.Request
						typeStr := astToString(field.Type)
						if strings.Contains(typeStr, "http.Request") ||
							strings.Contains(typeStr, "http.ResponseWriter") {
							hasHttpHandler = true
							return false
						}
					}
				}
			}
		}
		return true
	})

	return hasHttpHandler
}

// isUserInputSource проверяет, является ли выражение источником пользовательского ввода
func (r *InsecureUserInputRule) isUserInputSource(expr ast.Expr) bool {
	switch node := expr.(type) {
	case *ast.SelectorExpr:
		exprStr := astToString(node)
		for _, source := range r.userInputSources {
			if strings.Contains(exprStr, source) {
				return true
			}
		}
	case *ast.CallExpr:
		// Проверяем, является ли вызов функции источником пользовательского ввода
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			exprStr := astToString(sel)
			for _, source := range r.userInputSources {
				if strings.Contains(exprStr, source) {
					return true
				}
			}
		}
	}
	return false
}

// isUnsafeFunction проверяет, является ли селектор ссылкой на небезопасную функцию
func (r *InsecureUserInputRule) isUnsafeFunction(sel *ast.SelectorExpr) bool {
	if x, ok := sel.X.(*ast.Ident); ok {
		funcName := x.Name + "." + sel.Sel.Name
		return r.unsafeFunctions[funcName]
	}

	// Проверяем также имя метода независимо от пакета
	exprStr := astToString(sel)
	return r.unsafeFunctions[sel.Sel.Name] ||
		strings.Contains(exprStr, "Command") ||
		strings.Contains(exprStr, "Open") ||
		strings.Contains(exprStr, "Write") ||
		strings.Contains(exprStr, "HTML") ||
		r.commandInjectionRegex.MatchString(exprStr) ||
		r.xssRegex.MatchString(exprStr)
}

// containsUserInput проверяет, содержит ли выражение пользовательский ввод
func (r *InsecureUserInputRule) containsUserInput(expr ast.Expr, userInputVars map[string]bool) bool {
	switch node := expr.(type) {
	case *ast.Ident:
		// Проверяем, является ли идентификатор пользовательским вводом
		return userInputVars[node.Name]
	case *ast.SelectorExpr:
		// Проверяем, является ли селектор пользовательским вводом
		exprStr := astToString(node)
		for _, source := range r.userInputSources {
			if strings.Contains(exprStr, source) {
				return true
			}
		}
	case *ast.BinaryExpr:
		// Проверяем, содержат ли части бинарного выражения пользовательский ввод
		return r.containsUserInput(node.X, userInputVars) || r.containsUserInput(node.Y, userInputVars)
	case *ast.CallExpr:
		// Проверяем аргументы вызова функции
		for _, arg := range node.Args {
			if r.containsUserInput(arg, userInputVars) {
				return true
			}
		}
	}
	return false
}

// astToString преобразует AST-выражение в строку для примерного анализа
func astToString(expr ast.Expr) string {
	switch node := expr.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		if x, ok := node.X.(*ast.Ident); ok {
			return x.Name + "." + node.Sel.Name
		}
		return astToString(node.X) + "." + node.Sel.Name
	case *ast.CallExpr:
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
			return astToString(sel)
		}
		return "call"
	default:
		return "expr"
	}
}
