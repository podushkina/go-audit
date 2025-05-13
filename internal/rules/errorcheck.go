package rules

import (
	"go/ast"
	"go/token"
	"strings"

	"go-audit/pkg/report"
)

// MissingErrorCheckRule проверяет код на отсутствие проверок ошибок
type MissingErrorCheckRule struct {
	BaseRule
	// Карта функций, которые возвращают ошибки и требуют проверки
	criticalFunctions map[string]bool
}

// NewMissingErrorCheckRule создает новое правило для проверки отсутствия обработки ошибок
func NewMissingErrorCheckRule() *MissingErrorCheckRule {
	return &MissingErrorCheckRule{
		BaseRule: BaseRule{
			id:          "SEC004",
			description: "Отсутствует проверка ошибки после критической операции",
			severity:    report.SeverityMedium,
		},
		criticalFunctions: map[string]bool{
			"Write":             true,
			"WriteString":       true,
			"Read":              true,
			"ReadAll":           true,
			"Close":             true,
			"Exec":              true,
			"Query":             true,
			"QueryRow":          true,
			"Open":              true,
			"Create":            true,
			"ReadFile":          true,
			"WriteFile":         true,
			"Unmarshal":         true,
			"Marshal":           true,
			"NewDecoder":        true,
			"NewEncoder":        true,
			"Decode":            true,
			"Encode":            true,
			"Scan":              true,
			"New":               true,
			"Listen":            true,
			"ListenAndServe":    true,
			"ListenAndServeTLS": true,
			"Dial":              true,
			"DialTLS":           true,
			"Connect":           true,
			"Start":             true,
			"Run":               true,
			"Copy":              true,
		},
	}
}

// Check реализует интерфейс Rule
func (r *MissingErrorCheckRule) Check(ctx *Context) []report.Issue {
	var issues []report.Issue

	// Создаем карту для отслеживания проверенных ошибок
	checkedErrors := make(map[token.Pos]bool)

	// Сначала находим все проверки ошибок
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		// Проверяем выражения сравнения (if err != nil, if err == nil)
		if binExpr, ok := n.(*ast.BinaryExpr); ok {
			if isErrorCheck(binExpr) {
				// Отмечаем, что ошибка проверена
				if ident, ok := binExpr.X.(*ast.Ident); ok {
					checkedErrors[ident.Obj.Pos()] = true
				}
			}
		}

		// Проверяем на использование ошибок в логах/печати
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				// Проверяем функции логирования (log.Error, fmt.Println и т.д.)
				if isLoggingFunction(sel) {
					for _, arg := range callExpr.Args {
						if ident, ok := arg.(*ast.Ident); ok && ident.Obj != nil {
							checkedErrors[ident.Obj.Pos()] = true
						}
					}
				}
			}
		}

		// Проверяем на возврат ошибок (return err, return nil, err)
		if retStmt, ok := n.(*ast.ReturnStmt); ok {
			for _, result := range retStmt.Results {
				if ident, ok := result.(*ast.Ident); ok && ident.Obj != nil {
					checkedErrors[ident.Obj.Pos()] = true
				}
			}
		}

		return true
	})

	// Затем ищем критические функции с непроверенными ошибками
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Проверяем присваивания, где возвращается ошибка
			if node.Tok == token.DEFINE || node.Tok == token.ASSIGN {
				if len(node.Rhs) == 1 {
					// Проверяем случаи вида: result, err := someFunction()
					if callExpr, ok := node.Rhs[0].(*ast.CallExpr); ok {
						if len(node.Lhs) >= 2 { // Как минимум два значения назначаются (возможно есть err)
							lastVar := node.Lhs[len(node.Lhs)-1]
							if ident, ok := lastVar.(*ast.Ident); ok && ident.Name == "err" && ident.Obj != nil {
								if !checkedErrors[ident.Obj.Pos()] {
									// Проверяем, является ли вызываемая функция критической
									if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
										if r.criticalFunctions[sel.Sel.Name] {
											issues = append(issues, r.NewIssue(node.Pos(), ctx,
												"Отсутствует проверка ошибки после вызова критической функции "+sel.Sel.Name))
										}
									}
								}
							}
						}
					}
				} else {
					// Проверяем поэлементные присваивания (a, b, err := x, y, z)
					for i, rhs := range node.Rhs {
						if i >= len(node.Lhs) {
							continue
						}

						if callExpr, ok := rhs.(*ast.CallExpr); ok {
							if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
								if r.criticalFunctions[sel.Sel.Name] {
									// Проверяем, возвращает ли функция ошибку как последний результат
									for j := 0; j < len(node.Lhs); j++ {
										if j >= len(node.Rhs) {
											continue
										}

										if ident, ok := node.Lhs[j].(*ast.Ident); ok && ident.Name == "err" && ident.Obj != nil {
											if !checkedErrors[ident.Obj.Pos()] {
												issues = append(issues, r.NewIssue(node.Pos(), ctx,
													"Отсутствует проверка ошибки после вызова критической функции "+sel.Sel.Name))
											}
										}
									}
								}
							}
						}
					}
				}
			}

		case *ast.ExprStmt:
			// Проверяем выражения-вызовы без присваивания результата
			if callExpr, ok := node.X.(*ast.CallExpr); ok {
				if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					if r.criticalFunctions[sel.Sel.Name] {
						// Некоторые критические функции возвращают ошибки, но результат не проверяется
						issues = append(issues, r.NewIssue(node.Pos(), ctx,
							"Результат вызова критической функции "+sel.Sel.Name+" игнорируется"))
					}
				}
			}
		}

		return true
	})

	return issues
}

// isErrorCheck проверяет, является ли бинарное выражение проверкой ошибки
func isErrorCheck(expr *ast.BinaryExpr) bool {
	// Проверяем на err != nil или err == nil
	if expr.Op == token.NEQ || expr.Op == token.EQL {
		// Левая часть должна быть идентификатором
		if ident, ok := expr.X.(*ast.Ident); ok {
			// Правая часть должна быть nil
			if nilExpr, ok := expr.Y.(*ast.Ident); ok && nilExpr.Name == "nil" {
				// Проверяем, что идентификатор похож на ошибку
				return strings.HasSuffix(ident.Name, "err") || ident.Name == "e" || ident.Name == "error"
			}
		}

		// Проверяем также обратный порядок: nil != err, nil == err
		if ident, ok := expr.Y.(*ast.Ident); ok {
			if nilExpr, ok := expr.X.(*ast.Ident); ok && nilExpr.Name == "nil" {
				return strings.HasSuffix(ident.Name, "err") || ident.Name == "e" || ident.Name == "error"
			}
		}
	}

	return false
}

// isLoggingFunction проверяет, является ли вызов функцией логирования
func isLoggingFunction(sel *ast.SelectorExpr) bool {
	if x, ok := sel.X.(*ast.Ident); ok {
		// Проверяем распространенные пакеты и функции логирования
		pkgName := x.Name
		funcName := sel.Sel.Name

		// log пакет
		if pkgName == "log" && (funcName == "Fatal" || funcName == "Fatalf" ||
			funcName == "Print" || funcName == "Printf" ||
			funcName == "Panic" || funcName == "Panicf") {
			return true
		}

		// fmt пакет для печати
		if pkgName == "fmt" && (funcName == "Print" || funcName == "Printf" ||
			funcName == "Println" || funcName == "Sprint" ||
			funcName == "Sprintf" || funcName == "Sprintln") {
			return true
		}

		// популярные библиотеки логирования
		if (pkgName == "logger" || pkgName == "logging" || pkgName == "logrus" ||
			pkgName == "zap" || pkgName == "zerolog") &&
			(funcName == "Error" || funcName == "Errorf" ||
				funcName == "Warn" || funcName == "Warnf" ||
				funcName == "Info" || funcName == "Infof" ||
				funcName == "Debug" || funcName == "Debugf") {
			return true
		}
	}

	return false
}
