package rules

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"go-audit/pkg/report"
)

// InsecureHTTPRule проверяет код на наличие небезопасных HTTP-настроек
type InsecureHTTPRule struct {
	BaseRule
}

// NewInsecureHTTPRule создает новое правило для проверки небезопасных HTTP-настроек
func NewInsecureHTTPRule() *InsecureHTTPRule {
	return &InsecureHTTPRule{
		BaseRule: BaseRule{
			id:          "SEC003",
			description: "Обнаружены небезопасные настройки HTTP-сервера",
			severity:    report.SeverityHigh,
		},
	}
}

// Check реализует интерфейс Rule
func (r *InsecureHTTPRule) Check(ctx *Context) []report.Issue {
	var issues []report.Issue

	ast.Inspect(ctx.File, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			// Проверяем структуры на наличие небезопасных настроек в tls.Config и http.Transport
			if r.isTLSConfigLiteral(node) {
				issues = append(issues, r.checkTLSConfig(node, ctx)...)
			} else if r.isHTTPTransportLiteral(node) {
				issues = append(issues, r.checkHTTPTransport(node, ctx)...)
			} else if r.isHTTPServerLiteral(node) {
				issues = append(issues, r.checkHTTPServer(node, ctx)...)
			}

		case *ast.CallExpr:
			// Проверяем вызовы функций
			if callExpr, ok := node.Fun.(*ast.SelectorExpr); ok {
				if r.isInsecureHTTPFunction(callExpr) {
					issues = append(issues, r.NewIssue(node.Pos(), ctx,
						"Использование небезопасной HTTP-функции "+callExpr.Sel.Name))
				}
			}

			// Проверяем на использование HTTP вместо HTTPS для URL
			if r.isHTTPURLInCode(node) {
				issues = append(issues, r.NewIssue(node.Pos(), ctx,
					"Использование HTTP вместо HTTPS, что не рекомендуется с точки зрения безопасности"))
			}
		}
		return true
	})

	return issues
}

// isTLSConfigLiteral проверяет, является ли составной литерал экземпляром tls.Config
func (r *InsecureHTTPRule) isTLSConfigLiteral(lit *ast.CompositeLit) bool {
	if typeExpr, ok := lit.Type.(*ast.SelectorExpr); ok {
		if ident, ok := typeExpr.X.(*ast.Ident); ok {
			return ident.Name == "tls" && typeExpr.Sel.Name == "Config"
		}
	}
	return false
}

// isHTTPTransportLiteral проверяет, является ли составной литерал экземпляром http.Transport
func (r *InsecureHTTPRule) isHTTPTransportLiteral(lit *ast.CompositeLit) bool {
	if typeExpr, ok := lit.Type.(*ast.SelectorExpr); ok {
		if ident, ok := typeExpr.X.(*ast.Ident); ok {
			return ident.Name == "http" && typeExpr.Sel.Name == "Transport"
		}
	}
	return false
}

// isHTTPServerLiteral проверяет, является ли составной литерал экземпляром http.Server
func (r *InsecureHTTPRule) isHTTPServerLiteral(lit *ast.CompositeLit) bool {
	if typeExpr, ok := lit.Type.(*ast.SelectorExpr); ok {
		if ident, ok := typeExpr.X.(*ast.Ident); ok {
			return ident.Name == "http" && typeExpr.Sel.Name == "Server"
		}
	}
	return false
}

// isInsecureHTTPFunction проверяет, является ли вызов функции небезопасной HTTP-функцией
func (r *InsecureHTTPRule) isInsecureHTTPFunction(sel *ast.SelectorExpr) bool {
	if ident, ok := sel.X.(*ast.Ident); ok {
		if ident.Name == "http" {
			// Проверяем небезопасные функции из пакета http
			insecureFuncs := map[string]bool{
				"ListenAndServe": true, // http.ListenAndServe обычно использует HTTP, а не HTTPS
			}
			return insecureFuncs[sel.Sel.Name]
		}
	}
	return false
}

// isHTTPURLInCode проверяет, используется ли HTTP URL вместо HTTPS
func (r *InsecureHTTPRule) isHTTPURLInCode(callExpr *ast.CallExpr) bool {
	// Проверяем аргументы вызова функции
	for _, arg := range callExpr.Args {
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			// Проверяем наличие HTTP URL, но не HTTPS
			value := strings.Trim(lit.Value, `"'`)
			if strings.HasPrefix(value, "http://") {
				// Исключаем localhost и локальные адреса
				if !strings.Contains(value, "localhost") && !regexp.MustCompile(`http://127\.0\.0\.1`).MatchString(value) && !regexp.MustCompile(`http://0\.0\.0\.0`).MatchString(value) {
					return true
				}
			}
		}
	}
	return false
}

// checkTLSConfig проверяет небезопасные настройки в tls.Config
func (r *InsecureHTTPRule) checkTLSConfig(lit *ast.CompositeLit, ctx *Context) []report.Issue {
	var issues []report.Issue

	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				switch key.Name {
				case "InsecureSkipVerify":
					// Проверяем InsecureSkipVerify = true
					if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
						issues = append(issues, r.NewIssue(kv.Pos(), ctx,
							"InsecureSkipVerify=true отключает проверку сертификатов TLS, что опасно"))
					}
				case "MinVersion":
					// Проверяем на низкие версии TLS
					if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
						if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "tls" {
							if sel.Sel.Name == "VersionSSL30" || sel.Sel.Name == "VersionTLS10" || sel.Sel.Name == "VersionTLS11" {
								issues = append(issues, r.NewIssue(kv.Pos(), ctx,
									"Использование устаревшей и небезопасной версии TLS: "+sel.Sel.Name))
							}
						}
					}
				}
			}
		}
	}

	return issues
}

// checkHTTPTransport проверяет небезопасные настройки в http.Transport
func (r *InsecureHTTPRule) checkHTTPTransport(lit *ast.CompositeLit, ctx *Context) []report.Issue {
	var issues []report.Issue

	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				if key.Name == "TLSClientConfig" {
					// Если это TLSClientConfig, проверяем его значение
					if nestedLit, ok := kv.Value.(*ast.CompositeLit); ok {
						issues = append(issues, r.checkTLSConfig(nestedLit, ctx)...)
					}
				} else if key.Name == "DisableKeepAlives" || key.Name == "DisableCompression" {
					// Проверяем на отключение важных функций безопасности
					if ident, ok := kv.Value.(*ast.Ident); ok && ident.Name == "true" {
						issues = append(issues, r.NewIssue(kv.Pos(), ctx,
							"Отключение "+key.Name+" может привести к проблемам безопасности или производительности"))
					}
				}
			}
		}
	}

	return issues
}

// checkHTTPServer проверяет небезопасные настройки в http.Server
func (r *InsecureHTTPRule) checkHTTPServer(lit *ast.CompositeLit, ctx *Context) []report.Issue {
	var issues []report.Issue

	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				switch key.Name {
				case "TLSConfig":
					// Если это TLSConfig, проверяем его значение
					if nestedLit, ok := kv.Value.(*ast.CompositeLit); ok {
						issues = append(issues, r.checkTLSConfig(nestedLit, ctx)...)
					}
				case "ReadTimeout", "WriteTimeout", "IdleTimeout":
					// Проверяем отсутствие таймаутов
					if _, ok := kv.Value.(*ast.BasicLit); !ok {
						// Если значение не является литералом (например, 0 или некоторая константа),
						// возможно, таймаут отсутствует
						hasMissingTimeout := true
						for _, otherElt := range lit.Elts {
							if otherKV, ok := otherElt.(*ast.KeyValueExpr); ok {
								if otherKey, ok := otherKV.Key.(*ast.Ident); ok && otherKey.Name == key.Name {
									hasMissingTimeout = false
									break
								}
							}
						}
						if hasMissingTimeout {
							issues = append(issues, r.NewIssue(lit.Pos(), ctx,
								"Отсутствует важный таймаут "+key.Name+" для http.Server, что может сделать сервер уязвимым к DoS-атакам"))
						}
					}
				}
			}
		}
	}

	// Проверяем, указан ли TLSConfig для сервера
	hasTLSConfig := false
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "TLSConfig" {
				hasTLSConfig = true
				break
			}
		}
	}

	if !hasTLSConfig {
		issues = append(issues, r.NewIssue(lit.Pos(), ctx,
			"HTTP-сервер не настроен для использования TLS (HTTPS), что небезопасно для производственной среды"))
	}

	return issues
}
