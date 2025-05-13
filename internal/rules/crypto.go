package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"go-audit/pkg/report"
)

// InsecureCryptoRule проверяет код на использование небезопасных криптографических функций
type InsecureCryptoRule struct {
	BaseRule
	// Карты для проверки опасных криптографических алгоритмов
	insecureHashAlgorithms    map[string]bool
	insecureCipherAlgorithms  map[string]bool
	deprecatedCryptoFunctions map[string]string
	weakKeyLengths            map[string]int
}

// NewInsecureCryptoRule создает новое правило для проверки небезопасных криптографических функций
func NewInsecureCryptoRule() *InsecureCryptoRule {
	return &InsecureCryptoRule{
		BaseRule: BaseRule{
			id:          "SEC005",
			description: "Использование устаревших или небезопасных криптографических функций",
			severity:    report.SeverityHigh,
		},
		insecureHashAlgorithms: map[string]bool{
			"MD4":       true,
			"MD5":       true,
			"SHA1":      true,
			"RIPEMD160": true,
		},
		insecureCipherAlgorithms: map[string]bool{
			"DES":      true,
			"3DES":     true,
			"RC4":      true,
			"Blowfish": true,
			"IDEA":     true,
			"CAST5":    true,
		},
		deprecatedCryptoFunctions: map[string]string{
			"GenerateKey":          "Использование GenerateKey может быть небезопасно без надлежащей энтропии",
			"NewCipher":            "Убедитесь, что используется безопасный алгоритм шифрования",
			"Seal":                 "Проверьте используемые параметры аутентификации",
			"Open":                 "Проверьте используемые параметры аутентификации",
			"NewCBCEncrypter":      "Режим CBC может быть уязвим к padding oracle attack",
			"NewCBCDecrypter":      "Режим CBC может быть уязвим к padding oracle attack",
			"NewCTR":               "Режим CTR требует уникального nonce для каждого сообщения",
			"NewOFB":               "Режим OFB требует уникального IV для каждого сообщения",
			"NewCFB":               "Режим CFB требует уникального IV для каждого сообщения",
			"GenerateFromPassword": "Проверьте используемые параметры стоимости для bcrypt",
		},
		weakKeyLengths: map[string]int{
			"RSA":   2048, // Минимум 2048 бит
			"AES":   128,  // Минимум 128 бит
			"ECDSA": 256,  // Минимум 256 бит
			"DSA":   2048, // Минимум 2048 бит
			"HMAC":  256,  // Минимум 256 бит
		},
	}
}

// Check реализует интерфейс Rule
func (r *InsecureCryptoRule) Check(ctx *Context) []report.Issue {
	var issues []report.Issue

	// Проверяем импорты на наличие криптографических пакетов
	hasCryptoImport := false
	for _, imp := range ctx.File.Imports {
		if imp.Path != nil {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(path, "crypto/") ||
				strings.Contains(path, "crypto") ||
				strings.Contains(path, "cipher") ||
				strings.Contains(path, "hash") {
				hasCryptoImport = true
				break
			}
		}
	}

	// Если нет криптографических импортов, нет необходимости проверять дальше
	if !hasCryptoImport {
		return issues
	}

	// Проверяем использование криптографических функций
	ast.Inspect(ctx.File, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Проверяем вызовы функций из определенных пакетов
			if x, ok := node.X.(*ast.Ident); ok {
				// Проверяем небезопасные пакеты хеширования
				if x.Name == "md5" || x.Name == "sha1" {
					issues = append(issues, r.NewIssue(node.Pos(), ctx,
						"Использование небезопасного алгоритма хеширования: "+x.Name))
				}

				// Проверяем устаревшие шифры
				if x.Name == "des" || x.Name == "rc4" {
					issues = append(issues, r.NewIssue(node.Pos(), ctx,
						"Использование устаревшего шифра: "+x.Name))
				}

				// Проверяем функцию из пакета crypto
				if x.Name == "crypto" && r.insecureHashAlgorithms[node.Sel.Name] {
					issues = append(issues, r.NewIssue(node.Pos(), ctx,
						"Использование небезопасного алгоритма хеширования: "+node.Sel.Name))
				}
			}

		case *ast.CallExpr:
			// Проверяем вызовы функций
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					// Проверяем небезопасные вызовы в определенных пакетах
					r.checkCryptoCall(x.Name, sel.Sel.Name, node, ctx, &issues)
				}
			}

		case *ast.ValueSpec:
			// Проверяем объявления переменных для слабых ключей
			for _, val := range node.Values {
				if callExpr, ok := val.(*ast.CallExpr); ok {
					if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
						if x, ok := sel.X.(*ast.Ident); ok {
							// Проверяем генерацию ключей
							r.checkKeyGeneration(x.Name, sel.Sel.Name, callExpr, ctx, &issues)
						}
					}
				}
			}
		}

		return true
	})

	return issues
}

// checkCryptoCall проверяет вызовы криптографических функций
func (r *InsecureCryptoRule) checkCryptoCall(pkgName, funcName string, callExpr *ast.CallExpr, ctx *Context, issues *[]report.Issue) {
	// Проверяем небезопасные хеш-функции
	if pkgName == "md5" && funcName == "New" {
		*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
			"Использование MD5 не рекомендуется для криптографических целей"))
	}

	if pkgName == "sha1" && funcName == "New" {
		*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
			"Использование SHA1 не рекомендуется для криптографических целей"))
	}

	// Проверяем небезопасные шифры
	if pkgName == "des" && (funcName == "NewCipher" || funcName == "NewTripleDESCipher") {
		*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
			"DES и 3DES считаются устаревшими и небезопасными, используйте AES"))
	}

	if pkgName == "rc4" && funcName == "NewCipher" {
		*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
			"RC4 считается криптографически слабым, используйте современные AEAD шифры"))
	}

	// Проверяем потенциально опасные режимы шифрования
	if pkgName == "cipher" {
		if message, ok := r.deprecatedCryptoFunctions[funcName]; ok {
			*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx, message))
		}
	}

	// Проверяем генерацию случайных чисел
	if pkgName == "rand" && funcName == "Read" {
		// Проверяем, что используется crypto/rand, а не math/rand
		if !r.isImportedFromCrypto(ctx, "rand") {
			*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
				"Использование небезопасного генератора случайных чисел, используйте crypto/rand"))
		}
	}

	// Проверяем bcrypt настройки
	if pkgName == "bcrypt" && funcName == "GenerateFromPassword" {
		if len(callExpr.Args) >= 2 {
			// Проверяем, что используется достаточный уровень стоимости (>= 10)
			if lit, ok := callExpr.Args[1].(*ast.BasicLit); ok && lit.Kind == token.INT {
				if lit.Value == "4" || lit.Value == "5" || lit.Value == "6" {
					*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
						"Слишком низкое значение стоимости для bcrypt, используйте как минимум 10"))
				}
			}
		}
	}
}

// checkKeyGeneration проверяет безопасность генерируемых ключей
func (r *InsecureCryptoRule) checkKeyGeneration(pkgName, funcName string, callExpr *ast.CallExpr, ctx *Context, issues *[]report.Issue) {
	// Проверки для RSA
	if pkgName == "rsa" && funcName == "GenerateKey" {
		if len(callExpr.Args) >= 1 {
			// Проверяем длину ключа RSA
			if lit, ok := callExpr.Args[0].(*ast.BasicLit); ok && lit.Kind == token.INT {
				// Преобразуем строковое значение в число
				var value int
				if _, err := fmt.Sscanf(lit.Value, "%d", &value); err == nil && value < 2048 {
					*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
						"Используется недостаточно безопасная длина ключа RSA, должно быть >= 2048 бит"))
				}
			}
		}
	}

	// Проверки для генерации ключей шифрования
	if pkgName == "aes" && funcName == "NewCipher" {
		if len(callExpr.Args) >= 1 {
			if lit, ok := callExpr.Args[0].(*ast.Ident); ok {
				if len(lit.Name) < 16 { // ключ AES должен быть не менее 16 байтов (128 бит)
					*issues = append(*issues, r.NewIssue(callExpr.Pos(), ctx,
						"Слишком короткий ключ для AES, должно быть минимум 16 байтов (128 бит)"))
				}
			}
		}
	}
}

// isImportedFromCrypto проверяет, что пакет импортирован из crypto/
func (r *InsecureCryptoRule) isImportedFromCrypto(ctx *Context, pkgName string) bool {
	for _, imp := range ctx.File.Imports {
		if imp.Path != nil {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "crypto/"+pkgName {
				return true
			}
		}
	}
	return false
}
