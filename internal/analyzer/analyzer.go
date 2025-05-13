package analyzer

import (
	_ "go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
	"go-audit/internal/rules"
	"go-audit/pkg/config"
	"go-audit/pkg/report"
)

// Analyzer обрабатывает статический анализ кода
type Analyzer struct {
	config *config.Config
	rules  []rules.Rule
}

// New создает новый Analyzer с предоставленной конфигурацией
func New(cfg *config.Config) *Analyzer {
	return &Analyzer{
		config: cfg,
		rules: []rules.Rule{
			rules.NewSQLInjectionRule(),
			rules.NewHardcodedSecretsRule(),
			rules.NewInsecureHTTPRule(),
			rules.NewMissingErrorCheckRule(),
			rules.NewInsecureCryptoRule(),
			rules.NewInsecureUserInputRule(),
		},
	}
}

// AnalyzeFiles выполняет анализ безопасности указанных Go-файлов
func (a *Analyzer) AnalyzeFiles(filePaths []string) ([]report.Issue, error) {
	var (
		allIssues []report.Issue
		mu        sync.Mutex
		wg        sync.WaitGroup
		semaphore = make(chan struct{}, 10) // Ограничиваем количество одновременных горутин
	)

	for _, filePath := range filePaths {
		wg.Add(1)
		semaphore <- struct{}{} // Получаем семафор

		go func(path string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Освобождаем семафор

			issues, err := a.analyzeFile(path)
			if err != nil {
				log.Error().Err(err).Str("file", path).Msg("Ошибка анализа файла")
				return
			}

			if len(issues) > 0 {
				mu.Lock()
				allIssues = append(allIssues, issues...)
				mu.Unlock()

				log.Debug().Str("file", path).Int("issues", len(issues)).Msg("Найдены проблемы в файле")
			}
		}(filePath)
	}

	wg.Wait()
	return allIssues, nil
}

// analyzeFile анализирует один Go-файл
func (a *Analyzer) analyzeFile(filePath string) ([]report.Issue, error) {
	// Проверяем, должен ли файл быть исключен
	if a.config != nil && a.config.ShouldExclude(filePath) {
		log.Debug().Str("file", filePath).Msg("Файл исключен из анализа")
		return nil, nil
	}

	fset := token.NewFileSet()
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseFile(fset, filePath, content, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var issues []report.Issue
	fileDir := filepath.Dir(filePath)

	ctx := &rules.Context{
		FileSet:     fset,
		File:        file,
		Config:      a.config,
		FilePath:    filePath,
		FileDir:     fileDir,
		FileContent: content,
		Package:     file.Name.Name,
	}

	for _, rule := range a.rules {
		if !a.isRuleEnabled(rule.ID()) {
			log.Debug().Str("rule", rule.ID()).Msg("Правило отключено")
			continue
		}

		log.Debug().Str("rule", rule.ID()).Str("file", filePath).Msg("Запуск проверки правилом")
		ruleIssues := rule.Check(ctx)
		issues = append(issues, ruleIssues...)
	}

	return issues, nil
}

// isRuleEnabled проверяет, включено ли правило в конфигурации
func (a *Analyzer) isRuleEnabled(ruleID string) bool {
	if a.config == nil {
		// Если конфигурация не указана, все правила включены по умолчанию
		return true
	}

	return a.config.IsRuleEnabled(ruleID)
}
