package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity представляет уровень серьезности проблемы
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Issue представляет проблему безопасности, найденную правилом
type Issue struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	FilePath    string   `json:"filePath"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Message     string   `json:"message"`
	Description string   `json:"description"`
}

// Reporter интерфейс для различных форматов отчетов
type Reporter interface {
	Generate(issues []Issue) string
}

// TextReporter генерирует текстовые отчеты
type TextReporter struct{}

// NewTextReporter создает новый текстовый репортер
func NewTextReporter() *TextReporter {
	return &TextReporter{}
}

// Generate реализует интерфейс Reporter
func (r *TextReporter) Generate(issues []Issue) string {
	if len(issues) == 0 {
		return "Проблем безопасности не обнаружено."
	}

	var builder strings.Builder

	// Сортировка проблем по серьезности и пути к файлу
	sortIssues(issues)

	// Отслеживаем текущий файл для группировки проблем по файлам
	currentFile := ""

	// Заголовок
	builder.WriteString("Go-audit - Отчет по анализу безопасности\n")
	builder.WriteString(fmt.Sprintf("Дата: %s\n", time.Now().Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("Всего проблем: %d\n\n", len(issues)))

	// Подсчет проблем по серьезности
	severityCounts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	for _, issue := range issues {
		severityCounts[issue.Severity]++
	}

	// Сводка по серьезности
	builder.WriteString("Сводка по серьезности проблем:\n")
	builder.WriteString(fmt.Sprintf("  КРИТИЧНЫЕ:  %d\n", severityCounts[SeverityCritical]))
	builder.WriteString(fmt.Sprintf("  ВЫСОКИЕ:    %d\n", severityCounts[SeverityHigh]))
	builder.WriteString(fmt.Sprintf("  СРЕДНИЕ:    %d\n", severityCounts[SeverityMedium]))
	builder.WriteString(fmt.Sprintf("  НИЗКИЕ:     %d\n", severityCounts[SeverityLow]))
	builder.WriteString(fmt.Sprintf("  ИНФО:       %d\n\n", severityCounts[SeverityInfo]))

	// Подробные проблемы
	builder.WriteString("Найденные проблемы:\n")
	for _, issue := range issues {
		if issue.FilePath != currentFile {
			builder.WriteString(fmt.Sprintf("\nФайл: %s\n", issue.FilePath))
			currentFile = issue.FilePath
		}

		builder.WriteString(fmt.Sprintf("  [%s] %s (Строка %d, Столбец %d)\n",
			issue.Severity, issue.RuleID, issue.Line, issue.Column))
		builder.WriteString(fmt.Sprintf("    %s\n", issue.Message))
		builder.WriteString(fmt.Sprintf("    Правило: %s\n", issue.Description))
	}

	return builder.String()
}

// JSONReporter генерирует отчеты в формате JSON
type JSONReporter struct{}

// NewJSONReporter создает новый JSON репортер
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// JSONReport представляет структуру JSON-отчета
type JSONReport struct {
	Timestamp   string         `json:"timestamp"`
	TotalIssues int            `json:"totalIssues"`
	Summary     map[string]int `json:"summary"`
	Issues      []Issue        `json:"issues"`
}

// Generate реализует интерфейс Reporter
func (r *JSONReporter) Generate(issues []Issue) string {
	sortIssues(issues)

	// Подсчет проблем по серьезности
	summary := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}

	for _, issue := range issues {
		summary[string(issue.Severity)]++
	}

	report := JSONReport{
		Timestamp:   time.Now().Format(time.RFC3339),
		TotalIssues: len(issues),
		Summary:     summary,
		Issues:      issues,
	}

	// Преобразование в JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Ошибка генерации отчета в формате JSON: %v", err)
	}

	return string(jsonData)
}

// Вспомогательная функция для сортировки проблем
func sortIssues(issues []Issue) {
	// Порядок серьезности для сортировки
	severityOrder := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityMedium:   2,
		SeverityLow:      3,
		SeverityInfo:     4,
	}

	// Сортировка по серьезности (более высокий приоритет сначала), затем по пути к файлу, затем по номеру строки
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Severity != issues[j].Severity {
			return severityOrder[issues[i].Severity] < severityOrder[issues[j].Severity]
		}
		if issues[i].FilePath != issues[j].FilePath {
			return issues[i].FilePath < issues[j].FilePath
		}
		return issues[i].Line < issues[j].Line
	})
}
