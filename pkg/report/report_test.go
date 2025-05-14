package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTextReporterNoIssues проверяет генерацию текстового отчета без проблем
func TestTextReporterNoIssues(t *testing.T) {
	reporter := NewTextReporter()
	report := reporter.Generate([]Issue{})

	expected := "Проблем безопасности не обнаружено."
	if report != expected {
		t.Errorf("Неверный отчет без проблем, получено: %q, ожидалось: %q", report, expected)
	}
}

// TestTextReporterWithIssues проверяет генерацию текстового отчета с проблемами
func TestTextReporterWithIssues(t *testing.T) {
	reporter := NewTextReporter()

	issues := []Issue{
		{
			RuleID:      "SEC001",
			Severity:    SeverityHigh,
			FilePath:    "main.go",
			Line:        42,
			Column:      10,
			Message:     "Потенциальная SQL-инъекция",
			Description: "Обнаружена потенциальная SQL-инъекция",
		},
		{
			RuleID:      "SEC002",
			Severity:    SeverityCritical,
			FilePath:    "main.go",
			Line:        50,
			Column:      5,
			Message:     "Жёстко закодированный пароль",
			Description: "Обнаружен жёстко закодированный пароль",
		},
		{
			RuleID:      "SEC003",
			Severity:    SeverityMedium,
			FilePath:    "api/server.go",
			Line:        30,
			Column:      15,
			Message:     "Небезопасная конфигурация HTTP",
			Description: "Обнаружена небезопасная конфигурация HTTP",
		},
	}

	report := reporter.Generate(issues)

	// Проверяем наличие ключевых данных в отчете
	if !strings.Contains(report, "Go-audit - Отчет по анализу безопасности") {
		t.Error("Отчет не содержит заголовок")
	}

	if !strings.Contains(report, "Всего проблем: 3") {
		t.Error("Отчет не содержит общее количество проблем")
	}

	if !strings.Contains(report, "КРИТИЧНЫЕ:  1") {
		t.Error("Отчет не содержит количество критичных проблем")
	}

	if !strings.Contains(report, "ВЫСОКИЕ:    1") {
		t.Error("Отчет не содержит количество высоких проблем")
	}

	if !strings.Contains(report, "СРЕДНИЕ:    1") {
		t.Error("Отчет не содержит количество средних проблем")
	}

	if !strings.Contains(report, "Файл: main.go") {
		t.Error("Отчет не содержит имя файла main.go")
	}

	if !strings.Contains(report, "Файл: api/server.go") {
		t.Error("Отчет не содержит имя файла api/server.go")
	}

	if !strings.Contains(report, "Потенциальная SQL-инъекция") {
		t.Error("Отчет не содержит сообщение о SQL-инъекции")
	}

	if !strings.Contains(report, "Жёстко закодированный пароль") {
		t.Error("Отчет не содержит сообщение о жёстко закодированном пароле")
	}

	if !strings.Contains(report, "Небезопасная конфигурация HTTP") {
		t.Error("Отчет не содержит сообщение о небезопасной конфигурации HTTP")
	}
}

// TestJSONReporterNoIssues проверяет генерацию JSON отчета без проблем
func TestJSONReporterNoIssues(t *testing.T) {
	reporter := NewJSONReporter()
	reportStr := reporter.Generate([]Issue{})

	var jsonReport JSONReport
	err := json.Unmarshal([]byte(reportStr), &jsonReport)
	if err != nil {
		t.Fatalf("Ошибка разбора JSON-отчета: %v", err)
	}

	if jsonReport.TotalIssues != 0 {
		t.Errorf("TotalIssues = %d, ожидалось 0", jsonReport.TotalIssues)
	}

	if len(jsonReport.Issues) != 0 {
		t.Errorf("len(Issues) = %d, ожидалось 0", len(jsonReport.Issues))
	}

	// Проверяем количество проблем по уровням серьезности
	if jsonReport.Summary["CRITICAL"] != 0 {
		t.Errorf("Summary[\"CRITICAL\"] = %d, ожидалось 0", jsonReport.Summary["CRITICAL"])
	}

	if jsonReport.Summary["HIGH"] != 0 {
		t.Errorf("Summary[\"HIGH\"] = %d, ожидалось 0", jsonReport.Summary["HIGH"])
	}

	if jsonReport.Summary["MEDIUM"] != 0 {
		t.Errorf("Summary[\"MEDIUM\"] = %d, ожидалось 0", jsonReport.Summary["MEDIUM"])
	}

	if jsonReport.Summary["LOW"] != 0 {
		t.Errorf("Summary[\"LOW\"] = %d, ожидалось 0", jsonReport.Summary["LOW"])
	}

	if jsonReport.Summary["INFO"] != 0 {
		t.Errorf("Summary[\"INFO\"] = %d, ожидалось 0", jsonReport.Summary["INFO"])
	}
}

// TestJSONReporterWithIssues проверяет генерацию JSON отчета с проблемами
func TestJSONReporterWithIssues(t *testing.T) {
	reporter := NewJSONReporter()

	issues := []Issue{
		{
			RuleID:      "SEC001",
			Severity:    SeverityHigh,
			FilePath:    "main.go",
			Line:        42,
			Column:      10,
			Message:     "Потенциальная SQL-инъекция",
			Description: "Обнаружена потенциальная SQL-инъекция",
		},
		{
			RuleID:      "SEC002",
			Severity:    SeverityCritical,
			FilePath:    "main.go",
			Line:        50,
			Column:      5,
			Message:     "Жёстко закодированный пароль",
			Description: "Обнаружен жёстко закодированный пароль",
		},
		{
			RuleID:      "SEC003",
			Severity:    SeverityMedium,
			FilePath:    "api/server.go",
			Line:        30,
			Column:      15,
			Message:     "Небезопасная конфигурация HTTP",
			Description: "Обнаружена небезопасная конфигурация HTTP",
		},
	}

	reportStr := reporter.Generate(issues)

	var jsonReport JSONReport
	err := json.Unmarshal([]byte(reportStr), &jsonReport)
	if err != nil {
		t.Fatalf("Ошибка разбора JSON-отчета: %v", err)
	}

	// Проверяем общее количество проблем
	if jsonReport.TotalIssues != 3 {
		t.Errorf("TotalIssues = %d, ожидалось 3", jsonReport.TotalIssues)
	}

	// Проверяем количество проблем по уровням серьезности
	if jsonReport.Summary["CRITICAL"] != 1 {
		t.Errorf("Summary[\"CRITICAL\"] = %d, ожидалось 1", jsonReport.Summary["CRITICAL"])
	}

	if jsonReport.Summary["HIGH"] != 1 {
		t.Errorf("Summary[\"HIGH\"] = %d, ожидалось 1", jsonReport.Summary["HIGH"])
	}

	if jsonReport.Summary["MEDIUM"] != 1 {
		t.Errorf("Summary[\"MEDIUM\"] = %d, ожидалось 1", jsonReport.Summary["MEDIUM"])
	}

	// Проверяем список проблем
	if len(jsonReport.Issues) != 3 {
		t.Errorf("len(Issues) = %d, ожидалось 3", len(jsonReport.Issues))
	}

	// Проверяем первую проблему в списке (отсортированном по серьезности)
	if jsonReport.Issues[0].RuleID != "SEC002" {
		t.Errorf("Issues[0].RuleID = %s, ожидалось SEC002", jsonReport.Issues[0].RuleID)
	}

	if jsonReport.Issues[0].Severity != SeverityCritical {
		t.Errorf("Issues[0].Severity = %s, ожидалось CRITICAL", jsonReport.Issues[0].Severity)
	}

	// Проверяем вторую проблему
	if jsonReport.Issues[1].RuleID != "SEC001" {
		t.Errorf("Issues[1].RuleID = %s, ожидалось SEC001", jsonReport.Issues[1].RuleID)
	}

	if jsonReport.Issues[1].Severity != SeverityHigh {
		t.Errorf("Issues[1].Severity = %s, ожидалось HIGH", jsonReport.Issues[1].Severity)
	}

	// Проверяем третью проблему
	if jsonReport.Issues[2].RuleID != "SEC003" {
		t.Errorf("Issues[2].RuleID = %s, ожидалось SEC003", jsonReport.Issues[2].RuleID)
	}

	if jsonReport.Issues[2].Severity != SeverityMedium {
		t.Errorf("Issues[2].Severity = %s, ожидалось MEDIUM", jsonReport.Issues[2].Severity)
	}
}

// TestSortIssues проверяет сортировку проблем
func TestSortIssues(t *testing.T) {
	issues := []Issue{
		{
			RuleID:      "SEC001",
			Severity:    SeverityMedium,
			FilePath:    "c.go",
			Line:        10,
			Message:     "Medium severity issue",
			Description: "Medium description",
		},
		{
			RuleID:      "SEC002",
			Severity:    SeverityCritical,
			FilePath:    "a.go",
			Line:        20,
			Message:     "Critical severity issue",
			Description: "Critical description",
		},
		{
			RuleID:      "SEC003",
			Severity:    SeverityHigh,
			FilePath:    "b.go",
			Line:        30,
			Message:     "High severity issue",
			Description: "High description",
		},
		{
			RuleID:      "SEC004",
			Severity:    SeverityCritical,
			FilePath:    "a.go",
			Line:        10,
			Message:     "Another critical in same file, earlier line",
			Description: "Critical description",
		},
		{
			RuleID:      "SEC005",
			Severity:    SeverityCritical,
			FilePath:    "a.go",
			Line:        30,
			Message:     "Another critical in same file, later line",
			Description: "Critical description",
		},
	}

	// Сортируем проблемы
	sortIssues(issues)

	// Проверяем порядок отсортированных проблем

	// 1. Сначала должны идти критические проблемы
	if issues[0].Severity != SeverityCritical || issues[1].Severity != SeverityCritical || issues[2].Severity != SeverityCritical {
		t.Error("Первые три проблемы должны быть критического уровня")
	}

	// 2. Затем проблемы с высоким уровнем серьезности
	if issues[3].Severity != SeverityHigh {
		t.Errorf("Четвертая проблема должна быть высокого уровня, получена: %s", issues[3].Severity)
	}

	// 3. Затем проблемы со средним уровнем серьезности
	if issues[4].Severity != SeverityMedium {
		t.Errorf("Пятая проблема должна быть среднего уровня, получена: %s", issues[4].Severity)
	}

	// 4. Проверяем сортировку по имени файла (для проблем с одинаковым уровнем серьезности)
	if issues[0].FilePath != issues[1].FilePath || issues[0].FilePath != issues[2].FilePath {
		t.Error("Критические проблемы должны быть сгруппированы по имени файла")
	}

	// 5. Проверяем сортировку по номеру строки (для проблем с одинаковым уровнем серьезности и в одном файле)
	if issues[0].Line > issues[1].Line || issues[1].Line > issues[2].Line {
		t.Errorf("Проблемы в одном файле должны быть отсортированы по номеру строки: %d, %d, %d",
			issues[0].Line, issues[1].Line, issues[2].Line)
	}
}

// TestIssueCreation проверяет создание объекта Issue
func TestIssueCreation(t *testing.T) {
	issue := Issue{
		RuleID:      "SEC001",
		Severity:    SeverityHigh,
		FilePath:    "main.go",
		Line:        42,
		Column:      10,
		Message:     "Потенциальная SQL-инъекция",
		Description: "Обнаружена потенциальная SQL-инъекция",
	}

	if issue.RuleID != "SEC001" {
		t.Errorf("issue.RuleID = %s, ожидалось SEC001", issue.RuleID)
	}

	if issue.Severity != SeverityHigh {
		t.Errorf("issue.Severity = %s, ожидалось HIGH", issue.Severity)
	}

	if issue.FilePath != "main.go" {
		t.Errorf("issue.FilePath = %s, ожидалось main.go", issue.FilePath)
	}

	if issue.Line != 42 {
		t.Errorf("issue.Line = %d, ожидалось 42", issue.Line)
	}

	if issue.Column != 10 {
		t.Errorf("issue.Column = %d, ожидалось 10", issue.Column)
	}

	if issue.Message != "Потенциальная SQL-инъекция" {
		t.Errorf("issue.Message = %s, ожидалось 'Потенциальная SQL-инъекция'", issue.Message)
	}

	if issue.Description != "Обнаружена потенциальная SQL-инъекция" {
		t.Errorf("issue.Description = %s, ожидалось 'Обнаружена потенциальная SQL-инъекция'", issue.Description)
	}
}

// TestSeverityTypes проверяет константы уровней серьезности
func TestSeverityTypes(t *testing.T) {
	// Проверяем все уровни серьезности
	if SeverityCritical != "CRITICAL" {
		t.Errorf("SeverityCritical = %s, ожидалось CRITICAL", SeverityCritical)
	}

	if SeverityHigh != "HIGH" {
		t.Errorf("SeverityHigh = %s, ожидалось HIGH", SeverityHigh)
	}

	if SeverityMedium != "MEDIUM" {
		t.Errorf("SeverityMedium = %s, ожидалось MEDIUM", SeverityMedium)
	}

	if SeverityLow != "LOW" {
		t.Errorf("SeverityLow = %s, ожидалось LOW", SeverityLow)
	}

	if SeverityInfo != "INFO" {
		t.Errorf("SeverityInfo = %s, ожидалось INFO", SeverityInfo)
	}
}
