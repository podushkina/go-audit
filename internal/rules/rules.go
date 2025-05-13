package rules

import (
	"go/ast"
	"go/token"

	"go-audit/pkg/config"
	"go-audit/pkg/report"
)

// Context предоставляет контекст для проверки правил
type Context struct {
	FileSet     *token.FileSet
	File        *ast.File
	Config      *config.Config
	FilePath    string
	FileDir     string
	FileContent []byte
	Package     string
}

// Rule представляет правило безопасности, которое можно проверить
type Rule interface {
	// ID возвращает уникальный идентификатор правила
	ID() string

	// Description возвращает человекочитаемое описание правила
	Description() string

	// Severity возвращает уровень серьезности правила
	Severity() report.Severity

	// Check выполняет проверку безопасности и возвращает найденные проблемы
	Check(*Context) []report.Issue
}

// BaseRule предоставляет общую функциональность для всех правил
type BaseRule struct {
	id          string
	description string
	severity    report.Severity
}

// ID возвращает идентификатор правила
func (r *BaseRule) ID() string {
	return r.id
}

// Description возвращает описание правила
func (r *BaseRule) Description() string {
	return r.description
}

// Severity возвращает уровень серьезности правила
func (r *BaseRule) Severity() report.Severity {
	return r.severity
}

// NewIssue создает новую проблему с информацией о правиле
func (r *BaseRule) NewIssue(pos token.Pos, ctx *Context, message string) report.Issue {
	position := ctx.FileSet.Position(pos)

	return report.Issue{
		RuleID:      r.id,
		Severity:    r.severity,
		FilePath:    ctx.FilePath,
		Line:        position.Line,
		Column:      position.Column,
		Message:     message,
		Description: r.description,
	}
}
