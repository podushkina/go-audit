package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Config представляет конфигурацию линтера
type Config struct {
	// Список идентификаторов правил для включения (пустой означает, что все правила включены)
	EnabledRules []string `json:"enabledRules,omitempty"`

	// Список идентификаторов правил для отключения (имеет приоритет над EnabledRules)
	DisabledRules []string `json:"disabledRules,omitempty"`

	// Пользовательские переопределения серьезности для конкретных правил
	SeverityOverrides map[string]string `json:"severityOverrides,omitempty"`

	// Список шаблонов файлов или директорий для исключения
	Exclude []string `json:"exclude,omitempty"`

	// Настройки конкретных правил
	RuleSettings map[string]map[string]interface{} `json:"ruleSettings,omitempty"`
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		// По умолчанию все правила включены
		EnabledRules:      []string{},
		DisabledRules:     []string{},
		SeverityOverrides: map[string]string{},
		Exclude: []string{
			"vendor/",
			"testdata/",
			"*_test.go",
		},
		RuleSettings: map[string]map[string]interface{}{},
	}
}

// Load загружает конфигурацию из JSON-файла
func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Если файл конфигурации не указан, используем значения по умолчанию
	if configPath == "" {
		// Ищем .gosecheck.json в текущей директории
		if _, err := os.Stat(".gosecheck.json"); err == nil {
			configPath = ".gosecheck.json"
		} else {
			return config, nil
		}
	}

	// Чтение и разбор файла конфигурации
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Save записывает конфигурацию в указанный файл
func (c *Config) Save(configPath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// ShouldExclude проверяет, должен ли файл быть исключен на основе конфигурации
func (c *Config) ShouldExclude(path string) bool {
	for _, pattern := range c.Exclude {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}

		// Также проверяем исключения директорий
		if filepath.IsAbs(path) && filepath.IsAbs(pattern) {
			relPath, err := filepath.Rel(pattern, path)
			if err == nil && !filepath.IsAbs(relPath) && !strings.HasPrefix(relPath, "..") {
				return true
			}
		}
	}

	return false
}

// IsRuleEnabled проверяет, включено ли правило
func (c *Config) IsRuleEnabled(ruleID string) bool {
	// Сначала проверяем, явно ли отключено правило
	for _, id := range c.DisabledRules {
		if id == ruleID {
			return false
		}
	}

	// Если не указаны конкретные правила, все правила включены
	if len(c.EnabledRules) == 0 {
		return true
	}

	// Проверяем, явно ли включено правило
	for _, id := range c.EnabledRules {
		if id == ruleID {
			return true
		}
	}

	return false
}

// GetRuleSettings получает пользовательские настройки для конкретного правила
func (c *Config) GetRuleSettings(ruleID string) map[string]interface{} {
	if settings, ok := c.RuleSettings[ruleID]; ok {
		return settings
	}
	return nil
}
