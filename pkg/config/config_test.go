package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestDefaultConfig проверяет создание конфигурации по умолчанию
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Проверяем, что конфигурация не nil
	if cfg == nil {
		t.Fatal("DefaultConfig() вернул nil")
	}

	// Проверяем значения по умолчанию
	if len(cfg.EnabledRules) != 0 {
		t.Errorf("EnabledRules должен быть пустым списком, получено: %v", cfg.EnabledRules)
	}

	if len(cfg.DisabledRules) != 0 {
		t.Errorf("DisabledRules должен быть пустым списком, получено: %v", cfg.DisabledRules)
	}

	// Проверяем, что исключения по умолчанию содержат vendor/, testdata/ и *_test.go
	expectedExcludes := []string{"vendor/", "testdata/", "*_test.go"}
	if !reflect.DeepEqual(cfg.Exclude, expectedExcludes) {
		t.Errorf("Exclude должен быть %v, получено: %v", expectedExcludes, cfg.Exclude)
	}

	// Проверяем, что карта переопределений серьезности пуста
	if len(cfg.SeverityOverrides) != 0 {
		t.Errorf("SeverityOverrides должен быть пустой картой, получено: %v", cfg.SeverityOverrides)
	}

	// Проверяем, что карта настроек правил пуста
	if len(cfg.RuleSettings) != 0 {
		t.Errorf("RuleSettings должен быть пустой картой, получено: %v", cfg.RuleSettings)
	}
}

// TestLoadAndSave проверяет загрузку и сохранение конфигурации
func TestLoadAndSave(t *testing.T) {
	// Создаем временный файл конфигурации
	tempFile, err := ioutil.TempFile("", "gosecheck-config-*.json")
	if err != nil {
		t.Fatalf("Ошибка создания временного файла: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Создаем тестовую конфигурацию
	testConfig := &Config{
		EnabledRules:  []string{"SEC001", "SEC003"},
		DisabledRules: []string{"SEC002"},
		SeverityOverrides: map[string]string{
			"SEC001": "HIGH",
			"SEC003": "MEDIUM",
		},
		Exclude: []string{"vendor/", "testdata/", "generated/"},
		RuleSettings: map[string]map[string]interface{}{
			"SEC001": {
				"customParam": "value",
				"threshold":   10,
			},
		},
	}

	// Сериализуем и записываем конфигурацию во временный файл
	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Ошибка маршалинга тестовой конфигурации: %v", err)
	}

	err = ioutil.WriteFile(tempFile.Name(), data, 0644)
	if err != nil {
		t.Fatalf("Ошибка записи тестовой конфигурации: %v", err)
	}

	// Загружаем конфигурацию из файла
	loadedConfig, err := Load(tempFile.Name())
	if err != nil {
		t.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Проверяем, что загруженная конфигурация соответствует тестовой
	if !reflect.DeepEqual(loadedConfig.EnabledRules, testConfig.EnabledRules) {
		t.Errorf("EnabledRules не совпадают, ожидалось: %v, получено: %v",
			testConfig.EnabledRules, loadedConfig.EnabledRules)
	}

	if !reflect.DeepEqual(loadedConfig.DisabledRules, testConfig.DisabledRules) {
		t.Errorf("DisabledRules не совпадают, ожидалось: %v, получено: %v",
			testConfig.DisabledRules, loadedConfig.DisabledRules)
	}

	if !reflect.DeepEqual(loadedConfig.SeverityOverrides, testConfig.SeverityOverrides) {
		t.Errorf("SeverityOverrides не совпадают, ожидалось: %v, получено: %v",
			testConfig.SeverityOverrides, loadedConfig.SeverityOverrides)
	}

	if !reflect.DeepEqual(loadedConfig.Exclude, testConfig.Exclude) {
		t.Errorf("Exclude не совпадают, ожидалось: %v, получено: %v",
			testConfig.Exclude, loadedConfig.Exclude)
	}

	// Проверяем сохранение конфигурации
	saveFile, err := ioutil.TempFile("", "gosecheck-config-save-*.json")
	if err != nil {
		t.Fatalf("Ошибка создания временного файла для сохранения: %v", err)
	}
	defer os.Remove(saveFile.Name())

	err = loadedConfig.Save(saveFile.Name())
	if err != nil {
		t.Fatalf("Ошибка сохранения конфигурации: %v", err)
	}

	// Загружаем сохраненную конфигурацию
	savedConfig, err := Load(saveFile.Name())
	if err != nil {
		t.Fatalf("Ошибка загрузки сохраненной конфигурации: %v", err)
	}

	// Проверяем, что сохраненная конфигурация соответствует исходной
	if !reflect.DeepEqual(savedConfig, loadedConfig) {
		t.Error("Сохраненная конфигурация не соответствует исходной")
	}
}

// TestLoadDefault проверяет загрузку конфигурации по умолчанию
func TestLoadDefault(t *testing.T) {
	// Загружаем конфигурацию без указания файла
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Ошибка при загрузке конфигурации по умолчанию: %v", err)
	}

	// Проверяем, что вернулась конфигурация по умолчанию
	defaultCfg := DefaultConfig()
	if !reflect.DeepEqual(cfg, defaultCfg) {
		t.Error("Загруженная конфигурация не соответствует конфигурации по умолчанию")
	}
}

// TestLoadNonExistent проверяет загрузку несуществующего файла конфигурации
func TestLoadNonExistent(t *testing.T) {
	// Пытаемся загрузить несуществующий файл
	_, err := Load("non_existent_file.json")
	if err == nil {
		t.Error("Ожидалась ошибка при загрузке несуществующего файла")
	}
}

// TestLoadInvalid проверяет загрузку некорректного файла конфигурации
func TestLoadInvalid(t *testing.T) {
	// Создаем временный файл с некорректным JSON
	tempFile, err := ioutil.TempFile("", "gosecheck-invalid-*.json")
	if err != nil {
		t.Fatalf("Ошибка создания временного файла: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Записываем некорректный JSON
	invalidJSON := `{"enabledRules": ["SEC001", "SEC003"], "disabledRules": `
	err = ioutil.WriteFile(tempFile.Name(), []byte(invalidJSON), 0644)
	if err != nil {
		t.Fatalf("Ошибка записи некорректного JSON: %v", err)
	}

	// Пытаемся загрузить некорректный файл
	_, err = Load(tempFile.Name())
	if err == nil {
		t.Error("Ожидалась ошибка при загрузке некорректного файла")
	}
}

// TestShouldExclude проверяет метод ShouldExclude
func TestShouldExclude(t *testing.T) {
	cfg := &Config{
		Exclude: []string{
			"vendor/",
			"testdata/",
			"*_test.go",
			"*.generated.go",
		},
	}

	testCases := []struct {
		path     string
		expected bool
	}{
		{"file.go", false},
		{"file_test.go", true},
		{"dir/file.go", false},
		{"vendor/file.go", true},
		{"dir/vendor/file.go", true},
		{"testdata/file.go", true},
		{"dir/testdata/file.go", true},
		{"file.generated.go", true},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			if cfg.ShouldExclude(tc.path) != tc.expected {
				t.Errorf("ShouldExclude(%q) = %v, ожидалось %v", tc.path, !tc.expected, tc.expected)
			}
		})
	}

	// Проверка с абсолютными путями
	absDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("Ошибка получения абсолютного пути: %v", err)
	}

	absPath := filepath.Join(absDir, "file.go")
	if cfg.ShouldExclude(absPath) {
		t.Errorf("ShouldExclude(%q) = true, ожидалось false", absPath)
	}

	absTestPath := filepath.Join(absDir, "file_test.go")
	if !cfg.ShouldExclude(absTestPath) {
		t.Errorf("ShouldExclude(%q) = false, ожидалось true", absTestPath)
	}
}

// TestIsRuleEnabled проверяет метод IsRuleEnabled
func TestIsRuleEnabled(t *testing.T) {
	testCases := []struct {
		name         string
		cfg          *Config
		ruleID       string
		shouldEnable bool
	}{
		{
			name: "empty config enables all rules",
			cfg: &Config{
				EnabledRules:  []string{},
				DisabledRules: []string{},
			},
			ruleID:       "SEC001",
			shouldEnable: true,
		},
		{
			name: "explicitly enabled rule",
			cfg: &Config{
				EnabledRules:  []string{"SEC001", "SEC002"},
				DisabledRules: []string{},
			},
			ruleID:       "SEC001",
			shouldEnable: true,
		},
		{
			name: "rule not in enabled list",
			cfg: &Config{
				EnabledRules:  []string{"SEC001", "SEC002"},
				DisabledRules: []string{},
			},
			ruleID:       "SEC003",
			shouldEnable: false,
		},
		{
			name: "explicitly disabled rule overrides enabled",
			cfg: &Config{
				EnabledRules:  []string{"SEC001", "SEC002"},
				DisabledRules: []string{"SEC001"},
			},
			ruleID:       "SEC001",
			shouldEnable: false,
		},
		{
			name: "disabled rule with empty enabled list",
			cfg: &Config{
				EnabledRules:  []string{},
				DisabledRules: []string{"SEC001"},
			},
			ruleID:       "SEC001",
			shouldEnable: false,
		},
		{
			name: "rule not in disabled list with empty enabled list",
			cfg: &Config{
				EnabledRules:  []string{},
				DisabledRules: []string{"SEC001"},
			},
			ruleID:       "SEC002",
			shouldEnable: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isEnabled := tc.cfg.IsRuleEnabled(tc.ruleID)
			if isEnabled != tc.shouldEnable {
				t.Errorf("IsRuleEnabled(%q) = %v, ожидалось %v", tc.ruleID, isEnabled, tc.shouldEnable)
			}
		})
	}
}

// TestGetRuleSettings проверяет метод GetRuleSettings
func TestGetRuleSettings(t *testing.T) {
	cfg := &Config{
		RuleSettings: map[string]map[string]interface{}{
			"SEC001": {
				"param1": "value1",
				"param2": 42,
			},
			"SEC002": {
				"threshold": 10,
			},
		},
	}

	// Проверка получения настроек для существующего правила
	sec001Settings := cfg.GetRuleSettings("SEC001")
	if sec001Settings == nil {
		t.Fatal("GetRuleSettings(\"SEC001\") вернул nil")
	}

	if sec001Settings["param1"] != "value1" {
		t.Errorf("param1 = %v, ожидалось \"value1\"", sec001Settings["param1"])
	}

	if sec001Settings["param2"] != 42 {
		t.Errorf("param2 = %v, ожидалось 42", sec001Settings["param2"])
	}

	// Проверка получения настроек для другого существующего правила
	sec002Settings := cfg.GetRuleSettings("SEC002")
	if sec002Settings == nil {
		t.Fatal("GetRuleSettings(\"SEC002\") вернул nil")
	}

	if sec002Settings["threshold"] != 10 {
		t.Errorf("threshold = %v, ожидалось 10", sec002Settings["threshold"])
	}

	// Проверка получения настроек для несуществующего правила
	sec003Settings := cfg.GetRuleSettings("SEC003")
	if sec003Settings != nil {
		t.Errorf("GetRuleSettings(\"SEC003\") = %v, ожидалось nil", sec003Settings)
	}
}
