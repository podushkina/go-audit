package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go-audit/internal/analyzer"
	"go-audit/pkg/config"
	"go-audit/pkg/report"
)

var (
	// Версия устанавливается при сборке
	Version = "dev"
)

func main() {
	// Настройка логгера
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Парсинг аргументов командной строки
	configFile := flag.String("config", "", "путь к файлу конфигурации")
	outputFormat := flag.String("format", "text", "формат вывода (text, json)")
	outputFile := flag.String("output", "", "выходной файл (по умолчанию: stdout)")
	recursive := flag.Bool("recursive", false, "рекурсивное сканирование директорий")
	excludeDirs := flag.String("exclude", "", "список директорий для исключения через запятую")
	verboseFlag := flag.Bool("verbose", false, "режим подробного вывода")
	versionFlag := flag.Bool("version", false, "вывести версию и выйти")
	flag.Parse()

	// Вывод версии при запросе
	if *versionFlag {
		fmt.Printf("Go-audit v%s\n", Version)
		os.Exit(0)
	}

	// Установка уровня логирования
	if *verboseFlag {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	args := flag.Args()
	if len(args) == 0 {
		log.Error().Msg("Не указаны целевые файлы или директории")
		fmt.Println("Использование: gosecheck [опции] <file.go|directory>...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Загрузка конфигурации
	log.Debug().Str("configFile", *configFile).Msg("Загрузка конфигурации")
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Error().Err(err).Msg("Ошибка загрузки конфигурации")
		os.Exit(1)
	}

	// Инициализация анализатора
	a := analyzer.New(cfg)

	// Поиск всех Go файлов для анализа
	var files []string
	excludeDirsList := strings.Split(*excludeDirs, ",")
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			log.Error().Err(err).Str("path", arg).Msg("Ошибка доступа к файлу/директории")
			continue
		}

		if !info.IsDir() {
			if strings.HasSuffix(arg, ".go") {
				files = append(files, arg)
			}
			continue
		}

		// Это директория, находим все Go файлы
		if *recursive {
			err = filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Проверяем, должна ли директория быть исключена
				if info.IsDir() {
					for _, excludeDir := range excludeDirsList {
						if excludeDir != "" && filepath.Base(path) == excludeDir {
							return filepath.SkipDir
						}
					}
					return nil
				}

				if strings.HasSuffix(path, ".go") {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				log.Error().Err(err).Str("path", arg).Msg("Ошибка при сканировании директории")
			}
		} else {
			fileInfos, err := os.ReadDir(arg)
			if err != nil {
				log.Error().Err(err).Str("path", arg).Msg("Ошибка чтения директории")
				continue
			}

			for _, fileInfo := range fileInfos {
				if fileInfo.IsDir() {
					continue
				}

				path := filepath.Join(arg, fileInfo.Name())
				if strings.HasSuffix(path, ".go") {
					files = append(files, path)
				}
			}
		}
	}

	log.Info().Int("count", len(files)).Msg("Найдено файлов для анализа")

	// Запуск анализа
	results, err := a.AnalyzeFiles(files)
	if err != nil {
		log.Error().Err(err).Msg("Ошибка во время анализа")
		os.Exit(1)
	}

	// Генерация отчета
	var r report.Reporter
	switch *outputFormat {
	case "json":
		r = report.NewJSONReporter()
	default:
		r = report.NewTextReporter()
	}

	output := r.Generate(results)

	// Запись выходных данных
	if *outputFile == "" {
		fmt.Println(output)
	} else {
		err = os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			log.Error().Err(err).Str("file", *outputFile).Msg("Ошибка записи выходного файла")
			os.Exit(1)
		}
		log.Info().Str("file", *outputFile).Msg("Отчет записан в файл")
	}

	// Выход с ненулевым статусом, если найдены проблемы
	if len(results) > 0 {
		os.Exit(2)
	}
}
