package main

import (
	"database/sql"
	_ "fmt"
	"net/http"
	"os/exec"
)

func main() {
	// Небезопасная обработка SQL
	username := "user"
	db, _ := sql.Open("postgres", "postgres://user:password@localhost/db")
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	db.Query(query)

	// Жёстко закодированный ключ
	apiKey := "1234567890abcdefghijklmn"
	_ = apiKey
	// Небезопасный HTTP
	http.Get("http://example.com")

	// Потенциальная инъекция команды
	userInput := "ls -la"
	exec.Command("sh", "-c", userInput).Run()
}
