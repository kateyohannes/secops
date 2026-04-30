package main

import (
	"fmt"
	"os/exec"
)

var userInput = "test"

// Hardcoded credentials - G101
var adminPassword = "SuperSecret123!"

func main() {
	// SQL injection vulnerability - G201
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)

	// Command execution with user input - G204
	exec.Command("ls", userInput).Run()

	fmt.Println("Query:", query)
	fmt.Println("Done")
}
