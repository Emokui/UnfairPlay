package main

import (
 "bufio"
 "fmt"
 "os"
 "strings"
 "golang.org/x/term"
)
func main() {
 fmt.Print("password: ")
 secret, err := term.ReadPassword(int(os.Stdin.Fd()))
 if err != nil || string(secret) != "synthetic-go-secret" { os.Exit(2) }
 fmt.Print("\nenter 2FA code: ")
 code, err := bufio.NewReader(os.Stdin).ReadString('\n')
 if err != nil || strings.TrimSpace(code) != "123456" { os.Exit(3) }
 fmt.Println("Go interactive password and verification accepted")
}
