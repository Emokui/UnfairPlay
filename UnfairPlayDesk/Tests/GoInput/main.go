package main

import (
	"bufio"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--desk-session-fd" && os.Args[2] == "3" {
		socket := os.NewFile(3, "synthetic-session")
		// An unsupported opcode exercises the actual channel without touching Keychain.
		if _, err := socket.Write([]byte{'?'}); err != nil {
			os.Exit(5)
		}
		reply, err := io.ReadAll(socket)
		socket.Close()
		if err != nil || len(reply) < 2 || reply[0] != 1 {
			os.Exit(6)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "--ambiguous" {
		fmt.Fprint(os.Stderr, "Apple could not confirm sign-in. If you received a code, enter it or leave blank: ")
		code, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			os.Exit(2)
		}
		if strings.TrimSpace(code) == "" {
			fmt.Println(`{"error":"failed to read auth code: apple did not confirm sign-in; check your password or use a verification code if you received one","level":"error"}`)
			os.Exit(1)
		}
		os.Exit(4)
	}
	fmt.Print("password: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil || string(secret) != "synthetic-go-secret" {
		os.Exit(2)
	}
	fmt.Print("\nenter 2FA code: ")
	code, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(code) != "123456" {
		os.Exit(3)
	}
	fmt.Println("Go interactive password and verification accepted")
}
