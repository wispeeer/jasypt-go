package main

import (
	"fmt"
	"log"
	"os"

	"github.com/wispeeer/jasypt-go"
)

const (
	prefix string = "ENC~"
	suffix string = ""
)

func main() {
	if len(os.Args) < 2 {
		log.Println("Usage <passwd> <secretKey>")
		return
	}
	passwd := os.Args[1]    // 需要加密的密码
	secretKey := os.Args[2] // 加密密钥，在解密是需要

	resolver := jasypt.New
	resolver.Prefix = prefix
	resolver.Suffix = suffix

	fmt.Println("password:", passwd)
	fmt.Println("secretKey:", secretKey)
	esr := resolver.Encrypt(passwd, secretKey)
	fmt.Println("output:", esr)
	dsr, err := resolver.Decrypt(esr, secretKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("valid:", string(dsr) == passwd)
}
