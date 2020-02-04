package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

func main() {
	ln, _ := net.Listen("tcp", ":7777")
	defer ln.Close()
	fmt.Println("Serving at:", ln.Addr().String())
	for {
		conn, err := ln.Accept() // Waits for incoming connection
		if err != nil {
			fmt.Println(err)
			return
		}
		defer conn.Close()
		go handleConnection(conn)
	}
}

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
	for {
		emsg, err := bufio.NewReader(c).ReadString('\n') //Reads until enter
		emsg = strings.TrimSuffix(emsg, "\n")
		msg := decrypt([]byte(emsg), "S3Cr3t0")
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Print(msg)
	}
}

func createHash(passphrase string) (hash string) {
	hasher := md5.New()
	hasher.Write([]byte(passphrase))
	hash = hex.EncodeToString(hasher.Sum(nil))
	return 
}

func encrypt(data []byte, passphrase string) string {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return string(ciphertext)
}

func decrypt(data []byte, passphrase string) string {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return string(plaintext)
}