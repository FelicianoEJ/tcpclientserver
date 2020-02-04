package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:7777")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("Connection established...")

	
	for {
		msg, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Println([]byte(msg))
		emsg := encrypt([]byte(msg), "S3Cr3t0")
		fmt.Fprintf(conn, "%s\n", emsg)
		//conn.Write([]byte(emsg))
	}
	//fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
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

func decrypt2String(data []byte, passphrase string) string {
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