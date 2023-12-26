package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	path := os.Getenv("LOGPATH")
	if path == "" {
		path = "./data/ssh-honeypot.log"
	}

	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	w := bufio.NewWriter(logFile)

	port := os.Getenv("PORT")
	if port == "" {
		port = "22"
	}

	key, err := generateKeyPair()
	if err != nil {
		panic(err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ip, _, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				ip = c.RemoteAddr().String()
			}
			_, err = fmt.Fprintf(w, "[%s] \"honeypot login attempt: ssh - %s - %s - %s\"\n", time.Now().Format("2006-01-02 15:04:05.000"), ip, c.User(), string(pass))

			if err != nil {
				fmt.Printf("Error writing to log file: %v", err)
			}

			w.Flush()

			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	config.AddHostKey(key)

	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Listening on port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept incoming connection: %s", err)
			continue
		}

		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			ip = conn.RemoteAddr().String()
		}

		fmt.Fprintf(w, "[%s] \"honeypot connection: ssh - %s\"\n", time.Now().Format("2006-01-02 15:04:05.000"), ip)

		w.Flush()

		go handleConn(conn, config)
	}
}

func generateKeyPair() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func handleConn(c net.Conn, config *ssh.ServerConfig) {
	ssh.NewServerConn(c, config)
}
