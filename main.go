package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {

	port := 22

	key, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ip, _, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				ip = c.RemoteAddr().String()
			}
			log.Printf("[%s] \"honeypot connection attempt: ssh - %s - %s - %s\"\n", time.Now().Format("2006-01-02 15:04:05.000"), ip, c.User(), string(pass))
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	config.AddHostKey(key)

	// Listen on port 22
	listener, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", port, err)
	}
	log.Printf("Listening on port %d...", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %s", err)
			continue
		}

		go handleConn(conn, config)
	}
}

func generateKeyPair() (ssh.Signer, error) {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Encode the private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Parse the PEM encoded private key to get an ssh.Signer
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func handleConn(c net.Conn, config *ssh.ServerConfig) {
	ssh.NewServerConn(c, config)
}
