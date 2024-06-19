package main

import (
    "crypto/aes"
    "crypto/cipher"
	"crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "net"
    "os"
    "bufio"
)

// Encryption key (must be 16, 24, or 32 bytes long)
var key = []byte("myverystrongpasswordo32bitlength")

func main() {
    ln, err := net.Listen("tcp", ":8000")
    if err != nil {
        logMessage("Error setting up listener: " + err.Error())
        return
    }
    defer ln.Close()

    logMessage("Listening on :8000...")
    conn, err := ln.Accept()
    if err != nil {
        logMessage("Error accepting connection: " + err.Error())
        return
    }
    defer conn.Close()

    logMessage("Connection established")

    go func() {
        for {
            buf := make([]byte, 1024)
            n, err := conn.Read(buf)
            if err != nil {
                logMessage("Error reading: " + err.Error())
                return
            }

            decrypted, err := decrypt(string(buf[:n]))
            if err != nil {
                logMessage("Error decrypting: " + err.Error())
                return
            }

            logMessage("Received: " + decrypted)
        }
    }()

    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        command := scanner.Text()
        encrypted, err := encrypt(command)
        if err != nil {
            logMessage("Error encrypting: " + err.Error())
            continue
        }

        conn.Write([]byte(encrypted + "\n"))
    }

    if err := scanner.Err(); err != nil {
        logMessage("Error reading from stdin: " + err.Error())
    }
}

func encrypt(text string) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(text string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(text)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

func logMessage(message string) {
    fmt.Println("[Listener] " + message)
}
