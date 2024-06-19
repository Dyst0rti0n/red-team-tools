package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"
)

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <DIRECTORY> <PASSWORD>\n", os.Args[0])
        os.Exit(1)
    }

    dir := os.Args[1]
    password := os.Args[2]

    key := make([]byte, 32)
    copy(key, password)

    err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        if !info.IsDir() {
            encryptFile(path, key)
        }

        return nil
    })
    if err != nil {
        fmt.Println("Error walking through directory:", err)
    } else {
        fmt.Println("Encryption completed.")
    }
}

func encryptFile(filePath string, key []byte) {
    plaintext, err := ioutil.ReadFile(filePath)
    if err != nil {
        fmt.Println("Error reading file:", err)
        return
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        fmt.Println("Error creating cipher:", err)
        return
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println("Error creating GCM:", err)
        return
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        fmt.Println("Error generating nonce:", err)
        return
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    err = ioutil.WriteFile(filePath, ciphertext, 0644)
    if err != nil {
        fmt.Println("Error writing encrypted file:", err)
        return
    }

    fmt.Printf("Encrypted: %s\n", filePath)
}
