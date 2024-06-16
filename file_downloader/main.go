package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "net/http"
    "os"
)

var key = []byte("a very very very very secret key") // 32 bytes

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <URL> <DEST>\n", os.Args[0])
        os.Exit(1)
    }

    encryptedURL := os.Args[1]
    encryptedDest := os.Args[2]

    url, _ := decrypt(encryptedURL)
    dest, _ := decrypt(encryptedDest)

    err := downloadFile(url, dest)
    if err != nil {
        fmt.Println("Download error:", err)
    } else {
        fmt.Println("Download completed:", dest)
    }
}

func downloadFile(url, dest string) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    out, err := os.Create(dest)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, resp.Body)
    return err
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
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
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
