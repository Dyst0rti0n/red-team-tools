package main

import (
    "fmt"
    "os"
    "os/exec"
    "runtime"
    "strings"
    "syscall"
    "unsafe"
    "github.com/atotto/clipboard"
)

func main() {
    if isBeingDebugged() || isRunningInVM() {
        fmt.Println("Debugger or VM detected. Exiting.")
        os.Exit(1)
    }

    content, err := clipboard.ReadAll()
    if err != nil {
        fmt.Println("Clipboard error:", err)
        return
    }

    obfuscatedContent := obfuscate(content)
    fmt.Println("Obfuscated Clipboard content:", obfuscatedContent)
    decryptedContent := deobfuscate(obfuscatedContent)
    fmt.Println("Decrypted Clipboard content:", decryptedContent)
}

func obfuscate(text string) string {
    runes := []rune(text)
    for i := 0; i < len(runes); i++ {
        runes[i] += 3
    }
    return string(runes)
}

func deobfuscate(text string) string {
    runes := []rune(text)
    for i := 0; i < len(runes); i++ {
        runes[i] -= 3
    }
    return string(runes)
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
