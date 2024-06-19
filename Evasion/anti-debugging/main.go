package main

import (
    "fmt"
    "os"
    "syscall"
    "unsafe"
)

const (
    PROCESS_DEBUG_PORT = 0x7
)

func main() {
    if isBeingDebugged() {
        fmt.Println("Debugger detected. Exiting.")
        os.Exit(1)
    } else {
        fmt.Println("No debugger detected.")
    }
}

func isBeingDebugged() bool {
    var debugPort uintptr
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

    currentProcess, err := syscall.GetCurrentProcess()
    if err != nil {
        return false
    }

    r, _, _ := ntQueryInformationProcess.Call(
        uintptr(currentProcess),
        PROCESS_DEBUG_PORT,
        uintptr(unsafe.Pointer(&debugPort)),
        unsafe.Sizeof(debugPort),
        0,
    )

    return r == 0 && debugPort != 0
}
