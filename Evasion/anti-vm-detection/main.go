package main

import (
	"fmt"
	"os"
    "os/exec"
	"runtime"
	"strings"
)

func main() {
    if isRunningInVM() {
        fmt.Println("Virtual machine detected. Exiting.")
        os.Exit(1)
    } else {
        fmt.Println("No virtual machine detected.")
    }
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
