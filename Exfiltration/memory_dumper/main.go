package main

import (
	"fmt"
	"log"
	"os"
    "os/exec"
	"runtime"
	"strings"
	"syscall"
    "unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <INTERFACE>\n", os.Args[0])
        os.Exit(1)
    }

    if isBeingDebugged() || isRunningInVM() {
        fmt.Println("Debugger or VM detected. Exiting.")
        os.Exit(1)
    }

    iface := os.Args[1]
    handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        fmt.Println(packet)
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
