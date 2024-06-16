package main

import (
    "fmt"
    "net"
    "os"
    "os/exec"
    "runtime"
)

func main() {
    fmt.Println("System Information")
    fmt.Println("==================")
    fmt.Printf("Operating System: %s\n", runtime.GOOS)
    fmt.Printf("Architecture: %s\n", runtime.GOARCH)
    fmt.Printf("CPUs: %d\n", runtime.NumCPU())

    hostname, err := os.Hostname()
    if err != nil {
        fmt.Printf("Error getting hostname: %v\n", err)
    } else {
        fmt.Printf("Hostname: %s\n", hostname)
    }

    user, err := os.UserHomeDir()
    if err != nil {
        fmt.Printf("Error getting user home directory: %v\n", err)
    } else {
        fmt.Printf("User Home Directory: %s\n", user)
    }

    ipAddresses, err := getIPAddresses()
    if err != nil {
        fmt.Printf("Error getting IP addresses: %v\n", err)
    } else {
        fmt.Println("IP Addresses:")
        for _, ip := range ipAddresses {
            fmt.Printf(" - %s\n", ip)
        }
    }

    fmt.Println("\nInstalled Programs")
    fmt.Println("==================")
    programs, err := getInstalledPrograms()
    if err != nil {
        fmt.Printf("Error getting installed programs: %v\n", err)
    } else {
        fmt.Println(programs)
    }

    fmt.Println("\nRunning Processes")
    fmt.Println("==================")
    processes, err := getRunningProcesses()
    if err != nil {
        fmt.Printf("Error getting running processes: %v\n", err)
    } else {
        fmt.Println(processes)
    }

    fmt.Println("\nNetwork Connections")
    fmt.Println("===================")
    connections, err := getNetworkConnections()
    if err != nil {
        fmt.Printf("Error getting network connections: %v\n", err)
    } else {
        fmt.Println(connections)
    }
}

func getIPAddresses() ([]string, error) {
    var ips []string
    interfaces, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    for _, i := range interfaces {
        addrs, err := i.Addrs()
        if err != nil {
            continue
        }
        for _, addr := range addrs {
            ips = append(ips, addr.String())
        }
    }
    return ips, nil
}

func getInstalledPrograms() (string, error) {
    if runtime.GOOS == "windows" {
        out, err := exec.Command("powershell", "Get-WmiObject -Class Win32_Product | Select-Object -Property Name").Output()
        return string(out), err
    }
    out, err := exec.Command("bash", "-c", "dpkg -l").Output()
    return string(out), err
}

func getRunningProcesses() (string, error) {
    out, err := exec.Command("ps", "aux").Output()
    return string(out), err
}

func getNetworkConnections() (string, error) {
    out, err := exec.Command("netstat", "-an").Output()
    return string(out), err
}
