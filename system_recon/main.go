package main

import (
    "fmt"
    "net"
    "os"
    "os/exec"
    "runtime"
)

func main() {
    fmt.Println("Operating System:", runtime.GOOS)
    fmt.Println("Architecture:", runtime.GOARCH)
    fmt.Println("CPUs:", runtime.NumCPU())

    hostname, err := os.Hostname()
    if err != nil {
        fmt.Println("Error getting hostname:", err)
    } else {
        fmt.Println("Hostname:", hostname)
    }

    user, err := os.UserHomeDir()
    if err != nil {
        fmt.Println("Error getting user home directory:", err)
    } else {
        fmt.Println("User Home Directory:", user)
    }

    ipAddresses, err := getIPAddresses()
    if err != nil {
        fmt.Println("Error getting IP addresses:", err)
    } else {
        fmt.Println("IP Addresses:", ipAddresses)
    }

    fmt.Println("Installed Programs:")
    programs, err := getInstalledPrograms()
    if err != nil {
        fmt.Println("Error getting installed programs:", err)
    } else {
        fmt.Println(programs)
    }

    fmt.Println("Running Processes:")
    processes, err := getRunningProcesses()
    if err != nil {
        fmt.Println("Error getting running processes:", err)
    } else {
        fmt.Println(processes)
    }

    fmt.Println("Network Connections:")
    connections, err := getNetworkConnections()
    if err != nil {
        fmt.Println("Error getting network connections:", err)
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
            ip := addr.String()
            ips = append(ips, ip)
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
