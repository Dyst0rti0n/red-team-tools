package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(12)

	go func() {
		defer wg.Done()
		printBasicSystemInfo()
	}()

	go func() {
		defer wg.Done()
		printHostnameAndUser()
	}()

	go func() {
		defer wg.Done()
		printIPAddresses()
	}()

	go func() {
		defer wg.Done()
		printInstalledPrograms()
	}()

	go func() {
		defer wg.Done()
		printRunningProcesses()
	}()

	go func() {
		defer wg.Done()
		printNetworkConnections()
	}()

	go func() {
		defer wg.Done()
		printDiskUsage()
	}()

	go func() {
		defer wg.Done()
		printMemoryUsage()
	}()

	go func() {
		defer wg.Done()
		printEnvironmentVariables()
	}()

	go func() {
		defer wg.Done()
		printNetworkInterfaces()
	}()

	go func() {
		defer wg.Done()
		printActiveUsers()
	}()

	go func() {
		defer wg.Done()
		printSystemUptime()
	}()

	wg.Wait()
}

func printBasicSystemInfo() {
	fmt.Println("Operating System:", runtime.GOOS)
	fmt.Println("Architecture:", runtime.GOARCH)
	fmt.Println("CPUs:", runtime.NumCPU())
}

func printHostnameAndUser() {
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
}

func printIPAddresses() {
	ipAddresses, err := getIPAddresses()
	if err != nil {
		fmt.Println("Error getting IP addresses:", err)
	} else {
		fmt.Println("IP Addresses:")
		for _, ip := range ipAddresses {
			fmt.Println("  -", ip)
		}
	}
}

func printInstalledPrograms() {
	fmt.Println("Installed Programs:")
	programs, err := getInstalledPrograms()
	if err != nil {
		fmt.Println("Error getting installed programs:", err)
	} else {
		fmt.Println(programs)
	}
}

func printRunningProcesses() {
	fmt.Println("Running Processes:")
	processes, err := getRunningProcesses()
	if err != nil {
		fmt.Println("Error getting running processes:", err)
	} else {
		fmt.Println(processes)
	}
}

func printNetworkConnections() {
	fmt.Println("Network Connections:")
	connections, err := getNetworkConnections()
	if err != nil {
		fmt.Println("Error getting network connections:", err)
	} else {
		fmt.Println(connections)
	}
}

func printDiskUsage() {
	fmt.Println("Disk Usage:")
	usage, err := getDiskUsage()
	if err != nil {
		fmt.Println("Error getting disk usage:", err)
	} else {
		fmt.Println(usage)
	}
}

func printMemoryUsage() {
	fmt.Println("Memory Usage:")
	memory, err := getMemoryUsage()
	if err != nil {
		fmt.Println("Error getting memory usage:", err)
	} else {
		fmt.Println(memory)
	}
}

func printEnvironmentVariables() {
	fmt.Println("Environment Variables:")
	for _, env := range os.Environ() {
		fmt.Println("  -", env)
	}
}

func printNetworkInterfaces() {
	fmt.Println("Network Interfaces:")
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		fmt.Println("Error getting network interfaces:", err)
	} else {
		fmt.Println(interfaces)
	}
}

func printActiveUsers() {
	fmt.Println("Active Users:")
	users, err := getActiveUsers()
	if err != nil {
		fmt.Println("Error getting active users:", err)
	} else {
		fmt.Println(users)
	}
}

func printSystemUptime() {
	fmt.Println("System Uptime:")
	uptime, err := getSystemUptime()
	if err != nil {
		fmt.Println("Error getting system uptime:", err)
	} else {
		fmt.Println(uptime)
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
			ip := strings.Split(addr.String(), "/")[0]
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
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("tasklist").Output()
		return string(out), err
	default:
		out, err := exec.Command("ps", "aux").Output()
		return string(out), err
	}
}

func getNetworkConnections() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("netstat", "-an").Output()
		return string(out), err
	default:
		out, err := exec.Command("netstat", "-tuln").Output()
		return string(out), err
	}
}

func getDiskUsage() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "Get-PSDrive -PSProvider FileSystem | Select-Object -Property Name,Used,Free").Output()
		return string(out), err
	default:
		out, err := exec.Command("df", "-h").Output()
		return string(out), err
	}
}

func getMemoryUsage() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "Get-ComputerInfo | Select-Object -Property TotalPhysicalMemory,AvailablePhysicalMemory").Output()
		return string(out), err
	default:
		out, err := exec.Command("free", "-h").Output()
		return string(out), err
	}
}

func getNetworkInterfaces() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "Get-NetAdapter | Select-Object -Property Name,Status,MacAddress,LinkSpeed").Output()
		return string(out), err
	default:
		out, err := exec.Command("ifconfig").Output()
		return string(out), err
	}
}

func getActiveUsers() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("query", "user").Output()
		return string(out), err
	default:
		out, err := exec.Command("who").Output()
		return string(out), err
	}
}

func getSystemUptime() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "Get-Uptime").Output()
		return string(out), err
	default:
		out, err := exec.Command("uptime", "-p").Output()
		return string(out), err
	}
}
