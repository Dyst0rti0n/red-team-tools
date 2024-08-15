package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

type SystemInfo struct {
	OS              string   `json:"os"`
	Architecture    string   `json:"architecture"`
	CPUs            int      `json:"cpus"`
	Hostname        string   `json:"hostname"`
	User            string   `json:"user"`
	UserID          string   `json:"user_id"`
	GroupID         string   `json:"group_id"`
	HomeDir         string   `json:"home_dir"`
	EnvVariables    []string `json:"env_variables"`
	IPAddresses     []string `json:"ip_addresses"`
	RunningProcesses []ProcessInfo `json:"running_processes"`
	DiskUsage       []DiskUsage `json:"disk_usage"`
}

type ProcessInfo struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
}

type DiskUsage struct {
	Filesystem string `json:"filesystem"`
	Used       string `json:"used"`
	Available  string `json:"available"`
	MountPoint string `json:"mount_point"`
}

func main() {
	// Command-line flag for output file
	outputFile := flag.String("output", "", "File to save the system information as JSON")
	flag.Parse()

	systemInfo := gatherSystemInfo()
	output, err := json.MarshalIndent(systemInfo, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal system information: %v", err)
	}

	if *outputFile != "" {
		err = saveToFile(*outputFile, output)
		if err != nil {
			log.Fatalf("Failed to save to file: %v", err)
		}
		fmt.Printf("System information saved to %s\n", *outputFile)
	} else {
		fmt.Println(string(output))
	}
}

func saveToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func gatherSystemInfo() SystemInfo {
	return SystemInfo{
		OS:              runtime.GOOS,
		Architecture:    runtime.GOARCH,
		CPUs:            runtime.NumCPU(),
		Hostname:        getHostname(),
		User:            getCurrentUser().Username,
		UserID:          getCurrentUser().Uid,
		GroupID:         getCurrentUser().Gid,
		HomeDir:         getCurrentUser().HomeDir,
		EnvVariables:    getEnvVariables(),
		IPAddresses:     getIPAddresses(),
		RunningProcesses: getRunningProcesses(),
		DiskUsage:       getDiskUsage(),
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Error getting hostname: %v", err)
		return "Unknown"
	}
	return hostname
}

func getCurrentUser() *user.User {
	currentUser, err := user.Current()
	if err != nil {
		log.Printf("Error getting current user: %v", err)
		return &user.User{
			Username: "Unknown",
			Uid:      "Unknown",
			Gid:      "Unknown",
			HomeDir:  "Unknown",
		}
	}
	return currentUser
}

func getEnvVariables() []string {
	return os.Environ()
}

func getIPAddresses() []string {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error getting network interfaces: %v", err)
		return ips
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("Error getting IP addresses: %v", err)
			continue
		}
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
	}
	return ips
}

func getRunningProcesses() []ProcessInfo {
	var processes []ProcessInfo

	if runtime.GOOS == "windows" {
		output, err := exec.Command("cmd", "/C", "tasklist", "/FO", "CSV", "/NH").Output()
		if err != nil {
			log.Printf("Error getting running processes: %v", err)
			return processes
		}
		lines := strings.Split(string(output), "\r\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			fields := strings.Split(line, "\",\"")
			if len(fields) >= 2 {
				pid := strings.Trim(fields[1], "\"")
				name := strings.Trim(fields[0], "\"")
				processes = append(processes, ProcessInfo{
					PID:  pid,
					Name: name,
				})
			}
		}
	} else {
		output, err := exec.Command("ps", "-e", "-o", "pid,comm").Output()
		if err != nil {
			log.Printf("Error getting running processes: %v", err)
			return processes
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				processes = append(processes, ProcessInfo{
					PID:  fields[0],
					Name: fields[1],
				})
			}
		}
	}

	return processes
}

func getDiskUsage() []DiskUsage {
	var usage []DiskUsage
	var output []byte
	var err error

	if runtime.GOOS == "windows" {
		output, err = exec.Command("wmic", "logicaldisk", "get", "Caption,FreeSpace,Size").Output()
		if err != nil {
			log.Printf("Error getting disk usage: %v", err)
			return usage
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				filesystem := fields[0]
				freeSpace := fields[1]
				size := fields[2]
				used := fmt.Sprintf("%.2f GB", (parseDiskSize(size)-parseDiskSize(freeSpace))/(1024*1024*1024))
				available := fmt.Sprintf("%.2f GB", parseDiskSize(freeSpace)/(1024*1024*1024))
				usage = append(usage, DiskUsage{
					Filesystem: filesystem,
					Used:       used,
					Available:  available,
					MountPoint: filesystem,
				})
			}
		}
	} else {
		output, err = exec.Command("df", "-h").Output()
		if err != nil {
			log.Printf("Error getting disk usage: %v", err)
			return usage
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				usage = append(usage, DiskUsage{
					Filesystem: fields[0],
					Used:       fields[2],
					Available:  fields[3],
					MountPoint: fields[5],
				})
			}
		}
	}

	return usage
}

func parseDiskSize(size string) float64 {
	var sizeFloat float64
	_, err := fmt.Sscanf(size, "%f", &sizeFloat)
	if err != nil {
		log.Printf("Error parsing disk size: %v", err)
		return 0
	}
	return sizeFloat
}
