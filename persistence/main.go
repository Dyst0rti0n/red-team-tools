package main

import (
    "fmt"
    "os"
    "path/filepath"
    "runtime"

    "golang.org/x/sys/windows/registry"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <TARGET_PATH>\n", os.Args[0])
        os.Exit(1)
    }

    targetPath := os.Args[1]
    err := addToStartup(targetPath)
    if err != nil {
        fmt.Println("Error adding to startup:", err)
    } else {
        fmt.Println("Persistence established.")
    }
}

func addToStartup(targetPath string) error {
    if runtime.GOOS == "windows" {
        return addToStartupWindows(targetPath)
    } else if runtime.GOOS == "linux" {
        return addToStartupLinux(targetPath)
    }
    return fmt.Errorf("unsupported operating system")
}

func addToStartupWindows(targetPath string) error {
    key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
    if err != nil {
        return err
    }
    defer key.Close()

    exePath, err := os.Executable()
    if err != nil {
        return err
    }
    exePath, err = filepath.Abs(exePath)
    if err != nil {
        return err
    }

    return key.SetStringValue(filepath.Base(targetPath), exePath)
}

func addToStartupLinux(targetPath string) error {
    home, err := os.UserHomeDir()
    if err != nil {
        return err
    }
    autostartDir := filepath.Join(home, ".config", "autostart")
    os.MkdirAll(autostartDir, 0755)

    autostartFile := filepath.Join(autostartDir, filepath.Base(targetPath)+".desktop")
    content := fmt.Sprintf("[Desktop Entry]\nType=Application\nExec=%s\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\nName=%s\nComment=Startup script", targetPath, filepath.Base(targetPath))

    return os.WriteFile(autostartFile, []byte(content), 0644)
}
