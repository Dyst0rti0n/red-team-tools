package main

import (
    "fmt"
    "os"
    "path/filepath"

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

    return key.SetStringValue(targetPath, exePath)
}
