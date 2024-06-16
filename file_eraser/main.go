package main

import (
    "crypto/rand"
    "fmt"
    "os"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <FILE_PATH>\n", os.Args[0])
        os.Exit(1)
    }

    filePath := os.Args[1]
    err := securelyDelete(filePath)
    if err != nil {
        fmt.Println("Error securely deleting file:", err)
    } else {
        fmt.Println("File securely deleted.")
    }
}

func securelyDelete(filePath string) error {
    fileInfo, err := os.Stat(filePath)
    if err != nil {
        return err
    }

    file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
    if err != nil {
        return err
    }
    defer file.Close()

    fileSize := fileInfo.Size()
    randomData := make([]byte, fileSize)
    _, err = rand.Read(randomData)
    if err != nil {
        return err
    }

    _, err = file.WriteAt(randomData, 0)
    if err != nil {
        return err
    }

    err = file.Close()
    if err != nil {
        return err
    }

    return os.Remove(filePath)
}
