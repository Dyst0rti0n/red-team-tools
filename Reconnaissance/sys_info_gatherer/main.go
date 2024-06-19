package main

import (
    "fmt"
    "os"
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
}
