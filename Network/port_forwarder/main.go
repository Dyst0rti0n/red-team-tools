package main

import (
    "fmt"
    "io"
    "net"
    "os"
)

func main() {
    if len(os.Args) != 4 {
        fmt.Printf("Usage: %s <LOCAL_PORT> <REMOTE_HOST> <REMOTE_PORT>\n", os.Args[0])
        os.Exit(1)
    }

    localPort := os.Args[1]
    remoteHost := os.Args[2]
    remotePort := os.Args[3]

    listener, err := net.Listen("tcp", ":"+localPort)
    if err != nil {
        fmt.Println("Error starting local listener:", err)
        os.Exit(1)
    }
    defer listener.Close()

    fmt.Printf("Forwarding traffic from local port %s to %s:%s\n", localPort, remoteHost, remotePort)

    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Println("Error accepting connection:", err)
            continue
        }

        go handleConnection(conn, remoteHost, remotePort)
    }
}

func handleConnection(localConn net.Conn, remoteHost, remotePort string) {
    remoteConn, err := net.Dial("tcp", remoteHost+":"+remotePort)
    if err != nil {
        fmt.Println("Error connecting to remote host:", err)
        localConn.Close()
        return
    }

    go io.Copy(remoteConn, localConn)
    go io.Copy(localConn, remoteConn)
}
