package main

import (
    "fmt"
    "image/png"
    "os"
    "path/filepath"
    "time"

    "github.com/kbinani/screenshot"
)

func main() {
    n := screenshot.NumActiveDisplays()
    if n <= 0 {
        fmt.Println("No active displays found")
        return
    }

    for i := 0; i < n; i++ {
        bounds := screenshot.GetDisplayBounds(i)

        img, err := screenshot.CaptureRect(bounds)
        if err != nil {
            fmt.Println("Screenshot error:", err)
            return
        }

        filename := fmt.Sprintf(".%s_%d.png", time.Now().Format("20060102_150405"), i)
        file, err := os.Create(filepath.Join(os.TempDir(), filename))
        if err != nil {
            fmt.Println("File creation error:", err)
            return
        }
        defer file.Close()

        err = png.Encode(file, img)
        if err != nil {
            fmt.Println("PNG encoding error:", err)
            return
        }

        fmt.Printf("Screenshot saved: %s\n", filepath.Join(os.TempDir(), filename))
    }
}
