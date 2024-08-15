Here's a simple `README.md` for your `sys_info_gatherer` tool:

```markdown
# Sys Info Gatherer

## Overview

The `Sys Info Gatherer` is a cross-platform tool written in Go that collects detailed system information such as OS details, architecture, CPU info, environment variables, IP addresses, running processes, and disk usage. It outputs this information in JSON format and can optionally save it to a file.

## Usage

### Running the Tool

To run the tool and print the system information to the console:

```bash
go run main.go
```

### Saving the Output to a File

You can save the JSON output to a file using the `-output` flag:

```bash
go run main.go -output system_info.json
```

This will create (or overwrite) the file `system_info.json` in the current directory with the gathered system information.

## Features

- Cross-platform compatibility (Windows, Linux, macOS)
- Collects:
  - OS and architecture information
  - CPU details
  - Hostname
  - Current user information
  - Environment variables
  - IP addresses
  - Running processes
  - Disk usage
- Outputs data in JSON format
- Optional file-saving feature

## Requirements

- Go 1.22.6 or later
