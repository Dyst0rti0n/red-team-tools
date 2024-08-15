package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/viper"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ScanResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	OS      string `json:"os,omitempty"`
}

type BannerPattern struct {
	Regex   string `json:"regex"`
	Service string `json:"service"`
	Version string `json:"version"`
}

var (
	ipRange        string
	portRange      string
	threads        int
	scanType       string
	config         string
	results        []ScanResult
	resultsMutex   sync.Mutex
	bannerDB       []BannerPattern
	cpuProfile     string
	memProfile     string
	profileDuration time.Duration
	totalScans     int
	progressBar    *progressbar.ProgressBar
	ctx            context.Context
	cancel         context.CancelFunc
)

func init() {
	flag.StringVar(&ipRange, "ip", getLocalCIDR(), "IP range to scan")
	flag.StringVar(&portRange, "p", "1-1000", "Port range to scan (e.g., 20-80)")
	flag.IntVar(&threads, "t", runtime.NumCPU()*10, "Number of threads")
	flag.StringVar(&scanType, "scan", "syn", "Scan type (syn, ack, udp, stealth, http, https)")
	flag.StringVar(&config, "config", "", "Path to configuration file")
	flag.StringVar(&cpuProfile, "cpuprofile", "", "Write CPU profile to file")
	flag.StringVar(&memProfile, "memprofile", "", "Write memory profile to file")
	flag.DurationVar(&profileDuration, "profileduration", 30*time.Second, "Duration for CPU and memory profiling")
}

func main() {
	flag.Parse()
	setupGracefulShutdown()

	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
		go func() {
			time.Sleep(profileDuration)
			pprof.StopCPUProfile()
			fmt.Println("CPU profiling completed")
		}()
	}

	if config != "" {
		loadConfig(config)
	}

	if err := loadBannerDB("banner_patterns.json"); err != nil {
		log.Fatalf("Error loading banner database: %v", err)
	}

	ipList, err := expandIPRange(ipRange)
	if err != nil {
		fmt.Println("Invalid IP range:", err)
		os.Exit(1)
	}

	portList, err := expandPortRange(portRange)
	if err != nil {
		fmt.Println("Invalid port range:", err)
		os.Exit(1)
	}

	totalScans = len(ipList) * len(portList)
	progressBar = progressbar.NewOptions(totalScans,
		progressbar.OptionSetDescription("[cyan]Scanning..."),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetWidth(15),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionFullWidth(),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetRenderBlankState(true),
	)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)
	resultChan := make(chan ScanResult, totalScans)

	go func() {
		for result := range resultChan {
			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()
		}
	}()

	for _, ip := range ipList {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			for _, port := range portList {
				semaphore <- struct{}{}
				go func(ip string, port int) {
					defer func() { <-semaphore }()
					scanPort(ip, port, scanType, resultChan)
					progressBar.Add(1)
				}(ip, port)
			}
		}(ip)
	}

	wg.Wait()
	close(resultChan)
	saveCSVResults()

	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
		fmt.Println("Memory profiling completed")
	}
}

func setupGracefulShutdown() {
	ctx, cancel = context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, shutting down gracefully...")
		cancel()
	}()
}

func getLocalCIDR() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("Failed to get local network interfaces: %v", err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.String()
		}
	}
	return "192.168.1.0/24"
}

func loadConfig(path string) {
	viper.SetConfigFile(path)
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	ipRange = viper.GetString("ip")
	portRange = viper.GetString("port")
	threads = viper.GetInt("threads")
	scanType = viper.GetString("scan")
}

func loadBannerDB(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &bannerDB)
}

func expandIPRange(ipRange string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func expandPortRange(portRange string) ([]int, error) {
	ports := strings.Split(portRange, "-")
	if len(ports) != 2 {
		return nil, fmt.Errorf("invalid port range")
	}
	startPort, err := strconv.Atoi(ports[0])
	if err != nil {
		return nil, err
	}
	endPort, err := strconv.Atoi(ports[1])
	if err != nil {
		return nil, err
	}
	var portList []int
	for i := startPort; i <= endPort; i++ {
		portList = append(portList, i)
	}
	return portList, nil
}

func scanPort(ip string, port int, scanType string, resultChan chan<- ScanResult) {
	select {
	case <-ctx.Done():
		return
	default:
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			service, version, banner, os := detectServiceAndOS(ip, port, conn)
			conn.Close()
			result := ScanResult{IP: ip, Port: port, Service: service, Version: version, Banner: banner, OS: os}
			resultChan <- result
			fmt.Printf("[+] %s:%d open (Service: %s, Version: %s, Banner: %s, OS: %s)\n", ip, port, service, version, banner, os)
		}
	}
}

func detectServiceAndOS(ip string, port int, conn net.Conn) (string, string, string, string) {
	banner := grabBanner(conn)
	service, version := analyzeBanner(banner)
	os := advancedOSFingerprinting(ip, port, banner)
	return service, version, banner, os
}

func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	reader := bufio.NewReader(conn)
	var banner strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		banner.WriteString(line)
		if len(banner.String()) > 1024 { // limit banner length
			break
		}
	}
	return strings.TrimSpace(banner.String())
}

func analyzeBanner(banner string) (string, string) {
	for _, pattern := range bannerDB {
		re := regexp.MustCompile(pattern.Regex)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 0 {
			return pattern.Service, matches[1]
		}
	}
	return "unknown", "unknown"
}

func advancedOSFingerprinting(ip string, port int, banner string) string {
	service, _ := analyzeBanner(banner)
	timingOS := performTimingAnalysis(ip, port)

	probeTypes := []string{"SYN", "ACK", "FIN", "XMAS", "NULL", "ICMP", "HTTP"}
	var responses []string
	for _, probe := range probeTypes {
		response := sendProbe(ip, port, probe)
		responses = append(responses, analyzeProbeResponse(response))
	}

	osCandidates := map[string]int{}
	if service != "unknown" {
		osCandidates[service]++
	}
	if timingOS != "unknown" {
		osCandidates[timingOS]++
	}
	for _, os := range responses {
		if os != "unknown" {
			osCandidates[os]++
		}
	}

	var finalOS string
	var maxScore int
	for os, score := range osCandidates {
		if score > maxScore {
			finalOS = os
			maxScore = score
		}
	}

	if finalOS == "" {
		return "unknown"
	}

	return finalOS
}

func performTimingAnalysis(ip string, port int) string {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 200*time.Millisecond)
	duration := time.Since(start)

	if err != nil {
		return "unknown"
	}

	conn.Close()

	if duration < 50*time.Millisecond {
		return "Linux"
	} else if duration < 100*time.Millisecond {
		return "Windows"
	} else if duration < 200*time.Millisecond {
		return "BSD"
	}

	return "unknown"
}

func sendProbe(ip string, port int, probeType string) string {
	handle, err := pcap.OpenLive("eth0", 1600, false, pcap.BlockForever)
	if err != nil {
		return ""
	}
	defer handle.Close()

	var packet gopacket.Packet
	switch probeType {
	case "SYN":
		packet = createSYNPacket(ip, port)
	case "ACK":
		packet = createACKPacket(ip, port)
	case "FIN":
		packet = createFINPacket(ip, port)
	case "XMAS":
		packet = createXMASPacket(ip, port)
	case "NULL":
		packet = createNULLPacket(ip, port)
	case "ICMP":
		packet = createICMPPacket(ip)
	case "HTTP":
		packet = createHTTPPacket(ip)
	default:
		return ""
	}

	err = handle.WritePacketData(packet.Data())
	if err != nil {
		return ""
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		return packet.String()
	}

	return ""
}

func createSYNPacket(ip string, port int) gopacket.Packet {
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0c, 0x29, 0x6d, 0x89, 0x9a},
		DstMAC:       net.HardwareAddr{0x00, 0x50, 0x56, 0xe0, 0xc5, 0x11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ethLayer, ipLayer, tcpLayer)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createACKPacket(ip string, port int) gopacket.Packet {
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		ACK:     true,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func createFINPacket(ip string, port int) gopacket.Packet {
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		FIN:     true,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func createXMASPacket(ip string, port int) gopacket.Packet {
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		FIN:     true,
		PSH:     true,
		URG:     true,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func createNULLPacket(ip string, port int) gopacket.Packet {
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer)
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func createICMPPacket(ip string) gopacket.Packet {
	icmpLayer := &icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 1234, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	icmpData, _ := icmpLayer.Marshal(nil)
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(icmpData))
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func createHTTPPacket(ip string) gopacket.Packet {
	httpRequest := "GET / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n"
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer, gopacket.Payload([]byte(httpRequest)))
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func analyzeProbeResponse(response string) string {
	probeResponseDatabase := map[string]string{
		"SYN-ACK":                       "Linux",
		"RST":                           "Windows",
		"FIN-ACK":                       "BSD",
		"XMAS response":                 "Linux",
		"NULL response":                 "BSD",
		"ICMP time-exceeded":            "Linux",
		"ICMP destination-unreachable":  "Windows",
		"HTTP/1.1 200 OK":               "Windows",
		"HTTP/1.1 404 Not Found":        "Linux",
	}

	for key, os := range probeResponseDatabase {
		if strings.Contains(response, key) {
			return os
		}
	}

	return "unknown"
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func saveCSVResults() {
	file, err := os.Create("scan_results.csv")
	if err != nil {
		log.Fatalf("Error creating CSV results file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"IP", "Port", "Service", "Version", "Banner", "OS"})
	for _, result := range results {
		writer.Write([]string{result.IP, strconv.Itoa(result.Port), result.Service, result.Version, result.Banner, result.OS})
	}

	fmt.Println("Scan results saved to scan_results.csv")
}
