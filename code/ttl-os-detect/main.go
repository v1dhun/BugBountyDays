package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Config holds the application configuration
type Config struct {
	Timeout        time.Duration
	MaxConcurrency int
	OutputFile     string
	BufferSize     int
}

// ScanResult stores JSON output for each scanned IP
type ScanResult struct {
	IP       string    `json:"ip"`
	Domain   string    `json:"domain,omitempty"`
	TTL      int       `json:"ttl,omitempty"`
	OS       string    `json:"os,omitempty"`
	Success  bool      `json:"success"`
	ErrorMsg string    `json:"error,omitempty"`
	ScanTime time.Time `json:"scan_time"`
	Hostname string    `json:"hostname,omitempty"`
	RTTms    float64   `json:"rtt_ms,omitempty"`
}

// OSDetector provides an interface for OS detection strategies
type OSDetector interface {
	DetectOS(ttl int) string
}

// DefaultOSDetector implements standard OS detection logic
type DefaultOSDetector struct{}

// DetectOS determines OS based on TTL value
func (d *DefaultOSDetector) DetectOS(ttl int) string {
	switch {
	case ttl >= 128 && ttl < 129:
		return "Windows"
	case ttl >= 64 && ttl < 65:
		return "Linux/Unix"
	case ttl >= 255:
		return "Cisco/Network Device"
	default:
		return "Unknown OS"
	}
}

// IPScanner handles IP scanning operations
type IPScanner struct {
	config     *Config
	osDetector OSDetector
	logger     *log.Logger
}

// NewIPScanner creates a new IPScanner with given configuration
func NewIPScanner(config *Config) *IPScanner {
	return &IPScanner{
		config:     config,
		osDetector: &DefaultOSDetector{},
		logger:     log.New(os.Stdout, "IPScanner: ", log.Ldate|log.Ltime),
	}
}

// sendICMPEcho sends an ICMP Echo Request and returns TTL and other details
func (s *IPScanner) sendICMPEcho(target string, originalInput string) (ScanResult, error) {
	start := time.Now()
	var proto string
	ip := net.ParseIP(target)

	if ip == nil {
		return ScanResult{}, fmt.Errorf("invalid IP address: %s", target)
	}

	if ip.To4() != nil {
		proto = "ip4:icmp"
	} else {
		proto = "ip6:ipv6-icmp"
	}

	conn, err := net.DialTimeout(proto, target, s.config.Timeout)
	if err != nil {
		return ScanResult{}, err
	}
	defer conn.Close()

	// Create ICMP message
	msg := icmp.Message{
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("Ping"),
		},
	}

	// Set ICMP type
	if proto == "ip4:icmp" {
		msg.Type = ipv4.ICMPTypeEcho
	} else {
		msg.Type = ipv6.ICMPTypeEchoRequest
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return ScanResult{}, err
	}

	// Send ICMP Echo Request
	if _, err = conn.Write(msgBytes); err != nil {
		return ScanResult{}, err
	}

	// Read ICMP Echo Reply
	reply := make([]byte, 512)
	if err := conn.SetReadDeadline(time.Now().Add(s.config.Timeout)); err != nil {
		return ScanResult{}, err
	}

	n, err := conn.Read(reply)
	if err != nil {
		return ScanResult{}, err
	}

	// Extract TTL
	if n < 9 {
		return ScanResult{}, fmt.Errorf("invalid ICMP response")
	}
	ttl := int(reply[8])
	rtt := time.Since(start)

	// Resolve hostname if possible
	hostnames, err := net.LookupAddr(target)
	hostname := ""
	if err == nil && len(hostnames) > 0 {
		hostname = hostnames[0]
	}

	// Determine if original input was domain
	domain := ""
	if originalInput != target {
		domain = originalInput
	}

	return ScanResult{
		IP:       target,
		Domain:   domain,
		TTL:      ttl,
		OS:       s.osDetector.DetectOS(ttl),
		Success:  true,
		ScanTime: time.Now(),
		Hostname: hostname,
		RTTms:    float64(rtt.Milliseconds()),
	}, nil
}

// streamScanner processes targets and writes results to the output
func (s *IPScanner) streamScanner(targetChan <-chan targetInfo, wg *sync.WaitGroup, resultsChan chan<- ScanResult) {
	defer wg.Done()

	for target := range targetChan {
		result, err := s.sendICMPEcho(target.IP, target.Original)
		if err != nil {
			result = ScanResult{
				IP:       target.IP,
				Domain:   target.Original,
				Success:  false,
				ErrorMsg: err.Error(),
				ScanTime: time.Now(),
			}
		}
		resultsChan <- result
	}
}

// ResultWriter handles writing scan results to output
type ResultWriter struct {
	writer      *bufio.Writer
	file        *os.File
	isFirstItem bool
	mu          sync.Mutex
}

// NewResultWriter creates a new result writer
func NewResultWriter(outputPath string) (*ResultWriter, error) {
	var file *os.File
	var err error

	if outputPath == "" {
		file = os.Stdout
	} else {
		file, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}
	}

	writer := bufio.NewWriterSize(file, 64*1024) // 64KB buffer

	if outputPath != "" {
		if _, err := writer.WriteString("[\n"); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to write opening bracket: %v", err)
		}
		if err := writer.Flush(); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to flush writer: %v", err)
		}
	}

	return &ResultWriter{
		writer:      writer,
		file:        file,
		isFirstItem: true,
	}, nil
}

// WriteResult writes a scan result to the output
func (rw *ResultWriter) WriteResult(result ScanResult) error {
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("error marshaling result: %v", err)
	}

	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.file != os.Stdout {
		if !rw.isFirstItem {
			if _, err := rw.writer.WriteString(",\n"); err != nil {
				return err
			}
		}
		rw.isFirstItem = false
	}

	if rw.file == os.Stdout {
		if _, err := rw.writer.Write(jsonBytes); err != nil {
			return err
		}
		if _, err := rw.writer.WriteString("\n"); err != nil {
			return err
		}
	} else {
		if _, err := rw.writer.Write(jsonBytes); err != nil {
			return err
		}
	}

	return rw.writer.Flush()
}

// Close finalizes and closes the output
func (rw *ResultWriter) Close() error {
	if rw.file != os.Stdout {
		if _, err := rw.writer.WriteString("\n]"); err != nil {
			return err
		}
		if err := rw.writer.Flush(); err != nil {
			return err
		}
		return rw.file.Close()
	}
	return nil
}

// targetInfo stores a target IP and its original input
type targetInfo struct {
	IP       string
	Original string
}

// processArgs processes command line arguments and files
func (s *IPScanner) processArgs(args []string, targetChan chan<- targetInfo) error {
	for _, arg := range args {
		// CIDR subnet handling
		if _, _, err := net.ParseCIDR(arg); err == nil {
			if err := s.processSubnet(arg, targetChan); err != nil {
				s.logger.Printf("Error processing subnet %s: %v", arg, err)
			}
			continue
		}

		// File handling
		if stat, err := os.Stat(arg); err == nil && !stat.IsDir() {
			if err := s.processFile(arg, targetChan); err != nil {
				s.logger.Printf("Error processing file %s: %v", arg, err)
			}
			continue
		}

		// Domain handling
		if isDomain(arg) {
			ip, err := s.resolveDomain(arg)
			if err != nil {
				s.logger.Printf("Error resolving domain %s: %v", arg, err)
				continue
			}
			targetChan <- targetInfo{IP: ip, Original: arg}
			continue
		}

		// IP handling
		if net.ParseIP(arg) != nil {
			targetChan <- targetInfo{IP: arg, Original: arg}
			continue
		}

		s.logger.Printf("Skipping invalid target: %s", arg)
	}

	return nil
}

// processFile streams a file of targets line by line
func (s *IPScanner) processFile(filename string, targetChan chan<- targetInfo) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, s.config.BufferSize)
	scanner.Buffer(buf, s.config.BufferSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if isDomain(line) {
			ip, err := s.resolveDomain(line)
			if err != nil {
				s.logger.Printf("Error resolving domain %s: %v", line, err)
				continue
			}
			targetChan <- targetInfo{IP: ip, Original: line}
		} else if net.ParseIP(line) != nil {
			targetChan <- targetInfo{IP: line, Original: line}
		} else if _, _, err := net.ParseCIDR(line); err == nil {
			if err := s.processSubnet(line, targetChan); err != nil {
				s.logger.Printf("Error processing subnet %s: %v", line, err)
			}
		} else {
			s.logger.Printf("Skipping invalid target in file: %s", line)
		}
	}

	return scanner.Err()
}

// processSubnet processes a CIDR subnet
func (s *IPScanner) processSubnet(cidr string, targetChan chan<- targetInfo) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	// Make a copy of the IP to avoid modifying the original
	for ip := copyIP(ip.Mask(ipNet.Mask)); ipNet.Contains(ip); inc(ip) {
		ipStr := ip.String()
		targetChan <- targetInfo{IP: ipStr, Original: ipStr}
	}

	return nil
}

// copyIP creates a copy of an IP address
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isDomain checks if a string is likely a domain name
func isDomain(s string) bool {
	return strings.Contains(s, ".") && net.ParseIP(s) == nil && !strings.Contains(s, "/")
}

// resolveDomain converts a domain to an IP address
func (s *IPScanner) resolveDomain(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", domain)
	}

	// Prefer IPv4 addresses
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// Fall back to first IP of any type
	return ips[0].String(), nil
}

// Run executes the scanning process
func (s *IPScanner) Run(args []string) error {
	// Set up channels
	targetChan := make(chan targetInfo, 1000)
	resultsChan := make(chan ScanResult, 1000)

	// Create result writer
	resultWriter, err := NewResultWriter(s.config.OutputFile)
	if err != nil {
		return err
	}
	defer resultWriter.Close()

	// Start worker goroutines
	var scanWg sync.WaitGroup
	for i := 0; i < s.config.MaxConcurrency; i++ {
		scanWg.Add(1)
		go s.streamScanner(targetChan, &scanWg, resultsChan)
	}

	// Process results in separate goroutine
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for result := range resultsChan {
			if err := resultWriter.WriteResult(result); err != nil {
				s.logger.Printf("Error writing result: %v", err)
			}
		}
	}()

	// Process arguments
	if err := s.processArgs(args, targetChan); err != nil {
		return err
	}

	// Close channels and wait for completion
	close(targetChan)
	scanWg.Wait()
	close(resultsChan)
	resultsWg.Wait()

	return nil
}

func main() {
	config := &Config{}

	flag.DurationVar(&config.Timeout, "timeout", 2*time.Second, "Timeout for each scan")
	flag.IntVar(&config.MaxConcurrency, "max-concurrent", runtime.NumCPU()*2, "Maximum concurrent scans")
	flag.StringVar(&config.OutputFile, "output", "", "Output JSON file path")
	flag.IntVar(&config.BufferSize, "buffer", 4*1024*1024, "Buffer size for file reading (bytes)")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("Usage: program [options] <target1> [target2] ...")
		fmt.Println("Targets can be IP addresses, domain names, CIDR notation, or files with IPs/domains")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	scanner := NewIPScanner(config)

	if err := scanner.Run(flag.Args()); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
