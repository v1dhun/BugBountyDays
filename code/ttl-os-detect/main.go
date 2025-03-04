package main

import (
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
	Targets       []string
	Timeout       time.Duration
	MaxConcurrency int
	OutputFile    string
}

// ScanResult stores JSON output for each scanned IP
type ScanResult struct {
	IP         string    `json:"ip"`
	TTL        int       `json:"ttl,omitempty"`
	OS         string    `json:"os,omitempty"`
	Success    bool      `json:"success"`
	ErrorMsg   string    `json:"error,omitempty"`
	ScanTime   time.Time `json:"scan_time"`
	Hostname   string    `json:"hostname,omitempty"`
	RTTms      float64   `json:"rtt_ms,omitempty"`
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
	case ttl >= 32 && ttl < 33:
		return "MacOS"
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
		logger:     log.New(os.Stdout, "IPScanner: ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

// sendICMPEcho sends an ICMP Echo Request and returns TTL and other details
func (s *IPScanner) sendICMPEcho(target string) (ScanResult, error) {
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
	conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
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

	return ScanResult{
		IP:       target,
		TTL:      ttl,
		OS:       s.osDetector.DetectOS(ttl),
		Success:  true,
		ScanTime: time.Now(),
		Hostname: hostname,
		RTTms:    float64(rtt.Milliseconds()),
	}, nil
}

// scanTargets concurrently scans multiple IP targets
func (s *IPScanner) scanTargets(targets []string) []ScanResult {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var wg sync.WaitGroup
	results := make(chan ScanResult, len(targets))
	semaphore := make(chan struct{}, s.config.MaxConcurrency)

	for _, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result, err := s.sendICMPEcho(ip)
			if err != nil {
				result = ScanResult{
					IP:       ip,
					Success:  false,
					ErrorMsg: err.Error(),
					ScanTime: time.Now(),
				}
			}
			results <- result
		}(target)
	}

	wg.Wait()
	close(results)
	close(semaphore)

	var scanResults []ScanResult
	for result := range results {
		scanResults = append(scanResults, result)
	}

	return scanResults
}

// outputResults writes scan results to JSON file or stdout
func (s *IPScanner) outputResults(results []ScanResult) error {
	var output []byte
	var err error

	output, err = json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %v", err)
	}

	if s.config.OutputFile != "" {
		if err := os.WriteFile(s.config.OutputFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %v", err)
		}
		s.logger.Printf("Results written to %s", s.config.OutputFile)
	} else {
		fmt.Println(string(output))
	}

	return nil
}

// resolveTargets converts various input types to IP list
func (s *IPScanner) resolveTargets(args []string) ([]string, error) {
	var targets []string

	for _, arg := range args {
		// Subnet handling
		if _, _, err := net.ParseCIDR(arg); err == nil {
			ips, err := expandSubnet(arg)
			if err != nil {
				s.logger.Printf("Error expanding subnet %s: %v", arg, err)
				continue
			}
			targets = append(targets, ips...)
		} else if stat, err := os.Stat(arg); err == nil && !stat.IsDir() {
			// File handling
			ips, err := readIPList(arg)
			if err != nil {
				s.logger.Printf("Error reading file %s: %v", arg, err)
				continue
			}
			targets = append(targets, ips...)
		} else {
			// Single IP handling
			if net.ParseIP(arg) != nil {
				targets = append(targets, arg)
			}
		}
	}

	return targets, nil
}

// expandSubnet converts a subnet CIDR (e.g., "192.168.1.0/24") into individual IPs
func expandSubnet(subnet string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
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

// readIPList loads IPs from a file
func readIPList(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := string(data)
	return splitLines(lines), nil
}

// splitLines removes empty lines & trims spaces
func splitLines(input string) []string {
	var result []string
	for _, line := range strings.Split(input, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func main() {
	config := &Config{}

	flag.DurationVar(&config.Timeout, "timeout", 2*time.Second, "Timeout for each scan")
	flag.IntVar(&config.MaxConcurrency, "max-concurrent", runtime.NumCPU()*2, "Maximum concurrent scans")
	flag.StringVar(&config.OutputFile, "output", "", "Output JSON file path")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("Usage: program [options] <target1> [target2] ...")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	scanner := NewIPScanner(config)
	targets, err := scanner.resolveTargets(flag.Args())
	if err != nil {
		log.Fatalf("Error resolving targets: %v", err)
	}

	results := scanner.scanTargets(targets)

	if err := scanner.outputResults(results); err != nil {
		log.Fatalf("Error outputting results: %v", err)
	}
}
