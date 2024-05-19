// Basic port scanner for TCP open ports
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Flags
var a = flag.Bool("a", false, "enable all ports scan")
var syn = flag.String("syn", "", "use sudo and input network iface to enable scan against syn protections")
var t = flag.String("t", "localhost", "set target IP/URL")
var v = flag.Bool("v", false, "enable verbose output")
var w = flag.Int("w", 100, "set worker count > 0")

var workers int
var isVerbose bool
var isAllPorts bool
var isSynScan bool

// Program start
func main() {
	var wg sync.WaitGroup
	var openPorts = []int{}
	var synResults = map[string]int{}
	var host string = ""
	var targetIP string = ""
	tokens := make(chan struct{}, *w)
	startTime := time.Now()

	// Check for empty argument list and validate target input
	if len(os.Args) <= 1 {
		prHeader()
		os.Exit(0)
	}
	targetCheck(&host, &targetIP)

	if isVerbose {
		fmt.Println("Scan target: ", host)
		fmt.Println("Target IP:", targetIP)
	}

	// Sniff packets for extra header packets after handshake
	if isSynScan {
		go sniff(*syn, synResults, &targetIP)
		// Wait before tcp scanning starts
		time.Sleep(1 * time.Second)
	}

	// Scanning ports (system ports are 1 to 1023; max 65535)
	minPort := 1
	maxPort := 1023
	if isAllPorts {
		minPort = 1
		maxPort = 65535
	}
	if isVerbose {
		fmt.Println("Scanning port", minPort, "to port", maxPort, ".")
	}
	for i := minPort; i <= maxPort; i++ {
		wg.Add(1)
		go scan(host, i, &wg, &tokens, &openPorts)
	}
	wg.Wait()

	// Wait for packets some more
	if isSynScan {
		time.Sleep(2 * time.Second)
	}

	// Format and output results
	outTable(openPorts, isVerbose, isSynScan, synResults)

	// Manage duration of program
	stopTime := time.Now()
	if isVerbose {
		duration := stopTime.Sub(startTime)
		fmt.Println("")
		fmt.Println("Scan duration: ", duration)
	}
}

// Port scan logic
func scan(host string, port int, wg *sync.WaitGroup, tokens *chan struct{}, openPorts *[]int) {
	defer wg.Done()
	*tokens <- struct{}{}
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		<-*tokens
		return
	}
	conn.Close()
	<-*tokens
	*openPorts = append(*openPorts, port)
}

// Sniff nr of packets for header packets after handshake to circumvent syn protections
func sniff(iface string, synResults map[string]int, targetIP *string) {

	// Filter for target host and non handshake passages
	filter := fmt.Sprintf("%s%s%s", "ip src host ", *targetIP, " and (tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18)")
	handle, err := pcap.OpenLive(iface, int32(320), true, pcap.BlockForever)
	if err != nil {
		log.Panicln(err)
	}

	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Panicln(err)
	}

	// Find port of packet and add to results of syn scan
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		// Result managing
		srcPort := transportLayer.TransportFlow().Src().String()
		synResults[srcPort] += 1
	}

}

// Print ordered results with added service type to terminal
func outTable(openPorts []int, isVerbose bool, isSynScan bool, synResults map[string]int) {
	sort.Ints(openPorts)

	// Hashmap of common port names
	portType := make(map[int]string)
	portType[20] = "FTP"
	portType[21] = "FTP"
	portType[22] = "SSH"
	portType[23] = "telnet"
	portType[25] = "SMTP"
	portType[42] = "nameserver"
	portType[53] = "DNS"
	portType[67] = "DHCP"
	portType[68] = "DHCP"
	portType[69] = "TFTP"
	portType[80] = "HTTP"
	portType[110] = "POP3"
	portType[119] = "NNTP"
	portType[123] = "NTP"
	portType[137] = "NetBIOS"
	portType[138] = "NetBIOS"
	portType[139] = "NetBIOS"
	portType[143] = "IMAP"
	portType[156] = "SQL"
	portType[161] = "SNMP"
	portType[162] = "SNMP"
	portType[179] = "BGP"
	portType[194] = "IRC"
	portType[389] = "LDAP"
	portType[443] = "HTTPS"
	portType[445] = "SMB"
	portType[631] = "IPP"
	portType[1433] = "MSSQL"
	portType[3389] = "RDP"

	// Output as table standard
	if isVerbose {
		fmt.Println("")
	}
	fmt.Printf("%-5v %v\n", "PORT", "SERVICE")
	for _, port := range openPorts {
		pType := portType[port]
		fmt.Printf("%-5d %v\n", port, pType)
	}

	// Output as table syn
	if isSynScan {
		fmt.Println("")
		fmt.Println("SYNSCAN: ")
		fmt.Printf("%-5v %-4v %v\n", "PORT", "SYN", "SERVICE")
		// Order map by string and print
		keys := make([]string, 0)
		for k := range synResults {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if synResults[k] > 0 {
				i, _ := strconv.Atoi(k)
				pType := portType[i]
				fmt.Printf("%-5s %-4d %s\n", k, synResults[k], pType)
			}
		}
	}
}

// Check if user input for target is valid IP or URI
func targetCheck(host *string, targetIP *string) {

	// Check for valid IP in input
	checkIP := net.ParseIP(*t)
	if checkIP != nil {
		*host = *t
		*targetIP = *t
		return
	}

	// Check for valid URI in input
	_, err := url.ParseRequestURI(*t)
	if err == nil {
		tempHost := *t
		*host = strings.TrimPrefix(tempHost, "http://")
		*targetIP = getIP(*host)
		return
	}

	// Check for if input is string localhost
	if *t == "localhost" {
		tempHost := *t
		*host = strings.TrimPrefix(tempHost, "http://")
		*targetIP = getIP(*host)
		return
	}

	// Add http prefix to check isURI again
	tempHost := fmt.Sprintf("%s%s", "http://", *t)
	_, err2 := url.ParseRequestURI(tempHost)
	if err2 == nil {
		*host = strings.TrimPrefix(tempHost, "http://")
		*targetIP = getIP(*host)
		return
	}

	// Exit program since no valid input
	prHeader()
	fmt.Println("Error: No valid IP or URI given")
	fmt.Println("Error on input target candidate: ", *t)
	os.Exit(0)

}

// Return IPv4 from URL
func getIP(host string) string {
	ips, _ := net.LookupIP(host)
	var tempIP string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			tempIP = fmt.Sprintf("%v", ipv4)

		}
	}
	return tempIP

}

// Set initial values from flags and other values
func init() {
	flag.Parse()
	if *v {
		isVerbose = true
		fmt.Println("Gordo is in a talkative mood right now")
	} else {
		isVerbose = false
	}

	if *a {
		isAllPorts = true
	} else {
		isAllPorts = false
	}

	if *syn != "" {
		isSynScan = true
	} else {
		isSynScan = false
	}

	if *w > 0 {
		workers = *w

	} else {
		// Default on negative input
		workers = 100
	}

	if isVerbose {
		fmt.Println("Worker Count: ", workers)
	}
}

// Print header when no arguments in CLI or on error
func prHeader() {
	var Reset = "\033[0m"
	var White = "\033[97m"
	fmt.Println("Gordo Port Scanner by BenPapple")
	fmt.Println("")
	// ANSI Shadow
	fmt.Println(White + " ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ")
	fmt.Println("██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗")
	fmt.Println("██║  ███╗██║   ██║██████╔╝██║  ██║██║   ██║")
	fmt.Println("██║   ██║██║   ██║██╔══██╗██║  ██║██║   ██║")
	fmt.Println("╚██████╔╝╚██████╔╝██║  ██║██████╔╝╚██████╔╝")
	fmt.Println(" ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ " + Reset)
	fmt.Println("")
	fmt.Println("Use -h for help")
	fmt.Println("Example use case: gordo -t 127.0.0.1")
	fmt.Println("Example use case: gordo -t localhost")
	fmt.Println("Example use case: gordo -t URL")
	fmt.Println("")
}
