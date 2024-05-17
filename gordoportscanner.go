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
var openports = []int{}
var host string = ""
var targetIP string = ""
var isverbose bool
var isallports bool
var issynscan bool
var tokens chan struct{}
var synmap = make(map[string]int)

// Program start
func main() {
	var wg sync.WaitGroup
	tokens = make(chan struct{}, *w)
	startTime := time.Now()

	// Check for empty argument list and correct target input
	if len(os.Args) <= 1 {
		prheader()
		os.Exit(0)
	}
	targetcheck()

	if isverbose {
		fmt.Println("Scan target: ", host)
		fmt.Println("Target IP:", targetIP)
	}

	// Sniff packets for extra header packets after handshake
	if issynscan {
		go sniff(*syn)
		// Wait before tcp scanning starts
		time.Sleep(1 * time.Second)
	}

	// Scanning ports (system ports are 1 to 1023; max 65535)
	minport := 1
	maxport := 1023
	if isallports {
		minport = 1
		maxport = 65535
	}
	if isverbose {
		fmt.Println("Scanning port", minport, "to port", maxport, ".")
	}
	for i := minport; i <= maxport; i++ {
		wg.Add(1)
		go scan(host, i, &wg)
	}
	wg.Wait()

	// Wait for packages some more
	if issynscan {
		time.Sleep(3 * time.Second)
	}

	// Format and output results
	outtable()

	// Manage duration of program
	stopTime := time.Now()
	if isverbose {
		duration := stopTime.Sub(startTime)
		fmt.Println("")
		fmt.Println("Scan duration: ", duration)
	}
}

// Port scan logic
func scan(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	tokens <- struct{}{}
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		<-tokens
		return
	}
	conn.Close()
	<-tokens
	openports = append(openports, port)
}

// Sniff nr of packets for header packages after handshake to circumvent syn protections
func sniff(iface string) {

	// Filter for target host and non handshake passages
	filter := fmt.Sprintf("%s%s%s", "ip src host ", targetIP, " and (tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18)")
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
		synmap[srcPort] += 1
	}

}

// Print ordered results with added service type to terminal
func outtable() {
	sort.Ints(openports)

	// Hashmap of common port names
	porttype := make(map[int]string)
	porttype[21] = "FTP"
	porttype[22] = "SSH"
	porttype[23] = "telnet"
	porttype[25] = "SMTP"
	porttype[42] = "nameserver"
	porttype[53] = "DNS"
	porttype[80] = "HTTP"
	porttype[137] = "NetBIOS"
	porttype[138] = "NetBIOS"
	porttype[139] = "NetBIOS"
	porttype[443] = "HTTPS"
	porttype[445] = "SMB"
	porttype[631] = "IPP"
	porttype[1433] = "MSSQL"
	porttype[3389] = "RDP"

	// Output as table standard
	if isverbose {
		fmt.Println("")
	}
	fmt.Printf("%-5v %v\n", "PORT", "SERVICE")
	for _, port := range openports {
		ptype := porttype[port]
		fmt.Printf("%-5d %v\n", port, ptype)
	}

	// Output as table syn
	if issynscan {
		fmt.Println("")
		fmt.Println("SYNSCAN: ")
		fmt.Printf("%-5v %-4v %v\n", "PORT", "SYN", "SERVICE")
		for port, syn := range synmap {
			if syn > 0 {
				i, _ := strconv.Atoi(port)
				ptype := porttype[i]
				fmt.Printf("%-5s %-4d %s\n", port, syn, ptype)
			}
		}
	}
}

// Check if user input for target is valid IP or URI
func targetcheck() {

	// Check for valid IP in input
	checkIP := net.ParseIP(*t)
	if checkIP != nil {
		host = *t
		targetIP = *t
		return
	}

	// Check for valid URI in input
	_, err := url.ParseRequestURI(*t)
	if err == nil {
		temphost := *t
		host = strings.TrimPrefix(temphost, "http://")
		targetIP = getIP()
		return
	}

	// Check for if input is string localhost
	if *t == "localhost" {
		temphost := *t
		host = strings.TrimPrefix(temphost, "http://")
		targetIP = getIP()
		return
	}

	// Add http prefix to check isURI again
	temphost := fmt.Sprintf("%s%s", "http://", *t)
	_, err2 := url.ParseRequestURI(temphost)
	if err2 == nil {
		host = strings.TrimPrefix(temphost, "http://")
		targetIP = getIP()
		return
	}

	// Exit program since no valid input
	prheader()
	fmt.Println("Error: No valid IP or URI given")
	fmt.Println("Error on input target candidate: ", *t)
	os.Exit(0)

}

// Return IPv4 from URL
func getIP() string {
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
		isverbose = true
		fmt.Println("Gordo is in a talkative mood right now")
	} else {
		isverbose = false
	}

	if *a {
		isallports = true
	} else {
		isallports = false
	}

	if *syn != "" {
		issynscan = true
	} else {
		issynscan = false
	}

	if *w > 0 {
		workers = *w

	} else {
		// Default on negative input
		workers = 100
	}

	if isverbose {
		fmt.Println("Worker Count: ", workers)
	}
}

// Print header when no arguments in CLI or on error
func prheader() {
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
