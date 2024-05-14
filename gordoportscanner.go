// Basic port scanner for TCP open ports
package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"
)

var workers int
var openports = []int{}
var host string = ""
var isverbose bool

// Flags
var v = flag.Bool("v", false, "enable verbose output")
var w = flag.Int("w", 10, "set worker count > 0")
var t = flag.String("t", "localhost", "set target IP/URL")

// Program start
func main() {
	//work := make(chan int, workers)
	var wg sync.WaitGroup
	startTime := time.Now()

	// Check for empty argument list
	//fmt.Println("Args: ", os.Args)
	if len(os.Args) <= 1 {
		prheader()
		os.Exit(0)
	}

	// Scanning system ports 1 to 1023
	for i := 1; i < 1024; i++ {
		wg.Add(1)
		go scan(host, i, &wg)
	}
	wg.Wait()

	// Format output of program
	sort.Ints(openports)
	fmt.Println("Final list of open ports: ", openports)
	stopTime := time.Now()
	duration := stopTime.Sub(startTime)
	if isverbose {
		fmt.Println("Scan duration: ", duration)
	}
}

// Port scan logic
func scan(host string, port int, wg *sync.WaitGroup) {
	defer wg.Done()
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	conn.Close()
	openports = append(openports, port)
}

// Set initial values from flags and other values
func init() {
	flag.Parse()
	if *v {
		isverbose = true
		fmt.Println("Verbose mode active")
	} else {
		isverbose = false
	}

	if *w > 0 {
		workers = *w

	} else {
		// Default on negative input
		workers = 10
	}

	if isverbose {
		fmt.Println("Worker Count: ", workers)
	}

	// Check for valid URI or IP in input
	checkIP := net.ParseIP(*t)
	_, err := url.ParseRequestURI(*t)
	if err != nil && *t != "localhost" && checkIP == nil {
		panic(err)
	}

	host = *t
	if isverbose {
		fmt.Println("Target chosen: ", host)
	}
}

// Print header when no arguments in CLI
func prheader() {
	var Reset = "\033[0m"
	var White = "\033[97m"
	fmt.Println("")
	fmt.Println(White + ":'######:::'#######:'########:'########::'#######::::'######::'######::::'###:::'##::: ##'##::: ##'########'########::")
	fmt.Println(" ##:::..:::##:::: ##:##:::: ##:##:::: ##:##:::: ##:::##:::..::##:::..::'##:. ##::####: ##:####: ##:##:::::::##:::: ##:")
	fmt.Println(" ##::'####:##:::: ##:########::##:::: ##:##:::: ##::. ######::##::::::'##:::. ##:## ## ##:## ## ##:######:::########::")
	fmt.Println(" ##::: ##::##:::: ##:##.. ##:::##:::: ##:##:::: ##:::..... ##:##:::::::#########:##. ####:##. ####:##...::::##.. ##:::")
	fmt.Println(" ##::: ##::##:::: ##:##::. ##::##:::: ##:##:::: ##::'##::: ##:##::: ##:##.... ##:##:. ###:##:. ###:##:::::::##::. ##::")
	fmt.Println(". ######::. #######::##:::. ##:########:. #######:::. ######:. ######::##:::: ##:##::. ##:##::. ##:########:##:::. ##:")
	fmt.Println(":......::::.......::..:::::..:........:::.......:::::......:::......::..:::::..:..::::..:..::::..:........:..:::::..::" + Reset)
	fmt.Println("")
	fmt.Println("Use -h for help")
	fmt.Println("Example use case: gordo -t 127.0.0.1")
	fmt.Println("")
}
