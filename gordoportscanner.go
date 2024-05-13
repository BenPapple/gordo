// Basic port scanner for TCP/IP open ports
package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"sync"
)

var workers int
var openports = []int{}
var host string = "localhost"

// Flags
var v = flag.Bool("v", false, "enable verbose output")
var w = flag.Int("w", 10, "set worker count > 0")
var t = flag.Bool("t", false, "set target IP/URL")

// Program start
func main() {
	//work := make(chan int, workers)
	var wg sync.WaitGroup

	// Scanning system ports 0 to 1023
	for i := 0; i < 1024; i++ {
		wg.Add(1)
		go scan(host, i, &wg)
	}
	wg.Wait()

	// Format output of program
	sort.Ints(openports)
	fmt.Println("Final list of open ports: ", openports)
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
		fmt.Println("Verbose mode active")
	} else {
		fmt.Println("Verbose mode not active")
	}

	if *w > 0 {
		workers = *w
		fmt.Println("Worker Count: ", workers)
	} else {
		workers = 10
		fmt.Println("Negative input, adjusted worker Count: ", workers)
	}

	if *t {
		fmt.Println("Target chosen: ", host)
	} else {
		fmt.Println("Default target chosen: ", host)
	}

}
