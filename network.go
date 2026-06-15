package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func getHostsList() []string {
	var hosts []string

	// Validate input parameters
	if *hostFlag != "" && *networkFlag != "" {
		printUsageError(
			"Cannot use both -h and -n flags at the same time.",
			"NullFang -h 192.168.1.10 -u admin -p password",
		)
	}

	if *hostFlag != "" {
		// Validate if it's a valid IP
		if net.ParseIP(*hostFlag) == nil {
			printUsageError(
				"Invalid IP address format for -h flag. Expected format: x.x.x.x",
				"NullFang -h 192.168.1.10 -u admin -p password",
			)
		}
		hosts = append(hosts, *hostFlag)
	}

	if *networkFlag != "" {
		_, ipnet, err := net.ParseCIDR(*networkFlag)
		if err != nil {
			printUsageError(
				"Invalid CIDR format for -n flag. Expected format: x.x.x.x/y",
				"NullFang -n 192.168.1.0/24 -u admin -p password",
			)
		}
		hosts = append(hosts, expandCIDR(ipnet)...)
	}

	if *listFlag != "" {
		// Check if file exists
		if _, err := os.Stat(*listFlag); os.IsNotExist(err) {
			printUsageError(
				"File specified with -l flag does not exist: "+*listFlag,
				"NullFang -l hosts.txt -u admin -p password",
			)
		}

		// Check if it's a file (not a directory)
		fileInfo, err := os.Stat(*listFlag)
		if err == nil && fileInfo.IsDir() {
			printUsageError(
				"Path specified with -l flag is a directory, expected a file: "+*listFlag,
				"NullFang -l hosts.txt -u admin -p password",
			)
		}

		fileHosts, err := readHostsFile(*listFlag)
		if err != nil {
			printUsageError(
				"Error reading hosts file: "+err.Error(),
				"NullFang -l hosts.txt -u admin -p password",
			)
		}

		// Validate each IP in the file
		for i, host := range fileHosts {
			if net.ParseIP(host) == nil {
				printUsageError(
					fmt.Sprintf("Invalid IP address at line %d in file %s: %s", i+1, *listFlag, host),
					"NullFang -l hosts.txt -u admin -p password",
				)
			}
		}
		hosts = append(hosts, fileHosts...)
	}

	if len(hosts) == 0 {
		printUsageError(
			"No target specified. Use -h, -n, or -l to specify a target.",
			"NullFang -h 192.168.1.10 -u admin -p password",
		)
	}

	return hosts
}

func expandCIDR(ipnet *net.IPNet) []string {
	var ips []string
	// Primeiro, coleta todos os IPs
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Randomiza a ordem dos IPs usando o algoritmo Fisher-Yates
	rand.Seed(time.Now().UnixNano())
	for i := len(ips) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		ips[i], ips[j] = ips[j], ips[i]
	}

	return ips
}

func readHostsFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var hosts []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			hosts = append(hosts, line)
		}
	}
	return hosts, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
