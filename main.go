package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	infoPtr := flag.Bool("i", false, "a bool")
	flag.Parse()

	scan(*infoPtr)
}

func scan(infoMode bool) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("***E-Mail Domain Verifier***")
	fmt.Println("Type the domain to verify:")

	for scanner.Scan() {
		verifyDomain(scanner.Text(), infoMode)
		fmt.Println("Press (any key +) enter to continue or 'q' + enter to quit:")
		scanner.Scan()
		if scanner.Text() == "q" {
			break
		} else {
			fmt.Println("Type the domain to verify:")
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error: could not read from input %v \n", err)
	}
}

func verifyDomain(domain string, infoMode bool) {
	var hasMX, hasSPF, hasDMARC bool
	var spfRecord, dmarcRecord string

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("Error: %+v\n", err)
	}
	if len(mxRecords) > 0 {
		hasMX = true
	} else {
		hasMX = false
	}

	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("Error: %+v\n", err)
	}
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true
			spfRecord = record
			break
		}
	}

	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		log.Printf("Error: %+v\n", err)
	}
	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			hasDMARC = true
			dmarcRecord = record
			break
		}
	}

	if hasSPF || hasDMARC || hasMX {
		fmt.Printf("Domain %s is valid!\n", domain)

		if infoMode {
			fmt.Printf("Domain: %v, Has MX: %v, Has SPF: %v, SPF Record: %v, Has DMARC: %v, DMARC Record: %v\n", domain, hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord)
		}
		return
	}

	fmt.Printf("Domain %s invalid.\n", domain)
}
