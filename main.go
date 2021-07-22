package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"flag"

	"github.com/banviktor/asnlookup/pkg/database"
	"github.com/gocarina/gocsv"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"moul.io/banner"
)

var (
	iface string
	snaplen  = int32(1600)
	promisc  = false
	timeout  = pcap.BlockForever
	filter   = "inbound and tcp[tcpflags] == tcp-syn and port "
	devFound = false
	allowed_orgs string
	asndata string
	asndb string
	port string
	output string
)

type Info struct {
	First string `csv:"first"` // .csv column headers
	Last  string `csv:"last"`
	Asn   string `csv:"asn"` // .csv column headers
	Name  string `csv:"org_name"`
}



var PrivateIPNetworks = []net.IPNet{
	net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	},
	net.IPNet{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.CIDRMask(12, 32),
	},
	net.IPNet{
		IP:   net.ParseIP("192.168.0.0"),
		Mask: net.CIDRMask(16, 32),
	},
}

func IsIPPrivate(ip net.IP) bool {
	for _, ipNet := range PrivateIPNetworks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func getOrgOffline(ip string) int {
	dbFile, err := os.OpenFile(asndb, os.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}
	defer dbFile.Close()

	db, err := database.NewFromDump(dbFile)
	if err != nil {
		panic(err)
	}

	as, err := db.Lookup(net.ParseIP(ip))
	if err != nil {
		log.Println("Cannot find ASN: " + ip)
		fmt.Println("Cannot find ASN: " + ip)
		return 0
	}
	//fmt.Println(as.Number)
	return int(as.Number)
}

func checkOrg(asnNumber int) bool {
	for _, item := range validOrgs {
		i, _ := strconv.Atoi(item)
		if i == asnNumber {
			log.Printf("[!] Allowed ASN: " + item)
			fmt.Printf("[!] Allowed ASN: " + item  + "\n")
			return true
		}
	}
	//asnNumber, _ := strconv.Itoa(asnNumber)
	log.Printf("[!] Blocked ASN: " + strconv.Itoa(asnNumber))
	fmt.Printf("[!] Blocked ASN: " + strconv.Itoa(asnNumber)  + "\n")
	return false
}

func blockIP(validateIP string) {
	app2 := "/sbin/iptables"
	cmd2 := exec.Command(app2, "-A", "INPUT", "-s", validateIP, "--cstate", "ESTABLISHED", "-j", "REJECT")
	err := cmd2.Run()
	if err != nil {
		log.Println(err.Error())
	}
	app := "/sbin/iptables"
	cmd := exec.Command(app, "-A", "INPUT", "-s", validateIP, "-j", "REJECT")
	err = cmd.Run()
	if err != nil {
		log.Println(err.Error())
		return
	}
	log.Printf("[!] Blocked IP: " + validateIP)
	fmt.Printf("[!] Blocked IP: " + validateIP +"\n")
}



func getValidOrgs(asns []*Info ) {
	file, err := os.Open(allowed_orgs)
	if err != nil {
		return
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for _, item := range lines {
		for _, org := range asns {
			if strings.Contains(strings.ToLower(org.Name), strings.ToLower(item)) {
				validOrgs = append(validOrgs, org.Asn)
				log.Printf("[!] Allowed ASN: " + org.Asn + "\n")
				//fmt.Printf("[!] Allowed ASN: " + org.Asn + "\n")
			}
		}
	}
	removeDuplicateValues()
	fmt.Printf("[!] " + strconv.Itoa(len(validOrgs)) + " ASN's Allowed\n")
	fmt.Printf("[!] Check the log file for the complete list of allowed ASN's\n")
	log.Printf("[!] " + strconv.Itoa(len(validOrgs)) + " ASN's Allowed")
	if len(validOrgs) < 1 {
		panic("[!] Error: No valid ASN's found")
	}
}

func removeDuplicateValues() {
	keys := make(map[string]bool)
	list := []string{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. else we jump on another element.
	for _, entry := range validOrgs {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	validOrgs = list
}

var validOrgs []string

func runChecks(validateIP string, found bool) {
	if !IsIPPrivate(net.ParseIP(validateIP)) && !found {
		asnNumber := getOrgOffline(validateIP)
		allowed := checkOrg(asnNumber)
		if !allowed {
			go blockIP(validateIP)
		} else {
			log.Printf("[!] Allowed IP: " + validateIP)
			fmt.Printf("[!] Allowed IP: " + validateIP  +"\n")
		}
	}
}



func printBanner() {
	fmt.Println(banner.Inline("goalloworg"))

}


func main() {
	
	printBanner()
	flag.StringVar(&allowed_orgs, "orgs", "allowed_orgs.txt", "File with line delimited orgs to allow")
	flag.StringVar(&asndata, "asn_csv", "asndata.csv", "CSV file with org name to ASN number")
	flag.StringVar(&asndb, "asn_db", "asn.db", "ASN database")
	flag.StringVar(&port, "port", "443", "Port to monitor")
	flag.StringVar(&output, "output", "goFW.log", "Log file name")
	flag.StringVar(&iface, "interface", "ens5", "Interface name")
	flag.Parse()
	//fmt.Printf("[!] Warming Up..")
	log.Printf("[!] Warming Up..")

	f, err := os.OpenFile(output, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	asnFile, err := os.Open(asndata)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	asns := []*Info{}
	

	if err := gocsv.UnmarshalFile(asnFile, &asns); err != nil {
		log.Panicln(err)
	}
	getValidOrgs(asns)

	fmt.Printf("[!] Beginning Janky Firewall..\n")
	fmt.Printf("[!] Monitoring Port: " + port + "\n")
	log.Printf("[!] Beginning Janky Firewall..")
	log.Printf("[!] Monitoring Port: " + port)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln(err)
	}

	for _, device := range devices {
		if device.Name == iface {
			devFound = true
		}
	}
	if !devFound {
		log.Panicf("Device named '%s' does not exist\n", iface)
	}

	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter + port); err != nil {
		log.Panicln(err)
	}
	var checkedIP []string
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		//fmt.Println(packet.SrcIP())
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			//fmt.Println("This is a IP packet!")
			// Get actual IP data from this layer
			ip, _ := ipLayer.(*layers.IPv4)
			//fmt.Println(ip.SrcIP)

			validateIP := ip.SrcIP.String()
			found := Find(checkedIP, validateIP)
			checkedIP = append(checkedIP, validateIP)
			go runChecks(validateIP, found)

		}
	}
}
