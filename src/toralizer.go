package main

/*
Toralizer: Bulletproof Tor Traffic Enforcement
Type: Network Namespace Isolation & Nftables Redirection
*/

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Config holds the configuration for the sandbox
type Config struct {
	TorTransPort int
	TorDNSPort   int
	NetworkCIDR  string 
	Verbose      bool
}

// Sandbox represents an active isolation context
type Sandbox struct {
	ID        string
	Namespace string 
	VethHost  string
	VethPeer  string
	IPHost    string
	IPPeer    string
	Config    Config
}

var (
	defaultConfig = Config{
		TorTransPort: 9040,
		TorDNSPort:   9053,
		NetworkCIDR:  "10.200.0.0/30",
		Verbose:      true,
	}
)

func main() {
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	args := flag.Args()
	if *help || len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]

	if os.Geteuid() != 0 {
		log.Fatal("Error: Toralizer must be run as root.")
	}

	sandbox, err := NewSandbox(defaultConfig)
	if err != nil {
		log.Fatalf("Failed to initialize sandbox: %v", err)
	}
	defer sandbox.Teardown()

	if sandbox.Config.Verbose {
		log.Printf("Creating Network Namespace: %s", sandbox.Namespace)
	}
	if err := sandbox.SetupNetwork(); err != nil {
		log.Fatalf("Network setup failed: %v", err)
	}

	if sandbox.Config.Verbose {
		log.Println("Applying fail-closed Tor firewall rules...")
	}
	if err := sandbox.ApplyFirewall(); err != nil {
		log.Fatalf("Firewall setup failed: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived signal, tearing down...")
		sandbox.Teardown()
		os.Exit(0)
	}()
	
	time.Sleep(2 * time.Minute)

	if sandbox.Config.Verbose {
		log.Printf("Executing: %s %v", command, cmdArgs)
		log.Println("---------------------------------------------------")
	}

	err = sandbox.Run(command, cmdArgs)
	if err != nil {
		log.Printf("Execution finished with error: %v", err)
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		os.Exit(1)
	}
}

func NewSandbox(cfg Config) (*Sandbox, error) {
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(randBytes)

	baseIP, _, err := net.ParseCIDR(cfg.NetworkCIDR)
	if err != nil {
		return nil, err
	}
	ip4 := baseIP.To4()
	
	ipHost := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+1).String()
	ipPeer := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+2).String()

	return &Sandbox{
		ID:        id,
		Namespace: fmt.Sprintf("tor-ns-%s", id),
		VethHost:  fmt.Sprintf("veth-h-%s", id),
		VethPeer:  fmt.Sprintf("veth-p-%s", id),
		IPHost:    fmt.Sprintf("%s/30", ipHost),
		IPPeer:    fmt.Sprintf("%s/30", ipPeer),
		Config:    cfg,
	}, nil
}

func (s *Sandbox) SetupNetwork() error {
	runCmd("ip", "netns", "add", s.Namespace)
	runCmd("ip", "link", "add", s.VethHost, "type", "veth", "peer", "name", s.VethPeer)
	runCmd("ip", "link", "set", s.VethPeer, "netns", s.Namespace)
	runCmd("ip", "addr", "add", s.IPHost, "dev", s.VethHost)
	runCmd("ip", "link", "set", s.VethHost, "up")

	// Disable RP_FILTER and enable localnet routing
	runCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmd("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", s.VethHost))
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.route_localnet=1", s.VethHost))

	// Attempt to turn off offloading
	exec.Command("ethtool", "-K", s.VethHost, "tx", "off", "rx", "off").Run()

	runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", "lo", "up")
	runCmd("ip", "netns", "exec", s.Namespace, "ip", "addr", "add", s.IPPeer, "dev", s.VethPeer)
	runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", s.VethPeer, "up")
	
	gwIP := strings.Split(s.IPHost, "/")[0]
	runCmd("ip", "netns", "exec", s.Namespace, "ip", "route", "add", "default", "via", gwIP)

	netnsDir := fmt.Sprintf("/etc/netns/%s", s.Namespace)
	os.MkdirAll(netnsDir, 0755)
	
	// Set nameserver to the gateway (host IP) which will be intercepted by nftables
	resolvConf := fmt.Sprintf("nameserver %s\n", gwIP)
	os.WriteFile(filepath.Join(netnsDir, "resolv.conf"), []byte(resolvConf), 0644)

	return nil
}

func (s *Sandbox) ApplyFirewall() error {
	tableName := "toralizer"
	runCmd("nft", "add", "table", "inet", tableName)

	// --- NAT: Redirection Logic ---
	chainPre := fmt.Sprintf("pre-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainPre, "{ type nat hook prerouting priority -100; }")
	
	destTorDNS := fmt.Sprintf("127.0.0.1:%d", s.Config.TorDNSPort)
	destTorTrans := fmt.Sprintf("127.0.0.1:%d", s.Config.TorTransPort)

	runCmd("nft", "add", "rule", "inet", tableName, chainPre, "iifname", s.VethHost, "udp", "dport", "53", "dnat", "ip", "to", destTorDNS)
	runCmd("nft", "add", "rule", "inet", tableName, chainPre, "iifname", s.VethHost, "tcp", "dport", "53", "dnat", "ip", "to", destTorDNS)
	runCmd("nft", "add", "rule", "inet", tableName, chainPre, "iifname", s.VethHost, "meta", "l4proto", "tcp", "dnat", "ip", "to", destTorTrans)
	runCmd("nft", "add", "rule", "inet", tableName, chainPre, "iifname", s.VethHost, "drop")

	// --- MANGLE: Fix Checksums ---
	// This is critical because veth-to-lo transitions often fail due to "incorrect" checksums 
	// identified by your tcpdump. Zeroing them out forces the stack to ignore the error.
	chainMangle := fmt.Sprintf("mangle-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainMangle, "{ type filter hook prerouting priority -150; }")
	runCmd("nft", "add", "rule", "inet", tableName, chainMangle, "iifname", s.VethHost, "udp", "dport", "53", "udp", "checksum", "set", "0")

	// --- FILTER: Input Acceptance ---
	chainIn := fmt.Sprintf("in-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainIn, "{ type filter hook input priority -50; }")
	runCmd("nft", "add", "rule", "inet", tableName, chainIn, "iifname", s.VethHost, "accept")
	runCmd("nft", "add", "rule", "inet", tableName, chainIn, "iifname", "lo", "udp", "dport", fmt.Sprintf("%d", s.Config.TorDNSPort), "accept")
	runCmd("nft", "add", "rule", "inet", tableName, chainIn, "iifname", "lo", "tcp", "dport", fmt.Sprintf("%d", s.Config.TorTransPort), "accept")

	return nil
}
func (s *Sandbox) Run(bin string, args []string) error {
	cmdParams := []string{"netns", "exec", s.Namespace, bin}
	cmdParams = append(cmdParams, args...)
	cmd := exec.Command("ip", cmdParams...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (s *Sandbox) Teardown() {
	runCmd("ip", "netns", "del", s.Namespace)
	os.RemoveAll(fmt.Sprintf("/etc/netns/%s", s.Namespace))
	runCmd("nft", "delete", "table", "inet", "toralizer")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func printUsage() {
	fmt.Println("Usage: toralizer [command] [args...]")
}