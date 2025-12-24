package main

/*
Toralizer: Bulletproof Tor Traffic Enforcement
Type: Network Namespace Isolation & Nftables Redirection
*/

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	NetworkCIDR  string // e.g., "10.100.0.0/30"
	Verbose      bool
}

// Sandbox represents an active isolation context
type Sandbox struct {
	ID        string
	Namespace string // Name of the netns
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
		NetworkCIDR:  "10.200.0.0/30", // Small subnet: .1 host, .2 peer
		Verbose:      true,
	}
)

func main() {
	// Parse CLI arguments
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	args := flag.Args()
	if *help || len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]

	// 1. Validation
	if os.Geteuid() != 0 {
		log.Fatal("Error: Toralizer must be run as root to create namespaces and firewall rules.")
	}

	// 2. Initialize Sandbox
	sandbox, err := NewSandbox(defaultConfig)
	if err != nil {
		log.Fatalf("Failed to initialize sandbox: %v", err)
	}
	defer sandbox.Teardown()

	// 3. Setup Networking
	if sandbox.Config.Verbose {
		log.Printf("Creating Network Namespace: %s", sandbox.Namespace)
	}
	if err := sandbox.SetupNetwork(); err != nil {
		log.Fatalf("Network setup failed: %v", err)
	}

	// 4. Apply Firewall Rules (NFTables)
	if sandbox.Config.Verbose {
		log.Println("Applying fail-closed Tor firewall rules...")
	}
	if err := sandbox.ApplyFirewall(); err != nil {
		log.Fatalf("Firewall setup failed: %v", err)
	}

	// 5. Handle Signals for Cleanup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\nReceived signal, tearing down...")
		sandbox.Teardown()
		os.Exit(0)
	}()
	log.Println("Sleeping one 2 minnutes...")
	time.Sleep(2 * time.Minute)
	// 6. Execute Command in Namespace
	if sandbox.Config.Verbose {
		log.Printf("Executing: %s %v", command, cmdArgs)
		log.Println("---------------------------------------------------")
	}

	err = sandbox.Run(command, cmdArgs)
	if err != nil {
		log.Printf("Execution finished with error: %v", err)
		// Propagate exit code if possible
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		os.Exit(1)
	}
}

// NewSandbox creates a new Sandbox struct with a unique ID
func NewSandbox(cfg Config) (*Sandbox, error) {
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(randBytes)

	// Calculate IPs based on CIDR (Simplified logic for assignment)
	// Assuming /30, Host is .1, Peer is .2
	baseIP, _, err := net.ParseCIDR(cfg.NetworkCIDR)
	if err != nil {
		return nil, err
	}
	ip4 := baseIP.To4()
	if ip4 == nil {
		return nil, errors.New("IPv6 not supported in this version")
	}

	// Increment last octet
	ipHost := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+1).String()
	ipPeer := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+2).String()

	return &Sandbox{
		ID:        id,
		Namespace: fmt.Sprintf("tor-ns-%s", id),
		VethHost:  fmt.Sprintf("veth-h-%s", id),
		VethPeer:  fmt.Sprintf("veth-p-%s", id),
		IPHost:    fmt.Sprintf("%s/30", ipHost), // Add CIDR mask
		IPPeer:    fmt.Sprintf("%s/30", ipPeer),
		Config:    cfg,
	}, nil
}

// SetupNetwork builds the veth pair and configures IP routing
func (s *Sandbox) SetupNetwork() error {
	// 1. Create Network Namespace
	log.Printf("Tor network ns: %s", s.Namespace)
	if err := runCmd("ip", "netns", "add", s.Namespace); err != nil {
		return fmt.Errorf("creating netns: %w", err)
	}

	log.Printf("Creting veth host: %s, veth peer: %s", s.VethHost, s.VethPeer)
	// 2. Create Veth Pair
	if err := runCmd("ip", "link", "add", s.VethHost, "type", "veth", "peer", "name", s.VethPeer); err != nil {
		return fmt.Errorf("creating veth pair: %w", err)
	}

	// 3. Move Peer interface to Namespace
	if err := runCmd("ip", "link", "set", s.VethPeer, "netns", s.Namespace); err != nil {
		return fmt.Errorf("moving interface to netns: %w", err)
	}

	// 4. Configure Host Interface
	if err := runCmd("ip", "addr", "add", s.IPHost, "dev", s.VethHost); err != nil {
		return fmt.Errorf("setting host ip: %w", err)
	}
	if err := runCmd("ip", "link", "set", s.VethHost, "up"); err != nil {
		return fmt.Errorf("setting host interface up: %w", err)
	}

	// --- CRITICAL FIXES FOR CONNECTIVITY ---

	// Fix A: Enable route_localnet
	// Allows 127.0.0.1 traffic to be routed on this interface
	sysctlLocalnet := fmt.Sprintf("net.ipv4.conf.%s.route_localnet", s.VethHost)
	if err := runCmd("sysctl", "-w", fmt.Sprintf("%s=1", sysctlLocalnet)); err != nil {
		return fmt.Errorf("enabling route_localnet: %w", err)
	}

	// Fix B: Disable RP_FILTER (Reverse Path Filter)
	// Strict RP_FILTER drops packets destined for 127.0.0.1 arriving on a veth interface
	// We must disable it (set to 0) for the host-side veth
	sysctlRpFilter := fmt.Sprintf("net.ipv4.conf.%s.rp_filter", s.VethHost)
	if err := runCmd("sysctl", "-w", fmt.Sprintf("%s=0", sysctlRpFilter)); err != nil {
		return fmt.Errorf("disabling rp_filter: %w", err)
	}

	// Fix C: Disable Checksum Offloading on HOST side
	// Veth packets often have partial checksums which cause drops when redirected to loopback
	exec.Command("ethtool", "-K", s.VethHost, "tx", "off", "rx", "off").Run()

	// 5. Configure Namespace Interface (requires executing inside netns)
	// Enable loopback in NS
	if err := runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("enabling loopback in ns: %w", err)
	}
	// Configure Peer IP
	if err := runCmd("ip", "netns", "exec", s.Namespace, "ip", "addr", "add", s.IPPeer, "dev", s.VethPeer); err != nil {
		return fmt.Errorf("setting peer ip in ns: %w", err)
	}
	// Bring Peer Up
	if err := runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", s.VethPeer, "up"); err != nil {
		return fmt.Errorf("setting peer interface up in ns: %w", err)
	}

	// Fix D: Disable Checksum Offloading on PEER side (inside NS)
	exec.Command("ip", "netns", "exec", s.Namespace, "ethtool", "-K", s.VethPeer, "tx", "off", "rx", "off").Run()

	// Set Default Route (Gateway is Host IP)
	gwIP := strings.Split(s.IPHost, "/")[0]
	if err := runCmd("ip", "netns", "exec", s.Namespace, "ip", "route", "add", "default", "via", gwIP); err != nil {
		return fmt.Errorf("setting default route in ns: %w", err)
	}

	// 6. Setup DNS Overlay
	netnsDir := fmt.Sprintf("/etc/netns/%s", s.Namespace)
	if err := os.MkdirAll(netnsDir, 0755); err != nil {
		return fmt.Errorf("creating netns config dir: %w", err)
	}

	// resolvConf := fmt.Sprintf("nameserver %s\n", gwIP)
	// resolvConf := "nameserver 1.1.1.1\noptions edns0 trust-ad\n"
	resolvConf := "nameserver 1.1.1.1\noptions use-vc\n"
	if err := os.WriteFile(filepath.Join(netnsDir, "resolv.conf"), []byte(resolvConf), 0644); err != nil {
		return fmt.Errorf("writing ns resolv.conf: %w", err)
	}

	nsswitch := `hosts: files dns
`
	if err := os.WriteFile(filepath.Join(netnsDir, "nsswitch.conf"), []byte(nsswitch), 0644); err != nil {
		return fmt.Errorf("writing nsswitch.conf: %w", err)
	}


	return nil
}

// ApplyFirewall configures nftables on the HOST to intercept traffic from the namespace
func (s *Sandbox) ApplyFirewall() error {
	tableName := "toralizer"

	if err := runCmd("nft", "add", "table", "inet", tableName); err != nil {
		return fmt.Errorf("creating nft table: %w", err)
	}

	// Chain 1: PREROUTING (DNAT)
	// Priority -100 ensures we see packets before routing decisions
	chainPrerouting := fmt.Sprintf("pre-%s", s.ID)
	log.Printf("prerouting chain name: %s", chainPrerouting)
	if err := runCmd("nft", "add", "chain", "inet", tableName, chainPrerouting, "{ type nat hook prerouting priority -100; }"); err != nil {
		return fmt.Errorf("creating nft prerouting chain: %w", err)
	}

	// RULE 1: Redirect DNS (UDP 53) -> Explicit DNAT to 127.0.0.1
	// We use Explicit DNAT instead of 'redirect' to avoid ambiguity with interface IPs
	// if err := runCmd("nft", "add", "rule", "inet", tableName, chainPrerouting,
	// 	"iifname", s.VethHost, "udp", "dport", "53", "dnat", "ip", "to", fmt.Sprintf("127.0.0.1:%d", s.Config.TorDNSPort)); err != nil {
	// 	return fmt.Errorf("adding dns redirect rule: %w", err)
	// }
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainPrerouting,
		"iifname", s.VethHost,
		"udp", "dport", "53",
		"redirect", "to", fmt.Sprintf(":%d", s.Config.TorDNSPort)); err != nil {
		return fmt.Errorf("adding dns redirect rule: %w", err)
	}

	// RULE 2: Redirect TCP -> Explicit DNAT to 127.0.0.1
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainPrerouting,
		"iifname", s.VethHost, "meta", "l4proto", "tcp", "dnat", "ip", "to", fmt.Sprintf("127.0.0.1:%d", s.Config.TorTransPort)); err != nil {
		return fmt.Errorf("adding tcp redirect rule: %w", err)
	}

	// RULE 3: DROP everything else from this interface
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainPrerouting,
		"iifname", s.VethHost, "drop"); err != nil {
		return fmt.Errorf("adding drop rule: %w", err)
	}

	// Chain 2: INPUT (ACCEPT)
	// Priority -50 ensures we accept before standard filter chains (usually priority 0) drop it.
	// This is critical because after DNAT to 127.0.0.1, the packet is routed to INPUT.
	chainInput := fmt.Sprintf("in-%s", s.ID)
	if err := runCmd("nft", "add", "chain", "inet", tableName, chainInput, "{ type filter hook input priority -50; }"); err != nil {
		return fmt.Errorf("creating nft input chain: %w", err)
	}

	// RULE 4: Explicitly Accept traffic from veth interface
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainInput,
		"iifname", s.VethHost, "accept"); err != nil {
		return fmt.Errorf("adding input accept rule: %w", err)
	}

	return nil
}

// Run executes the command inside the namespace using 'ip netns exec'
func (s *Sandbox) Run(bin string, args []string) error {
	// Prepare params
	cmdParams := []string{"netns", "exec", s.Namespace, bin}
	cmdParams = append(cmdParams, args...)

	cmd := exec.Command("ip", cmdParams...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = os.Environ()

	return cmd.Run()
}

// Teardown cleans up the namespace and firewall rules
func (s *Sandbox) Teardown() {
	if s.Config.Verbose {
		log.Printf("Tearing down sandbox %s...", s.ID)
	}

	// 1. Delete Network Namespace
	if err := runCmd("ip", "netns", "del", s.Namespace); err != nil {
		log.Printf("Warning: failed to delete netns: %v", err)
	}

	// 2. Remove Netns Config Dir
	if err := os.RemoveAll(fmt.Sprintf("/etc/netns/%s", s.Namespace)); err != nil {
		log.Printf("Warning: failed to remove netns config: %v", err)
	}

	// 3. Remove NFTables Chains
	tableName := "toralizer"
	chainPrerouting := fmt.Sprintf("pre-%s", s.ID)
	chainInput := fmt.Sprintf("in-%s", s.ID)

	// We ignore errors here in case chains don't exist
	exec.Command("nft", "delete", "chain", "inet", tableName, chainPrerouting).Run()
	exec.Command("nft", "delete", "chain", "inet", tableName, chainInput).Run()
}

func runCmd(name string, args ...string) error {
	// Adding a small sleep to avoid race conditions on slower systems during interface creation
	if name == "sysctl" {
		time.Sleep(100 * time.Millisecond)
	}
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %v, output: %s", name, err, string(out))
	}
	return nil
}

func printUsage() {
	fmt.Println(`Toralizer - Bulletproof Tor Traffic Enforcement
Usage: toralizer run [command] [args...]

Example:
  toralizer run curl https://check.torproject.org
  toralizer run /bin/bash

Requirements:
  - Root privileges
  - Tor running with TransPort 9040 & DNSPort 9053
  - Nftables installed`)
}
