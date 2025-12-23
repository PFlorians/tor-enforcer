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
	"strings"
	"syscall"
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
// Uses direct 'ip' commands for reliability over complex netlink libraries in a single-file implementation.
func (s *Sandbox) SetupNetwork() error {
	// 1. Create Network Namespace
	if err := runCmd("ip", "netns", "add", s.Namespace); err != nil {
		return fmt.Errorf("creating netns: %w", err)
	}

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
	// Set Default Route (Gateway is Host IP)
	gwIP := strings.Split(s.IPHost, "/")[0]
	if err := runCmd("ip", "netns", "exec", s.Namespace, "ip", "route", "add", "default", "via", gwIP); err != nil {
		return fmt.Errorf("setting default route in ns: %w", err)
	}

	// 6. Enable Forwarding on Host for this specific interface (if global forwarding is off, though usually handled globally)
	// We rely on global `net.ipv4.ip_forward=1` checked in setup_check.sh

	return nil
}

// ApplyFirewall configures nftables on the HOST to intercept traffic from the namespace
func (s *Sandbox) ApplyFirewall() error {
	// We use a dedicated table for Toralizer
	tableName := "toralizer"
	
	// Create table
	if err := runCmd("nft", "add", "table", "inet", tableName); err != nil {
		return fmt.Errorf("creating nft table: %w", err)
	}

	// Create PREROUTING chain
	// This hook catches traffic coming FROM the namespace (entering the host via veth-host)
	// Priority -100 ensures it runs before standard routing decisions
	chainName := fmt.Sprintf("chain-%s", s.ID)
	if err := runCmd("nft", "add", "chain", "inet", tableName, chainName, "{ type nat hook prerouting priority -100; }"); err != nil {
		return fmt.Errorf("creating nft chain: %w", err)
	}

	// RULE 1: Redirect DNS (UDP 53) to Tor DNSPort
	// Matches only traffic coming from our specific host veth interface
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainName, 
		"iifname", s.VethHost, "udp", "dport", "53", "redirect", "to", fmt.Sprintf(":%d", s.Config.TorDNSPort)); err != nil {
		return fmt.Errorf("adding dns redirect rule: %w", err)
	}

	// RULE 2: Redirect TCP to Tor TransPort
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainName, 
		"iifname", s.VethHost, "meta", "l4proto", "tcp", "redirect", "to", fmt.Sprintf(":%d", s.Config.TorTransPort)); err != nil {
		return fmt.Errorf("adding tcp redirect rule: %w", err)
	}

	// RULE 3: DROP everything else from this interface
	// This ensures fail-closed behavior. No ICMP, no UDP leaks, no nothing else.
	if err := runCmd("nft", "add", "rule", "inet", tableName, chainName, 
		"iifname", s.VethHost, "drop"); err != nil {
		return fmt.Errorf("adding drop rule: %w", err)
	}

	return nil
}

// Run executes the command inside the namespace using 'nsenter'
// This is more robust than Go's syscall.Setns for multi-threaded programs (like Go itself)
// when launching external processes.
func (s *Sandbox) Run(bin string, args []string) error {
	// Look up binary path
	binPath, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}

	// Prepare nsenter arguments
	// --net: Join network namespace
	// --preserve-credentials: Keep root (or we could drop to user, but let's stay root inside NS for now as requested)
	nsParams := []string{
		"--net=/var/run/netns/" + s.Namespace,
		"--preserve-credentials", 
		binPath,
	}
	nsParams = append(nsParams, args...)

	cmd := exec.Command("nsenter", nsParams...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environment variables if needed
	cmd.Env = os.Environ()

	return cmd.Run()
}

// Teardown cleans up the namespace and firewall rules
func (s *Sandbox) Teardown() {
	if s.Config.Verbose {
		log.Printf("Tearing down sandbox %s...", s.ID)
	}

	// 1. Delete Network Namespace
	// This automatically removes the veth interfaces associated with it
	if err := runCmd("ip", "netns", "del", s.Namespace); err != nil {
		// Just log error, don't stop
		log.Printf("Warning: failed to delete netns: %v", err)
	}

	// 2. Remove NFTables Chain
	// We remove the specific chain for this ID to avoid disturbing other running sandboxes
	// If we were the only one, we could delete the table, but granular is better.
	tableName := "toralizer"
	chainName := fmt.Sprintf("chain-%s", s.ID)
	
	// Attempt to delete chain (and its rules)
	// Note: In nftables, you usually flush chain then delete chain, 
	// or delete table if it's the last one. 
	// For simplicity in this assignment, we leave the table structure but clear the chain.
	exec.Command("nft", "delete", "chain", "inet", tableName, chainName).Run()
}

// Helper to run shell commands
func runCmd(name string, args ...string) error {
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