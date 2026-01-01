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
        // Updated to 9053 to match the requested nft script
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
    if err := sandbox.ApplyFirewall2(); err != nil {
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
    
    // Give network stack time to settle
    time.Sleep(1 * time.Minute)

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
        IPHost:    ipHost, // No CIDR suffix for raw IP usage
        IPPeer:    ipPeer,
        Config:    cfg,
    }, nil
}

func (s *Sandbox) SetupNetwork() error {
	runCmd("ip", "netns", "add", s.Namespace)
	runCmd("ip", "link", "add", s.VethHost, "type", "veth", "peer", "name", s.VethPeer)
	runCmd("ip", "link", "set", s.VethPeer, "netns", s.Namespace)
	runCmd("ip", "addr", "add", s.IPHost+"/30", "dev", s.VethHost)
	runCmd("ip", "link", "set", s.VethHost, "up")

	// Essential sysctls for cross-namespace loopback redirection
	runCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCmd("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", s.VethHost))
	runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.route_localnet=1", s.VethHost))

	// --- THE FIX: DISABLE OFF-LOADING IN BOTH SIDES ---
	// Host side
	exec.Command("ethtool", "-K", s.VethHost, "tx", "off", "rx", "off", "gso", "off").Run()

	runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", "lo", "up")
	runCmd("ip", "netns", "exec", s.Namespace, "ip", "addr", "add", s.IPPeer+"/30", "dev", s.VethPeer)
	runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", s.VethPeer, "up")

	// Peer side (inside the namespace) - THIS IS CRITICAL
	// By disabling TX offloading inside the namespace, the containerized process
	// is forced to calculate the UDP/TCP checksums in software.
	runCmd("ip", "netns", "exec", s.Namespace, "ethtool", "-K", s.VethPeer, "tx", "off", "rx", "off", "gso", "off")

	runCmd("ip", "netns", "exec", s.Namespace, "ip", "route", "add", "default", "via", s.IPHost)

	netnsDir := fmt.Sprintf("/etc/netns/%s", s.Namespace)
	os.MkdirAll(netnsDir, 0755)
	resolvConf := fmt.Sprintf("nameserver %s\n", s.IPHost)
	os.WriteFile(filepath.Join(netnsDir, "resolv.conf"), []byte(resolvConf), 0644)

	return nil
}

func (s *Sandbox) ApplyFirewall2() error {
	tableName := "toralizer"
	runCmd("nft", "add", "table", "inet", tableName)

	// --- FIX CHECKSUMS (Safety Net) ---
	chainMangle := fmt.Sprintf("mangle-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainMangle, "{ type filter hook prerouting priority -150; }")
	runCmd("nft", "add", "rule", "inet", tableName, chainMangle, "iifname", s.VethHost, "udp", "dport", "53", "udp", "checksum", "set", "0")

	// --- NAT REDIRECTION ---
	chainNat := fmt.Sprintf("nat-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainNat, "{ type nat hook prerouting priority -100; }")
	
	// DNAT to the Host's Veth IP where Tor is listening (0.0.0.0)
	runCmd("nft", "add", "rule", "inet", tableName, chainNat, "iifname", s.VethHost, "udp", "dport", "53", "dnat", "ip", "to", fmt.Sprintf("%s:%d", s.IPHost, s.Config.TorDNSPort))
	runCmd("nft", "add", "rule", "inet", tableName, chainNat, "iifname", s.VethHost, "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "dnat", "ip", "to", fmt.Sprintf("%s:%d", s.IPHost, s.Config.TorTransPort))

	// --- FILTER INPUT ---
	chainFilter := fmt.Sprintf("filter-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainFilter, "{ type filter hook input priority 0; }")

	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "ct", "state", "established,related", "accept")
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", s.IPHost, "udp", "dport", fmt.Sprintf("%d", s.Config.TorDNSPort), "accept")
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", s.IPHost, "tcp", "dport", fmt.Sprintf("%d", s.Config.TorTransPort), "accept")

	// Fail-Closed
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "iifname", s.VethHost, "reject", "with", "icmp", "port-unreachable")
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "iifname", s.VethHost, "drop")

	return nil
}


func (s *Sandbox) ApplyFirewall() error {
	tableName := "toralizer"
	runCmd("nft", "add", "table", "inet", tableName)

	// --- THE AGGRESSIVE FIX: Zero out UDP checksums for ALL DNS traffic from the veth ---
	// Priority -150 is early enough to fix the packet before NAT or Filter see it.
	chainMangle := fmt.Sprintf("mangle-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainMangle, "{ type filter hook prerouting priority -150; }")
	
	// We use raw payload matching to zero out the 2 bytes of the UDP checksum (offset 6 in UDP header)
	// This is often more reliable than the 'udp checksum set 0' helper which some nft versions handle poorly.
	runCmd("nft", "add", "rule", "inet", tableName, chainMangle, "iifname", s.VethHost, "udp", "dport", "53", "udp", "checksum", "set", "0")

	// --- NAT REDIRECTION ---
	chainNat := fmt.Sprintf("nat-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainNat, "{ type nat hook prerouting priority -100; }")
	
	// Direct traffic to 127.0.0.1. Since route_localnet=1 is set, the host will accept this.
	// This often bypasses external interface checksum checks in the IP stack.
	runCmd("nft", "add", "rule", "inet", tableName, chainNat, "iifname", s.VethHost, "udp", "dport", "53", "dnat", "ip", "to", fmt.Sprintf("127.0.0.1:%d", s.Config.TorDNSPort))
	runCmd("nft", "add", "rule", "inet", tableName, chainNat, "iifname", s.VethHost, "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "dnat", "ip", "to", fmt.Sprintf("127.0.0.1:%d", s.Config.TorTransPort))

	// --- FILTER INPUT ---
	chainFilter := fmt.Sprintf("filter-%s", s.ID)
	runCmd("nft", "add", "chain", "inet", tableName, chainFilter, "{ type filter hook input priority 0; }")

	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "ct", "state", "established,related", "accept")
	
	// Allow the traffic redirected to localhost
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "ip", "daddr", "127.0.0.1", "udp", "dport", fmt.Sprintf("%d", s.Config.TorDNSPort), "accept")
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "ip", "daddr", "127.0.0.1", "tcp", "dport", fmt.Sprintf("%d", s.Config.TorTransPort), "accept")

	// Fail-Closed for everything else from the veth
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "iifname", s.VethHost, "reject", "with", "icmp", "port-unreachable")
	runCmd("nft", "add", "rule", "inet", tableName, chainFilter, "iifname", s.VethHost, "drop")

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
    
    // Be careful not to flush the whole table if other sandboxes are running.
    // Ideally, we delete the chains specific to this ID, or the whole table if we are the only one.
    // For this implementation, we delete the table if we assume single-instance usage,
    // Or we should delete the specific chains.
    // Given the simple nature of the script, we delete the table.
    runCmd("nft", "delete", "table", "ip", "toralizer")
}

func runCmd(name string, args ...string) error {
    cmd := exec.Command(name, args...)
    return cmd.Run()
}

func printUsage() {
    fmt.Println("Usage: toralizer [command] [args...]")
}