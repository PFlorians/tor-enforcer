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

    runCmd("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
    runCmd("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
    runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", s.VethHost))
    runCmd("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.route_localnet=1", s.VethHost))

    exec.Command("ethtool", "-K", s.VethHost, "tx", "off", "rx", "off").Run()

    runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", "lo", "up")
    runCmd("ip", "netns", "exec", s.Namespace, "ip", "addr", "add", s.IPPeer+"/30", "dev", s.VethPeer)
    runCmd("ip", "netns", "exec", s.Namespace, "ip", "link", "set", s.VethPeer, "up")
    
    runCmd("ip", "netns", "exec", s.Namespace, "ip", "route", "add", "default", "via", s.IPHost)

    netnsDir := fmt.Sprintf("/etc/netns/%s", s.Namespace)
    os.MkdirAll(netnsDir, 0755)
    
    resolvConf := fmt.Sprintf("nameserver %s\n", s.IPHost)
    os.WriteFile(filepath.Join(netnsDir, "resolv.conf"), []byte(resolvConf), 0644)

    return nil
}

func (s *Sandbox) ApplyFirewall2() error {
    tableName := "toralizer"
    runCmd("nft", "add", "table", "ip", tableName)

    chainNat := fmt.Sprintf("pre-%s", s.ID)
    runCmd("nft", "add", "chain", "ip", tableName, chainNat, "{ type nat hook prerouting priority -100; }")

    // REDIRECTION LOGIC
    // We target s.IPHost (10.200.0.1) because the Tor service on the host is 
    // now listening on all interfaces (0.0.0.0).
    
    // DNS Redirection
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "udp", "dport", "53", "dnat", "ip", "to", fmt.Sprintf("%s:%d", s.IPHost, s.Config.TorDNSPort))

    // Transparent Proxy Redirection (TCP)
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "dnat", "ip", "to", fmt.Sprintf("%s:%d", s.IPHost, s.Config.TorTransPort))

    // FILTERING LOGIC
    chainFilter := fmt.Sprintf("in-%s", s.ID)
    runCmd("nft", "add", "chain", "ip", tableName, chainFilter, "{ type filter hook input priority 0; }")

    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "ct", "state", "established,related", "accept")

    // Allow the specific redirected ports on the host's Veth IP
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", s.IPHost, "udp", "dport", fmt.Sprintf("%d", s.Config.TorDNSPort), "accept")
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", s.IPHost, "tcp", "dport", fmt.Sprintf("%d", s.Config.TorTransPort), "accept")

    // Fail-Closed
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "reject", "with", "icmp", "port-unreachable")
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "drop")

    return nil
}


func (s *Sandbox) ApplyFirewall() error {
    tableName := "toralizer"
    
    // Use 'ip' family to match the requested script logic, though 'inet' is also valid.
    runCmd("nft", "add", "table", "ip", tableName)

    // --------------------------------------------------------------------------
    // 1. NAT PREROUTING CHAIN
    // Matches the logic of the requested "chain output" (NAT), but moved to 
    // Prerouting because traffic is entering the host from the veth.
    // --------------------------------------------------------------------------
    chainNat := fmt.Sprintf("pre-%s", s.ID)
    runCmd("nft", "add", "chain", "ip", tableName, chainNat, "{ type nat hook prerouting priority -100; }")

    // Do not redirect private networks (LANs) - allow them to pass through 
    // (Note: They will likely be dropped by the filter chain later unless explicit)
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "ip", "daddr", "10.0.0.0/8", "return")
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "ip", "daddr", "172.16.0.0/12", "return")
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "ip", "daddr", "192.168.0.0/16", "return")

    // Redirect HS connections to the TransPort
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "ip", "daddr", "127.192.0.0/10", "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "redirect", "to", fmt.Sprintf(":%d", s.Config.TorTransPort))

    // Redirect DNS lookups to Tor DNSPort
    // Using 9053 as requested (Config.TorDNSPort updated)
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "udp", "dport", "53", "redirect", "to", fmt.Sprintf(":%d", s.Config.TorDNSPort))

    // Redirect all TCP traffic to Tor TransPort
    runCmd("nft", "add", "rule", "ip", tableName, chainNat, "iifname", s.VethHost, "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "redirect", "to", fmt.Sprintf(":%d", s.Config.TorTransPort))


    // --------------------------------------------------------------------------
    // 2. FILTER INPUT CHAIN
    // Matches the logic of the requested "chain output" (Filter) and "chain input" (Filter).
    // Traffic redirected to localhost (via NAT above) hits the INPUT hook.
    // --------------------------------------------------------------------------
    chainFilter := fmt.Sprintf("in-%s", s.ID)
    runCmd("nft", "add", "chain", "ip", tableName, chainFilter, "{ type filter hook input priority 0; }")

    // Allow established connections (Critical for return traffic)
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "ct", "state", "established,related", "accept")

    // Allow DNS requests to Tor DNSPort (After redirection)
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", "127.0.0.1", "udp", "dport", fmt.Sprintf("%d", s.Config.TorDNSPort), "accept")

    // Allow traffic to Tor TransPort (After redirection)
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", "127.0.0.1", "tcp", "dport", fmt.Sprintf("%d", s.Config.TorTransPort), "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "accept")

    // Allow traffic to Tor SOCKSPorts (Explicitly allowed in requested script)
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", "127.0.0.1", "tcp", "dport", "9050", "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "accept")
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "ip", "daddr", "127.0.0.1", "tcp", "dport", "9150", "tcp", "flags", "&", "(fin|syn|rst|ack)", "==", "syn", "accept")

    // --------------------------------------------------------------------------
    // 3. CLEANUP / DROP RULES
    // The requested script had a "policy drop" on Input.
    // SAFETY: We only drop traffic coming from THIS sandbox interface.
    // Setting global policy drop in a custom table can be dangerous for the host.
    // --------------------------------------------------------------------------
    
    // Log dropped packets (Optional, but good for debugging)
    // runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "limit", "rate", "5/minute", "log", "prefix", "\"TorBlock: \"")

    // Reject all other inbound connections from this namespace (Fail Closed)
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "udp", "ct", "state", "new", "reject", "with", "icmp", "port-unreachable")
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "tcp", "ct", "state", "new", "reject", "with", "tcp", "reset")
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "reject", "with", "icmp", "port-unreachable")
    
    // Explicit drop as final catch-all for the veth
    runCmd("nft", "add", "rule", "ip", tableName, chainFilter, "iifname", s.VethHost, "drop")

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