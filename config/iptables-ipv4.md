this is an IP tables file taken from this [answer](https://stackoverflow.com/questions/27077414/how-to-channel-all-traffic-to-tor-on-linux)
- this file belongs to `/etc/iptables.firewall.rules`

```shell
# Ues the nat table to redirect some traffic to Tor

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# Don't allow Tor traffic to get stuck in a redirect loop...
# TODO: Is `tor' your actual Tor user? It might be `debian-tor' or `toranon' or something else.
-A OUTPUT -m owner --uid-owner tor -j RETURN

# Redirect DNS lookups to Tor.
# TODO: Set this to your Tor DNSPort if it's not 53530.
-A OUTPUT ! -o lo -p udp -m udp --dport 53 -j REDIRECT --to-ports 53530

# Do not redirect private networks or loopback.
-A OUTPUT -d 10.0.0.0/8 -j RETURN
-A OUTPUT -d 172.16.0.0/12 -j RETURN
-A OUTPUT -d 192.168.0.0/16 -j RETURN

# Redirect HS connections to the TransPort.
-A OUTPUT -d 127.192.0.0/10 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040

# Redirect all TCP traffic to Tor's TransPort.
-A OUTPUT ! -o lo -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040

COMMIT

# Only accept anonymized network traffic in the filter table.

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:LAN - [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow connections that are already established.
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Reject incoming connections.
-A INPUT -p udp -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
-A INPUT -j REJECT --reject-with icmp-port-unreachable

# Accept network traffic for the Tor service itself.
# TODO: Tor user?
-A OUTPUT -m owner --uid-owner tor -j ACCEPT

# Accept DNS requests to the Tor DNSPort.
-A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53530 -j ACCEPT

# Accept outgoing traffic to the local Tor TransPort.
-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 9040 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

# Accept outgoing traffic to the local Tor SOCKSPorts.
-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 9050 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT
-A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport 9150 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

# Accept connections on private networks.
-A OUTPUT -d 10.0.0.0/8 -j LAN
-A OUTPUT -d 172.16.0.0/12 -j LAN
-A OUTPUT -d 192.168.0.0/16 -j LAN
-A LAN -p tcp -m tcp --dport 53 -j REJECT --reject-with icmp-port-unreachable
-A LAN -p udp -m udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
-A LAN -j ACCEPT

# Reject all other outgoing traffic.
-A OUTPUT -j REJECT --reject-with icmp-port-unreachable

COMMIT
```
- to use these files on startup create file `/etc/network/if-pre-up.d/firewall

```shell
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
/sbin/ip6tables-restore < /etc/ip6tables.firewall.rules
```

FYI, tor may need to be restarted