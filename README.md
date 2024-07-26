# Wirecrab

Monitor outgoing network requests in your terminal with built-in DNS resolution.

![example](/static/ex3.png)

Wirecrab currently supports IPv4 and IPv6 over Ethernet frames.


### Installation

 Mac users:
```
brew tap kevinl10/wirecrab
brew install wirecrab
```

To run Wirecrab directly:

```
cargo run
```

Wirecrab uses `libpcap` as the packet capture interface. MacOS comes with `libpcap` preinstalled. Linux users should install `libpcap` through their respective package manager.

**Note: Windows is not yet supported.**


### Roadmap
- [x] Resolve IP reverse lookups with the DNS traffic capture
- [x] Handle AAAA records
- [ ] Resolve CNAME results
- [ ] debug mode
- [ ] Listen on all network interfaces
- [ ] Clean up terminal UI
- [ ] Use local DNS server
- [ ] Add option to flush system and browser DNS