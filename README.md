# Wirecrab

Monitor outgoing network requests in your terminal.

![example](/static/ex1.png)

Wirecrab currently supports IPv4 and IPv6 over Ethernet frames.


### Usage
To run Wirecrab:

```
cargo run
```

Wirecrab uses `libpcap` as the packet capture interface. MacOS comes with `libpcap` preinstalled. Linux users should install `libpcap` through their respective package manager.

**Note: Windows is not yet supported.**


### Roadmap
- [ ] Listen on all network interfaces
- [ ] Resolve IP reverse lookups with the DNS traffic capture
- [ ] Clean up terminal UI