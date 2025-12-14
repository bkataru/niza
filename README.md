# niza

**Cross-Platform Network Interface Library & CLI for Zig**

[![Zig](https://img.shields.io/badge/Zig-0.15.2-orange)](https://ziglang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Niza is a pure Zig library and command-line tool for retrieving network interface information. It uses native OS APIs—no subprocess spawning—for fast, reliable interface enumeration across Linux, Windows, macOS, and BSD systems.

## Features

- 🚀 **Native OS APIs** - No subprocess spawning (no `ifconfig`/`ipconfig` calls)
- 🌍 **Cross-Platform** - Linux, Windows, macOS, FreeBSD, NetBSD, OpenBSD, DragonFlyBSD
- 📦 **Dual-Purpose** - Use as a library in your Zig projects or as a CLI tool
- 🎨 **Beautiful CLI** - Colorized output with multiple display modes
- 📋 **JSON Output** - Machine-readable output for scripting
- 🔒 **Zero Dependencies** - Pure Zig, no external Zig/C libraries required
- 🧪 **Well Tested** - Comprehensive unit and integration tests across platforms

## Installation

### As a Zig Package Dependency

Add niza to your `build.zig.zon`:

```zig
.dependencies = .{
    .niza = .{
        .url = "https://github.com/bkataru/niza/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

Alternatively, you can also add niza using `zig fetch`
```shell
zig fetch --save git+https://github.com/bkataru/niza.git
```

Then in your `build.zig`:

```zig
const niza = b.dependency("niza", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("niza", niza.module("niza"));
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/bkataru/niza.git
cd niza

# Build the CLI
zig build

# Run tests
zig build test

# Install to zig-out/bin
zig build -Doptimize=ReleaseFast
```

## CLI Usage

```
niza [OPTIONS]

OPTIONS:
    -h, --help      Show help message
    -a, --all       Show all interfaces (including inactive)
    -6, --ipv6      Show IPv6 addresses
    -m, --mac       Show MAC addresses
    -j, --json      Output in JSON format
    -q, --quiet     Quiet mode (minimal output)
    -v, --version   Show version information
    --no-color      Disable colored output
```

### Examples

```bash
# Show active interfaces with IPv4 addresses
niza

# Show all interfaces including inactive ones
niza --all

# Show all details including IPv6 and MAC addresses
niza -a -6 -m

# Output as JSON for scripting
niza --json

# Quiet mode - just interface names and IPs
niza -q

# Pipe to other tools
niza --json | jq '.interfaces[] | select(.status == "up")'
```

### Sample Output

```
╔══════════════════════════════════════════╗
║     niza - Network Interface Info        ║
╚══════════════════════════════════════════╝

● eth0 [up]
  IPv4:  192.168.1.100

● wlan0 [up]
  IPv4:  192.168.1.101

○ docker0 [down]
  IPv4:  172.17.0.1

─────────────────────────────────────────────
Displayed 3 interface(s), 2 active
```

### JSON Output

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "index": 2,
      "status": "up",
      "is_loopback": false,
      "ipv4": "192.168.1.100",
      "ipv6": "2001:db8::1",
      "mac": "00:1a:2b:3c:4d:5e",
      "netmask": null
    }
  ],
  "count": 1
}
```

## Library Usage

### Basic Example

```zig
const std = @import("std");
const niza = @import("niza");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get all network interfaces
    const interfaces = try niza.getNetworkInterfaces(allocator);
    defer niza.freeNetworkInterfaces(allocator, interfaces);

    for (interfaces) |iface| {
        std.debug.print("Interface: {s}\n", .{iface.name});
        std.debug.print("  Status: {s}\n", .{iface.status.toString()});
        
        if (iface.ipv4) |ip| {
            std.debug.print("  IPv4: {s}\n", .{ip});
        }
        
        if (iface.ipv6) |ip| {
            std.debug.print("  IPv6: {s}\n", .{ip});
        }
        
        if (iface.mac) |mac| {
            std.debug.print("  MAC: {s}\n", .{mac});
        }
    }
}
```

### API Reference

#### Types

##### `NetworkInterface`

Represents a network interface with its associated addresses and status.

```zig
pub const NetworkInterface = struct {
    /// Name of the interface (e.g., "eth0", "wlan0", "Ethernet")
    name: []const u8,
    
    /// IPv4 address in dotted-decimal notation, or null if not assigned
    ipv4: ?[]const u8,
    
    /// IPv6 address in colon-separated notation, or null if not assigned
    ipv6: ?[]const u8,
    
    /// MAC/hardware address in colon-separated notation, or null if not available
    mac: ?[]const u8,
    
    /// Subnet mask in dotted-decimal notation, or null if not available
    netmask: ?[]const u8,
    
    /// Operational status of the interface
    status: InterfaceStatus,
    
    /// Interface index (platform-specific identifier)
    index: u32,
    
    /// Whether this is a loopback interface
    is_loopback: bool,
};
```

##### `InterfaceStatus`

```zig
pub const InterfaceStatus = enum {
    up,      // Interface is active and operational
    down,    // Interface is down or not operational
    unknown, // Status could not be determined
    
    pub fn toString(self: InterfaceStatus) []const u8;
};
```

##### `NetworkError`

```zig
pub const NetworkError = error{
    SocketCreationFailed,
    IoctlFailed,
    AllocationFailed,
    InvalidData,
    UnsupportedPlatform,
    NetlinkSendFailed,
    NetlinkRecvFailed,
    WindowsApiError,
    SystemError,
    OutOfMemory,
};
```

#### Functions

##### `getNetworkInterfaces`

```zig
pub fn getNetworkInterfaces(allocator: Allocator) NetworkError![]NetworkInterface
```

Retrieves all network interfaces on the system using native OS APIs.

**Returns:** A slice of `NetworkInterface` structs that must be freed with `freeNetworkInterfaces`.

**Errors:**
- `SocketCreationFailed`: Could not create socket for querying
- `UnsupportedPlatform`: Current OS is not supported
- `OutOfMemory`: Memory allocation failed

##### `freeNetworkInterfaces`

```zig
pub fn freeNetworkInterfaces(allocator: Allocator, interfaces: []NetworkInterface) void
```

Frees a slice of network interfaces previously allocated by `getNetworkInterfaces`.

#### Utility Functions

```zig
/// Formats an IPv4 address from 4 bytes to a string
pub fn formatIpv4Address(allocator: Allocator, addr: [4]u8) ![]const u8

/// Formats an IPv6 address from 16 bytes to a string
pub fn formatIpv6Address(allocator: Allocator, addr: [16]u8) ![]const u8

/// Formats a MAC address from 6 bytes to a colon-separated string
pub fn formatMacAddress(allocator: Allocator, addr: [6]u8) ![]const u8

/// Checks if an IPv4 address is a loopback address (127.x.x.x)
pub fn isLoopbackIpv4(addr: [4]u8) bool

/// Checks if an IPv6 address is the loopback address (::1)
pub fn isLoopbackIpv6(addr: [16]u8) bool

/// Checks if an IPv6 address is link-local (fe80::)
pub fn isLinkLocalIpv6(addr: [16]u8) bool
```

## Platform-Specific Implementation Details

### Linux

Uses **Netlink sockets** (`NETLINK_ROUTE`) with `RTM_GETLINK` and `RTM_GETADDR` messages to enumerate interfaces and addresses. This is the most reliable and efficient method on Linux.

### Windows

Uses the **IP Helper API** (`GetAdaptersAddresses` from `iphlpapi.dll`) to enumerate network adapters and their addresses. Supports both IPv4 and IPv6.

### macOS / BSD

Uses the **`getifaddrs()`** system call via libc to enumerate interfaces. This works on macOS, FreeBSD, NetBSD, OpenBSD, and DragonFlyBSD.

## Building for Different Platforms

```bash
# Native build
zig build

# Cross-compile for Linux x86_64
zig build -Dtarget=x86_64-linux

# Cross-compile for Windows x86_64
zig build -Dtarget=x86_64-windows

# Cross-compile for macOS ARM64
zig build -Dtarget=aarch64-macos

# Release build with optimizations
zig build -Doptimize=ReleaseFast
```

## Running Tests

```bash
# Run all tests
zig build test

# Run tests with verbose output
zig build test -- --verbose

# Run only library tests
zig test src/root.zig

# Run only CLI tests
zig test src/main.zig
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE) file for details.
