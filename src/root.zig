//! # Niza - Cross-Platform Network Interface Library
//!
//! A pure Zig library for retrieving network interface information without spawning
//! external processes. Supports Linux, Windows, macOS, and BSD systems.
//!
//! ## Features
//!
//! - Native OS API calls (no subprocess spawning)
//! - Cross-platform support (Linux, Windows, macOS, BSD)
//! - IPv4 and IPv6 address retrieval
//! - MAC address retrieval
//! - Interface status detection
//! - Zero external dependencies
//!
//! ## Usage
//!
//! ```zig
//! const niza = @import("niza");
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     defer _ = gpa.deinit();
//!     const allocator = gpa.allocator();
//!
//!     const interfaces = try niza.getNetworkInterfaces(allocator);
//!     defer niza.freeNetworkInterfaces(allocator, interfaces);
//!
//!     for (interfaces) |iface| {
//!         std.debug.print("Interface: {s}\n", .{iface.name});
//!         if (iface.ipv4) |ip| std.debug.print("  IPv4: {s}\n", .{ip});
//!         if (iface.ipv6) |ip| std.debug.print("  IPv6: {s}\n", .{ip});
//!     }
//! }
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

/// Maximum length for interface names across all platforms
pub const MAX_INTERFACE_NAME_LEN = 256;

/// Maximum length for formatted IP addresses
pub const MAX_IP_ADDR_LEN = 64;

/// Maximum length for formatted MAC addresses (XX:XX:XX:XX:XX:XX + null)
pub const MAX_MAC_ADDR_LEN = 18;

/// Represents the operational status of a network interface
pub const InterfaceStatus = enum {
    /// Interface is active and operational
    up,
    /// Interface is down or not operational
    down,
    /// Status could not be determined
    unknown,

    /// Returns a human-readable string representation of the status
    pub fn toString(self: InterfaceStatus) []const u8 {
        return switch (self) {
            .up => "up",
            .down => "down",
            .unknown => "unknown",
        };
    }
};

/// Represents a network interface with its associated addresses and status
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

    /// Creates a deep copy of the interface
    pub fn clone(self: NetworkInterface, allocator: Allocator) !NetworkInterface {
        return NetworkInterface{
            .name = try allocator.dupe(u8, self.name),
            .ipv4 = if (self.ipv4) |ip| try allocator.dupe(u8, ip) else null,
            .ipv6 = if (self.ipv6) |ip| try allocator.dupe(u8, ip) else null,
            .mac = if (self.mac) |m| try allocator.dupe(u8, m) else null,
            .netmask = if (self.netmask) |nm| try allocator.dupe(u8, nm) else null,
            .status = self.status,
            .index = self.index,
            .is_loopback = self.is_loopback,
        };
    }

    /// Frees all memory associated with this interface
    pub fn deinit(self: *NetworkInterface, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.ipv4) |ip| allocator.free(ip);
        if (self.ipv6) |ip| allocator.free(ip);
        if (self.mac) |m| allocator.free(m);
        if (self.netmask) |nm| allocator.free(nm);
    }
};

/// Error types that can occur during network interface retrieval
pub const NetworkError = error{
    /// Failed to create a socket for querying interfaces
    SocketCreationFailed,
    /// The ioctl or similar system call failed
    IoctlFailed,
    /// Failed to allocate memory for interface data
    AllocationFailed,
    /// The system returned invalid or malformed data
    InvalidData,
    /// The operation is not supported on this platform
    UnsupportedPlatform,
    /// Failed to send netlink message
    NetlinkSendFailed,
    /// Failed to receive netlink message
    NetlinkRecvFailed,
    /// Windows-specific API error
    WindowsApiError,
    /// Generic system error
    SystemError,
    /// Out of memory
    OutOfMemory,
};

/// Retrieves all network interfaces on the system.
///
/// This function uses native OS APIs to enumerate network interfaces:
/// - **Linux**: Uses Netlink sockets (NETLINK_ROUTE)
/// - **Windows**: Uses GetAdaptersAddresses from iphlpapi.dll
/// - **macOS/BSD**: Uses getifaddrs from libc
///
/// The returned slice must be freed by calling `freeNetworkInterfaces`.
///
/// ## Example
/// ```zig
/// const interfaces = try niza.getNetworkInterfaces(allocator);
/// defer niza.freeNetworkInterfaces(allocator, interfaces);
/// ```
///
/// ## Errors
/// - `SocketCreationFailed`: Could not create socket for querying
/// - `AllocationFailed`: Memory allocation failed
/// - `SystemError`: OS-level error occurred
pub fn getNetworkInterfaces(allocator: Allocator) NetworkError![]NetworkInterface {
    return switch (builtin.os.tag) {
        .linux => getNetworkInterfacesLinux(allocator),
        .windows => getNetworkInterfacesWindows(allocator),
        .macos, .freebsd, .netbsd, .openbsd, .dragonfly => getNetworkInterfacesBsd(allocator),
        else => NetworkError.UnsupportedPlatform,
    };
}

/// Frees a slice of network interfaces previously allocated by `getNetworkInterfaces`.
///
/// ## Example
/// ```zig
/// const interfaces = try niza.getNetworkInterfaces(allocator);
/// defer niza.freeNetworkInterfaces(allocator, interfaces);
/// ```
pub fn freeNetworkInterfaces(allocator: Allocator, interfaces: []NetworkInterface) void {
    for (interfaces) |*iface| {
        iface.deinit(allocator);
    }
    allocator.free(interfaces);
}

/// Formats an IPv4 address from 4 bytes to a string.
///
/// ## Example
/// ```zig
/// const addr = [4]u8{ 192, 168, 1, 1 };
/// const str = try formatIpv4Address(allocator, addr);
/// // str = "192.168.1.1"
/// ```
pub fn formatIpv4Address(allocator: Allocator, addr: [4]u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
}

/// Formats an IPv6 address from 16 bytes to a string.
///
/// The output uses the standard colon-separated hexadecimal notation.
pub fn formatIpv6Address(allocator: Allocator, addr: [16]u8) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (i > 0) {
            try result.append(allocator, ':');
        }
        const high = addr[i];
        const low = addr[i + 1];
        const value = (@as(u16, high) << 8) | @as(u16, low);
        try result.writer(allocator).print("{x}", .{value});
    }

    return result.toOwnedSlice(allocator);
}

/// Formats a MAC address from 6 bytes to a colon-separated string.
///
/// ## Example
/// ```zig
/// const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
/// const str = try formatMacAddress(allocator, mac);
/// // str = "aa:bb:cc:dd:ee:ff"
/// ```
pub fn formatMacAddress(allocator: Allocator, addr: [6]u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
    });
}

/// Checks if an IPv4 address is a loopback address (127.x.x.x)
pub fn isLoopbackIpv4(addr: [4]u8) bool {
    return addr[0] == 127;
}

/// Checks if an IPv6 address is the loopback address (::1)
pub fn isLoopbackIpv6(addr: [16]u8) bool {
    for (addr[0..15]) |byte| {
        if (byte != 0) return false;
    }
    return addr[15] == 1;
}

/// Checks if an IPv6 address is link-local (fe80::)
pub fn isLinkLocalIpv6(addr: [16]u8) bool {
    return addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80;
}

// =============================================================================
// Linux Implementation using Netlink
// =============================================================================

fn getNetworkInterfacesLinux(allocator: Allocator) NetworkError![]NetworkInterface {
    const linux = std.os.linux;
    const posix = std.posix;

    // Create netlink socket
    const sock = posix.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC,
        linux.NETLINK.ROUTE,
    ) catch return NetworkError.SocketCreationFailed;
    defer posix.close(sock);

    // Bind the socket
    var local_addr = linux.sockaddr.nl{
        .family = linux.AF.NETLINK,
        .pid = 0,
        .groups = 0,
    };
    posix.bind(sock, @ptrCast(&local_addr), @sizeOf(linux.sockaddr.nl)) catch return NetworkError.SocketCreationFailed;

    // Interface map: index -> interface info
    var interface_map: std.AutoHashMapUnmanaged(u32, InterfaceInfo) = .empty;
    defer {
        var it = interface_map.valueIterator();
        while (it.next()) |info| {
            if (info.name) |n| allocator.free(n);
            if (info.mac) |m| allocator.free(m);
            if (info.ipv4) |ip| allocator.free(ip);
            if (info.ipv6) |ip| allocator.free(ip);
            if (info.netmask) |nm| allocator.free(nm);
        }
        interface_map.deinit(allocator);
    }

    // Request link information (interface names, MAC, status)
    try sendNetlinkRequest(sock, linux.NetlinkMessageType.RTM_GETLINK, linux.AF.UNSPEC);
    try receiveNetlinkResponses(allocator, sock, &interface_map, .link);

    // Request IPv4 addresses
    try sendNetlinkRequest(sock, linux.NetlinkMessageType.RTM_GETADDR, linux.AF.INET);
    try receiveNetlinkResponses(allocator, sock, &interface_map, .ipv4);

    // Request IPv6 addresses
    try sendNetlinkRequest(sock, linux.NetlinkMessageType.RTM_GETADDR, linux.AF.INET6);
    try receiveNetlinkResponses(allocator, sock, &interface_map, .ipv6);

    // Convert map to slice
    var result: std.ArrayListUnmanaged(NetworkInterface) = .empty;
    errdefer {
        for (result.items) |*iface| {
            iface.deinit(allocator);
        }
        result.deinit(allocator);
    }

    var it = interface_map.iterator();
    while (it.next()) |entry| {
        const info = entry.value_ptr;
        if (info.name) |name| {
            const iface = NetworkInterface{
                .name = try allocator.dupe(u8, name),
                .ipv4 = if (info.ipv4) |ip| try allocator.dupe(u8, ip) else null,
                .ipv6 = if (info.ipv6) |ip| try allocator.dupe(u8, ip) else null,
                .mac = if (info.mac) |m| try allocator.dupe(u8, m) else null,
                .netmask = if (info.netmask) |nm| try allocator.dupe(u8, nm) else null,
                .status = info.status,
                .index = entry.key_ptr.*,
                .is_loopback = info.is_loopback,
            };
            try result.append(allocator, iface);
        }
    }

    return result.toOwnedSlice(allocator) catch return NetworkError.OutOfMemory;
}

const InterfaceInfo = struct {
    name: ?[]const u8 = null,
    mac: ?[]const u8 = null,
    ipv4: ?[]const u8 = null,
    ipv6: ?[]const u8 = null,
    netmask: ?[]const u8 = null,
    status: InterfaceStatus = .unknown,
    is_loopback: bool = false,
};

const ParseMode = enum {
    link,
    ipv4,
    ipv6,
};

fn sendNetlinkRequest(sock: std.posix.socket_t, msg_type: std.os.linux.NetlinkMessageType, family: u8) NetworkError!void {
    const linux = std.os.linux;

    const NlReq = extern struct {
        hdr: linux.nlmsghdr,
        gen: extern struct {
            family: u8,
            pad: u8 = 0,
            pad2: u16 = 0,
        },
    };

    var req = NlReq{
        .hdr = .{
            .len = @sizeOf(NlReq),
            .type = msg_type,
            .flags = linux.NLM_F_REQUEST | linux.NLM_F_DUMP,
            .seq = 1,
            .pid = 0,
        },
        .gen = .{
            .family = family,
        },
    };

    var dest_addr = linux.sockaddr.nl{
        .family = linux.AF.NETLINK,
        .pid = 0,
        .groups = 0,
    };

    const iov = [_]std.posix.iovec_const{
        .{
            .base = @ptrCast(&req),
            .len = @sizeOf(NlReq),
        },
    };

    const msg = std.posix.msghdr_const{
        .name = @ptrCast(&dest_addr),
        .namelen = @sizeOf(linux.sockaddr.nl),
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    _ = std.posix.sendmsg(sock, &msg, 0) catch return NetworkError.NetlinkSendFailed;
}

fn receiveNetlinkResponses(
    allocator: Allocator,
    sock: std.posix.socket_t,
    interface_map: *std.AutoHashMapUnmanaged(u32, InterfaceInfo),
    mode: ParseMode,
) NetworkError!void {
    const linux = std.os.linux;

    var buf: [16384]u8 = undefined;

    while (true) {
        const len = std.posix.recv(sock, &buf, 0) catch return NetworkError.NetlinkRecvFailed;
        if (len == 0) break;

        var offset: usize = 0;
        while (offset < len) {
            if (offset + @sizeOf(linux.nlmsghdr) > len) break;

            const nlh: *align(1) const linux.nlmsghdr = @ptrCast(@alignCast(&buf[offset]));

            if (nlh.type == .DONE) {
                return;
            }

            if (nlh.type == .ERROR) {
                return NetworkError.NetlinkRecvFailed;
            }

            if (nlh.type == .RTM_NEWLINK) {
                try parseNewLink(allocator, &buf, offset, nlh.len, interface_map);
            } else if (nlh.type == .RTM_NEWADDR) {
                try parseNewAddr(allocator, &buf, offset, nlh.len, interface_map, mode);
            }

            // Move to next message (aligned)
            const aligned_len = (nlh.len + 3) & ~@as(u32, 3);
            offset += aligned_len;
        }
    }
}

fn parseNewLink(
    allocator: Allocator,
    buf: []const u8,
    offset: usize,
    msg_len: u32,
    interface_map: *std.AutoHashMapUnmanaged(u32, InterfaceInfo),
) NetworkError!void {
    const linux = std.os.linux;

    const hdr_size = @sizeOf(linux.nlmsghdr);
    const ifi_size = @sizeOf(linux.ifinfomsg);

    if (offset + hdr_size + ifi_size > buf.len) return;

    const ifi: *align(1) const linux.ifinfomsg = @ptrCast(@alignCast(&buf[offset + hdr_size]));
    const if_index: u32 = @intCast(ifi.index);

    var info = interface_map.get(if_index) orelse InterfaceInfo{};

    // Check interface flags
    const IFF_UP: c_uint = 0x1;
    const IFF_LOOPBACK: c_uint = 0x8;
    info.is_loopback = (ifi.flags & IFF_LOOPBACK) != 0;
    info.status = if ((ifi.flags & IFF_UP) != 0) InterfaceStatus.up else InterfaceStatus.down;

    // Parse attributes
    var attr_offset = offset + hdr_size + ifi_size;
    const end_offset = offset + msg_len;

    while (attr_offset + 4 <= end_offset) {
        const rta: *align(1) const linux.rtattr = @ptrCast(@alignCast(&buf[attr_offset]));
        if (rta.len < 4) break;

        const data_offset = attr_offset + 4;
        const data_len = rta.len - 4;

        if (rta.type.link == .IFNAME and data_len > 0) {
            // Find null terminator
            var name_len: usize = 0;
            while (name_len < data_len and buf[data_offset + name_len] != 0) {
                name_len += 1;
            }
            if (info.name) |old| allocator.free(old);
            info.name = allocator.dupe(u8, buf[data_offset..][0..name_len]) catch return NetworkError.OutOfMemory;
        } else if (rta.type.link == .ADDRESS and data_len == 6) {
            // MAC address
            const mac_bytes: [6]u8 = buf[data_offset..][0..6].*;
            // Check if it's not all zeros
            var is_valid = false;
            for (mac_bytes) |b| {
                if (b != 0) {
                    is_valid = true;
                    break;
                }
            }
            if (is_valid) {
                if (info.mac) |old| allocator.free(old);
                info.mac = formatMacAddress(allocator, mac_bytes) catch return NetworkError.OutOfMemory;
            }
        }

        // Move to next attribute (aligned to 4 bytes)
        const aligned_len = (rta.len + 3) & ~@as(c_ushort, 3);
        attr_offset += aligned_len;
    }

    interface_map.put(allocator, if_index, info) catch return NetworkError.OutOfMemory;
}

fn parseNewAddr(
    allocator: Allocator,
    buf: []const u8,
    offset: usize,
    msg_len: u32,
    interface_map: *std.AutoHashMapUnmanaged(u32, InterfaceInfo),
    mode: ParseMode,
) NetworkError!void {
    const linux = std.os.linux;

    const hdr_size = @sizeOf(linux.nlmsghdr);

    // ifaddrmsg structure
    const IfAddrMsg = extern struct {
        family: u8,
        prefixlen: u8,
        flags: u8,
        scope: u8,
        index: u32,
    };
    const ifa_size = @sizeOf(IfAddrMsg);

    if (offset + hdr_size + ifa_size > buf.len) return;

    const ifa: *align(1) const IfAddrMsg = @ptrCast(@alignCast(&buf[offset + hdr_size]));
    const if_index = ifa.index;

    var info = interface_map.get(if_index) orelse InterfaceInfo{};

    // Parse attributes
    var attr_offset = offset + hdr_size + ifa_size;
    const end_offset = offset + msg_len;

    while (attr_offset + 4 <= end_offset) {
        const rta: *align(1) const linux.rtattr = @ptrCast(@alignCast(&buf[attr_offset]));
        if (rta.len < 4) break;

        const data_offset = attr_offset + 4;
        const data_len = rta.len - 4;

        // Prefer IFA_LOCAL for IPv4, IFA_ADDRESS for IPv6
        if ((rta.type.addr == .LOCAL or rta.type.addr == .ADDRESS) and mode == .ipv4 and data_len >= 4) {
            const addr_bytes: [4]u8 = buf[data_offset..][0..4].*;
            if (info.ipv4 == null) {
                info.ipv4 = formatIpv4Address(allocator, addr_bytes) catch return NetworkError.OutOfMemory;
            }
        } else if (rta.type.addr == .ADDRESS and mode == .ipv6 and data_len >= 16) {
            const addr_bytes: [16]u8 = buf[data_offset..][0..16].*;
            // Skip link-local addresses for main display, but store if no other
            if (!isLinkLocalIpv6(addr_bytes) or info.ipv6 == null) {
                if (info.ipv6) |old| allocator.free(old);
                info.ipv6 = formatIpv6Address(allocator, addr_bytes) catch return NetworkError.OutOfMemory;
            }
        }

        const aligned_len = (rta.len + 3) & ~@as(c_ushort, 3);
        attr_offset += aligned_len;
    }

    interface_map.put(allocator, if_index, info) catch return NetworkError.OutOfMemory;
}

// =============================================================================
// Windows Implementation using GetAdaptersAddresses
// =============================================================================

// Windows API types - defined at module level for self-referential struct support
const win_types = if (builtin.os.tag == .windows) struct {
    const windows = std.os.windows;
    const ULONG = windows.ULONG;
    const DWORD = windows.DWORD;
    const WCHAR = windows.WCHAR;
    const BYTE = u8;
    const CHAR = u8;

    const AF_UNSPEC: ULONG = 0;
    const GAA_FLAG_INCLUDE_PREFIX: ULONG = 0x0010;
    const ERROR_BUFFER_OVERFLOW: ULONG = 111;
    const ERROR_SUCCESS: ULONG = 0;

    const MAX_ADAPTER_NAME_LENGTH = 256;
    const MAX_ADAPTER_ADDRESS_LENGTH = 8;

    const SOCKET_ADDRESS = extern struct {
        lpSockaddr: ?*anyopaque,
        iSockaddrLength: c_int,
    };

    const IP_ADAPTER_UNICAST_ADDRESS = extern struct {
        length: ULONG,
        flags: DWORD,
        next: ?*@This(),
        address: SOCKET_ADDRESS,
        prefix_origin: c_int,
        suffix_origin: c_int,
        dad_state: c_int,
        valid_lifetime: ULONG,
        preferred_lifetime: ULONG,
        lease_lifetime: ULONG,
        on_link_prefix_length: u8,
    };

    const IF_OPER_STATUS = enum(c_int) {
        IfOperStatusUp = 1,
        IfOperStatusDown = 2,
        IfOperStatusTesting = 3,
        IfOperStatusUnknown = 4,
        IfOperStatusDormant = 5,
        IfOperStatusNotPresent = 6,
        IfOperStatusLowerLayerDown = 7,
    };

    const IP_ADAPTER_ADDRESSES = extern struct {
        length: ULONG,
        if_index: DWORD,
        next: ?*@This(),
        adapter_name: ?[*:0]CHAR,
        first_unicast_address: ?*IP_ADAPTER_UNICAST_ADDRESS,
        first_anycast_address: ?*anyopaque,
        first_multicast_address: ?*anyopaque,
        first_dns_server_address: ?*anyopaque,
        dns_suffix: ?[*:0]WCHAR,
        description: ?[*:0]WCHAR,
        friendly_name: ?[*:0]WCHAR,
        physical_address: [MAX_ADAPTER_ADDRESS_LENGTH]BYTE,
        physical_address_length: DWORD,
        flags: DWORD,
        mtu: DWORD,
        if_type: DWORD,
        oper_status: IF_OPER_STATUS,
        ipv6_if_index: DWORD,
        zone_indices: [16]DWORD,
        first_prefix: ?*anyopaque,
    };

    extern "iphlpapi" fn GetAdaptersAddresses(
        Family: ULONG,
        Flags: ULONG,
        Reserved: ?*anyopaque,
        AdapterAddresses: ?*IP_ADAPTER_ADDRESSES,
        SizePointer: *ULONG,
    ) callconv(.winapi) ULONG;
} else struct {};

fn getNetworkInterfacesWindows(allocator: Allocator) NetworkError![]NetworkInterface {
    if (builtin.os.tag != .windows) {
        return NetworkError.UnsupportedPlatform;
    }

    const wt = win_types;

    // First call to get required size
    var buf_size: wt.ULONG = 0;
    var result = wt.GetAdaptersAddresses(wt.AF_UNSPEC, wt.GAA_FLAG_INCLUDE_PREFIX, null, null, &buf_size);

    if (result != wt.ERROR_BUFFER_OVERFLOW and result != wt.ERROR_SUCCESS) {
        return NetworkError.WindowsApiError;
    }

    // Allocate buffer
    const buf = allocator.alloc(u8, buf_size) catch return NetworkError.OutOfMemory;
    defer allocator.free(buf);

    const adapter_addresses: *wt.IP_ADAPTER_ADDRESSES = @ptrCast(@alignCast(buf.ptr));

    result = wt.GetAdaptersAddresses(wt.AF_UNSPEC, wt.GAA_FLAG_INCLUDE_PREFIX, null, adapter_addresses, &buf_size);
    if (result != wt.ERROR_SUCCESS) {
        return NetworkError.WindowsApiError;
    }

    var interfaces: std.ArrayListUnmanaged(NetworkInterface) = .empty;
    errdefer {
        for (interfaces.items) |*iface| {
            iface.deinit(allocator);
        }
        interfaces.deinit(allocator);
    }

    var current_adapter: ?*wt.IP_ADAPTER_ADDRESSES = adapter_addresses;
    while (current_adapter) |adapter| {
        // Get friendly name
        var name_buf: [wt.MAX_ADAPTER_NAME_LENGTH]u8 = undefined;
        var name_len: usize = 0;

        if (adapter.friendly_name) |wname| {
            // Convert wide string to UTF-8
            var i: usize = 0;
            while (wname[i] != 0 and i < wt.MAX_ADAPTER_NAME_LENGTH - 1) {
                const wchar = wname[i];
                if (wchar < 128) {
                    name_buf[name_len] = @intCast(wchar);
                    name_len += 1;
                }
                i += 1;
            }
        }

        const name = if (name_len > 0)
            allocator.dupe(u8, name_buf[0..name_len]) catch return NetworkError.OutOfMemory
        else
            allocator.dupe(u8, "Unknown") catch return NetworkError.OutOfMemory;
        errdefer allocator.free(name);

        // Get MAC address
        var mac: ?[]const u8 = null;
        if (adapter.physical_address_length == 6) {
            var mac_bytes: [6]u8 = undefined;
            for (0..6) |i| {
                mac_bytes[i] = adapter.physical_address[i];
            }
            // Check if not all zeros
            var is_valid = false;
            for (mac_bytes) |b| {
                if (b != 0) {
                    is_valid = true;
                    break;
                }
            }
            if (is_valid) {
                mac = formatMacAddress(allocator, mac_bytes) catch return NetworkError.OutOfMemory;
            }
        }
        errdefer if (mac) |m| allocator.free(m);

        // Get IP addresses
        var ipv4: ?[]const u8 = null;
        var ipv6: ?[]const u8 = null;

        var unicast = adapter.first_unicast_address;
        while (unicast) |addr| {
            if (addr.address.lpSockaddr) |sockaddr_ptr| {
                const family: u16 = @as(*align(1) const u16, @ptrCast(sockaddr_ptr)).*;
                const AF_INET: u16 = 2;
                const AF_INET6: u16 = 23;

                if (family == AF_INET and ipv4 == null) {
                    // sockaddr_in: family (2) + port (2) + addr (4)
                    const addr_ptr: [*]const u8 = @ptrCast(sockaddr_ptr);
                    const ip_bytes: [4]u8 = addr_ptr[4..8].*;
                    ipv4 = formatIpv4Address(allocator, ip_bytes) catch return NetworkError.OutOfMemory;
                } else if (family == AF_INET6 and ipv6 == null) {
                    // sockaddr_in6: family (2) + port (2) + flowinfo (4) + addr (16)
                    const addr_ptr: [*]const u8 = @ptrCast(sockaddr_ptr);
                    const ip_bytes: [16]u8 = addr_ptr[8..24].*;
                    if (!isLinkLocalIpv6(ip_bytes)) {
                        ipv6 = formatIpv6Address(allocator, ip_bytes) catch return NetworkError.OutOfMemory;
                    }
                }
            }
            unicast = addr.next;
        }
        errdefer if (ipv4) |ip| allocator.free(ip);
        errdefer if (ipv6) |ip| allocator.free(ip);

        // Determine status
        const status: InterfaceStatus = switch (adapter.oper_status) {
            .IfOperStatusUp => .up,
            .IfOperStatusDown => .down,
            else => .unknown,
        };

        // Check if loopback (IF_TYPE_SOFTWARE_LOOPBACK = 24)
        const is_loopback = adapter.if_type == 24;

        const iface = NetworkInterface{
            .name = name,
            .ipv4 = ipv4,
            .ipv6 = ipv6,
            .mac = mac,
            .netmask = null,
            .status = status,
            .index = adapter.if_index,
            .is_loopback = is_loopback,
        };

        interfaces.append(allocator, iface) catch return NetworkError.OutOfMemory;
        current_adapter = adapter.next;
    }

    return interfaces.toOwnedSlice(allocator) catch return NetworkError.OutOfMemory;
}

// =============================================================================
// BSD/macOS Implementation using getifaddrs
// =============================================================================

fn getNetworkInterfacesBsd(allocator: Allocator) NetworkError![]NetworkInterface {
    const c = @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/socket.h");
        @cInclude("ifaddrs.h");
        @cInclude("net/if.h");
        @cInclude("netinet/in.h");
        @cInclude("arpa/inet.h");
        @cInclude("net/if_dl.h");
    });

    var ifaddrs: ?*c.ifaddrs = null;
    if (c.getifaddrs(&ifaddrs) != 0) {
        return NetworkError.SystemError;
    }
    defer c.freeifaddrs(ifaddrs);

    // Map interface names to info
    var interface_map: std.StringHashMapUnmanaged(InterfaceInfo) = .empty;
    defer {
        var it = interface_map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            const info = entry.value_ptr;
            if (info.mac) |m| allocator.free(m);
            if (info.ipv4) |ip| allocator.free(ip);
            if (info.ipv6) |ip| allocator.free(ip);
            if (info.netmask) |nm| allocator.free(nm);
        }
        interface_map.deinit(allocator);
    }

    var ifa = ifaddrs;
    while (ifa) |addr| {
        if (addr.ifa_name) |name_ptr| {
            const name_slice = std.mem.sliceTo(name_ptr, 0);

            var info = interface_map.get(name_slice) orelse InterfaceInfo{};

            // Check flags
            const IFF_UP: c_uint = 0x1;
            const IFF_LOOPBACK: c_uint = 0x8;

            if (addr.ifa_flags & IFF_UP != 0) {
                info.status = .up;
            } else if (info.status == .unknown) {
                info.status = .down;
            }
            info.is_loopback = (addr.ifa_flags & IFF_LOOPBACK) != 0;

            if (addr.ifa_addr) |sockaddr_ptr| {
                const family = sockaddr_ptr.*.sa_family;

                if (family == c.AF_INET and info.ipv4 == null) {
                    const sin: *const c.sockaddr_in = @ptrCast(@alignCast(sockaddr_ptr));
                    const addr_int = sin.sin_addr.s_addr;
                    const bytes: [4]u8 = @bitCast(addr_int);
                    info.ipv4 = formatIpv4Address(allocator, bytes) catch return NetworkError.OutOfMemory;
                } else if (family == c.AF_INET6 and info.ipv6 == null) {
                    const sin6: *const c.sockaddr_in6 = @ptrCast(@alignCast(sockaddr_ptr));
                    const bytes: [16]u8 = @bitCast(sin6.sin6_addr);
                    if (!isLinkLocalIpv6(bytes)) {
                        info.ipv6 = formatIpv6Address(allocator, bytes) catch return NetworkError.OutOfMemory;
                    }
                } else if (family == c.AF_LINK) {
                    const sdl: *const c.sockaddr_dl = @ptrCast(@alignCast(sockaddr_ptr));
                    if (sdl.sdl_alen == 6 and info.mac == null) {
                        const mac_ptr: [*]const u8 = @ptrCast(&sdl.sdl_data);
                        const mac_offset = sdl.sdl_nlen;
                        var mac_bytes: [6]u8 = undefined;
                        for (0..6) |i| {
                            mac_bytes[i] = mac_ptr[mac_offset + i];
                        }
                        // Check if valid
                        var is_valid = false;
                        for (mac_bytes) |b| {
                            if (b != 0) {
                                is_valid = true;
                                break;
                            }
                        }
                        if (is_valid) {
                            info.mac = formatMacAddress(allocator, mac_bytes) catch return NetworkError.OutOfMemory;
                        }
                    }
                }
            }

            // Update or insert
            const key = interface_map.getKey(name_slice) orelse (allocator.dupe(u8, name_slice) catch return NetworkError.OutOfMemory);
            interface_map.put(allocator, key, info) catch return NetworkError.OutOfMemory;
        }

        ifa = addr.ifa_next;
    }

    // Convert to slice
    var result: std.ArrayListUnmanaged(NetworkInterface) = .empty;
    errdefer {
        for (result.items) |*iface| {
            iface.deinit(allocator);
        }
        result.deinit(allocator);
    }

    var idx: u32 = 0;
    var it = interface_map.iterator();
    while (it.next()) |entry| {
        const info = entry.value_ptr;
        const iface = NetworkInterface{
            .name = allocator.dupe(u8, entry.key_ptr.*) catch return NetworkError.OutOfMemory,
            .ipv4 = if (info.ipv4) |ip| allocator.dupe(u8, ip) catch return NetworkError.OutOfMemory else null,
            .ipv6 = if (info.ipv6) |ip| allocator.dupe(u8, ip) catch return NetworkError.OutOfMemory else null,
            .mac = if (info.mac) |m| allocator.dupe(u8, m) catch return NetworkError.OutOfMemory else null,
            .netmask = if (info.netmask) |nm| allocator.dupe(u8, nm) catch return NetworkError.OutOfMemory else null,
            .status = info.status,
            .index = idx,
            .is_loopback = info.is_loopback,
        };
        result.append(allocator, iface) catch return NetworkError.OutOfMemory;
        idx += 1;
    }

    return result.toOwnedSlice(allocator) catch return NetworkError.OutOfMemory;
}

// =============================================================================
// Unit Tests
// =============================================================================

test "formatIpv4Address" {
    const allocator = std.testing.allocator;

    const addr1 = [4]u8{ 192, 168, 1, 1 };
    const str1 = try formatIpv4Address(allocator, addr1);
    defer allocator.free(str1);
    try std.testing.expectEqualStrings("192.168.1.1", str1);

    const addr2 = [4]u8{ 0, 0, 0, 0 };
    const str2 = try formatIpv4Address(allocator, addr2);
    defer allocator.free(str2);
    try std.testing.expectEqualStrings("0.0.0.0", str2);

    const addr3 = [4]u8{ 255, 255, 255, 255 };
    const str3 = try formatIpv4Address(allocator, addr3);
    defer allocator.free(str3);
    try std.testing.expectEqualStrings("255.255.255.255", str3);

    const addr4 = [4]u8{ 127, 0, 0, 1 };
    const str4 = try formatIpv4Address(allocator, addr4);
    defer allocator.free(str4);
    try std.testing.expectEqualStrings("127.0.0.1", str4);
}

test "formatIpv6Address" {
    const allocator = std.testing.allocator;

    // Loopback ::1
    const loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const str1 = try formatIpv6Address(allocator, loopback);
    defer allocator.free(str1);
    try std.testing.expectEqualStrings("0:0:0:0:0:0:0:1", str1);

    // Link-local fe80::1
    const link_local = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const str2 = try formatIpv6Address(allocator, link_local);
    defer allocator.free(str2);
    try std.testing.expectEqualStrings("fe80:0:0:0:0:0:0:1", str2);
}

test "formatMacAddress" {
    const allocator = std.testing.allocator;

    const mac1 = [6]u8{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    const str1 = try formatMacAddress(allocator, mac1);
    defer allocator.free(str1);
    try std.testing.expectEqualStrings("00:1a:2b:3c:4d:5e", str1);

    const mac2 = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const str2 = try formatMacAddress(allocator, mac2);
    defer allocator.free(str2);
    try std.testing.expectEqualStrings("ff:ff:ff:ff:ff:ff", str2);
}

test "isLoopbackIpv4" {
    try std.testing.expect(isLoopbackIpv4([4]u8{ 127, 0, 0, 1 }));
    try std.testing.expect(isLoopbackIpv4([4]u8{ 127, 255, 255, 255 }));
    try std.testing.expect(!isLoopbackIpv4([4]u8{ 192, 168, 1, 1 }));
    try std.testing.expect(!isLoopbackIpv4([4]u8{ 10, 0, 0, 1 }));
}

test "isLoopbackIpv6" {
    const loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(isLoopbackIpv6(loopback));

    const not_loopback = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(!isLoopbackIpv6(not_loopback));
}

test "isLinkLocalIpv6" {
    const link_local = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(isLinkLocalIpv6(link_local));

    const not_link_local = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(!isLinkLocalIpv6(not_link_local));

    const loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(!isLinkLocalIpv6(loopback));
}

test "InterfaceStatus.toString" {
    try std.testing.expectEqualStrings("up", InterfaceStatus.up.toString());
    try std.testing.expectEqualStrings("down", InterfaceStatus.down.toString());
    try std.testing.expectEqualStrings("unknown", InterfaceStatus.unknown.toString());
}

test "NetworkInterface.clone and deinit" {
    const allocator = std.testing.allocator;

    var original = NetworkInterface{
        .name = try allocator.dupe(u8, "eth0"),
        .ipv4 = try allocator.dupe(u8, "192.168.1.1"),
        .ipv6 = try allocator.dupe(u8, "fe80::1"),
        .mac = try allocator.dupe(u8, "00:11:22:33:44:55"),
        .netmask = try allocator.dupe(u8, "255.255.255.0"),
        .status = .up,
        .index = 1,
        .is_loopback = false,
    };
    defer original.deinit(allocator);

    var cloned = try original.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expectEqualStrings("eth0", cloned.name);
    try std.testing.expectEqualStrings("192.168.1.1", cloned.ipv4.?);
    try std.testing.expectEqualStrings("fe80::1", cloned.ipv6.?);
    try std.testing.expectEqualStrings("00:11:22:33:44:55", cloned.mac.?);
    try std.testing.expectEqualStrings("255.255.255.0", cloned.netmask.?);
    try std.testing.expectEqual(InterfaceStatus.up, cloned.status);
    try std.testing.expectEqual(@as(u32, 1), cloned.index);
    try std.testing.expect(!cloned.is_loopback);
}

test "getNetworkInterfaces - basic functionality" {
    // This test verifies that the function runs without error on the current platform
    // The actual results depend on the system's network configuration
    const allocator = std.testing.allocator;

    const interfaces = getNetworkInterfaces(allocator) catch |err| {
        // Some platforms may not support this operation in test environment
        if (err == NetworkError.UnsupportedPlatform) {
            return;
        }
        // Socket creation might fail in sandboxed environments
        if (err == NetworkError.SocketCreationFailed) {
            return;
        }
        return err;
    };
    defer freeNetworkInterfaces(allocator, interfaces);

    // We should have at least one interface (loopback)
    // But in some container/VM environments this might not be true
    if (interfaces.len > 0) {
        for (interfaces) |iface| {
            // Each interface should have a valid name
            try std.testing.expect(iface.name.len > 0);
        }
    }
}

test "getNetworkInterfaces - loopback detection" {
    // Test that loopback interface is correctly identified
    const allocator = std.testing.allocator;

    const interfaces = getNetworkInterfaces(allocator) catch |err| {
        if (err == NetworkError.UnsupportedPlatform or err == NetworkError.SocketCreationFailed) {
            return;
        }
        return err;
    };
    defer freeNetworkInterfaces(allocator, interfaces);

    // On most systems, we should find at least one interface
    // Look for a loopback interface with 127.0.0.1
    for (interfaces) |iface| {
        if (iface.is_loopback) {
            // Loopback typically has 127.0.0.1
            if (iface.ipv4) |ip| {
                try std.testing.expect(std.mem.startsWith(u8, ip, "127."));
            }
        }
    }
    // Most systems have a loopback interface, but we don't fail if not found
    // as some containerized environments might not have one
}

test "getNetworkInterfaces - interface status" {
    // Test that interface status is correctly detected
    const allocator = std.testing.allocator;

    const interfaces = getNetworkInterfaces(allocator) catch |err| {
        if (err == NetworkError.UnsupportedPlatform or err == NetworkError.SocketCreationFailed) {
            return;
        }
        return err;
    };
    defer freeNetworkInterfaces(allocator, interfaces);

    for (interfaces) |iface| {
        // Status should be one of the known values
        const status_str = iface.status.toString();
        try std.testing.expect(
            std.mem.eql(u8, status_str, "up") or
                std.mem.eql(u8, status_str, "down") or
                std.mem.eql(u8, status_str, "unknown"),
        );
    }
}

test "getNetworkInterfaces - ipv4 format validation" {
    // Test that IPv4 addresses are in correct format
    const allocator = std.testing.allocator;

    const interfaces = getNetworkInterfaces(allocator) catch |err| {
        if (err == NetworkError.UnsupportedPlatform or err == NetworkError.SocketCreationFailed) {
            return;
        }
        return err;
    };
    defer freeNetworkInterfaces(allocator, interfaces);

    for (interfaces) |iface| {
        if (iface.ipv4) |ip| {
            // IPv4 addresses should contain dots
            var dot_count: usize = 0;
            for (ip) |c| {
                if (c == '.') dot_count += 1;
            }
            // A valid IPv4 address has exactly 3 dots
            try std.testing.expectEqual(@as(usize, 3), dot_count);
        }
    }
}

test "getNetworkInterfaces - mac address format validation" {
    // Test that MAC addresses are in correct format
    const allocator = std.testing.allocator;

    const interfaces = getNetworkInterfaces(allocator) catch |err| {
        if (err == NetworkError.UnsupportedPlatform or err == NetworkError.SocketCreationFailed) {
            return;
        }
        return err;
    };
    defer freeNetworkInterfaces(allocator, interfaces);

    for (interfaces) |iface| {
        if (iface.mac) |mac| {
            // MAC addresses should be in format xx:xx:xx:xx:xx:xx (17 chars)
            try std.testing.expectEqual(@as(usize, 17), mac.len);

            // Should have 5 colons
            var colon_count: usize = 0;
            for (mac) |c| {
                if (c == ':') colon_count += 1;
            }
            try std.testing.expectEqual(@as(usize, 5), colon_count);
        }
    }
}

test "getNetworkInterfaces - multiple calls consistency" {
    // Test that calling getNetworkInterfaces multiple times doesn't leak memory
    // and returns consistent results
    const allocator = std.testing.allocator;

    var first_count: usize = 0;

    // First call
    {
        const interfaces = getNetworkInterfaces(allocator) catch |err| {
            if (err == NetworkError.UnsupportedPlatform or err == NetworkError.SocketCreationFailed) {
                return;
            }
            return err;
        };
        first_count = interfaces.len;
        freeNetworkInterfaces(allocator, interfaces);
    }

    // Second call - should work without issues
    {
        const interfaces = getNetworkInterfaces(allocator) catch |err| {
            if (err == NetworkError.UnsupportedPlatform or err == NetworkError.SocketCreationFailed) {
                return;
            }
            return err;
        };
        // Count should be the same (barring network changes)
        try std.testing.expectEqual(first_count, interfaces.len);
        freeNetworkInterfaces(allocator, interfaces);
    }
}

test "NetworkInterface with null fields" {
    // Test NetworkInterface with all optional fields set to null
    const allocator = std.testing.allocator;

    var iface = NetworkInterface{
        .name = try allocator.dupe(u8, "test0"),
        .ipv4 = null,
        .ipv6 = null,
        .mac = null,
        .netmask = null,
        .status = .unknown,
        .index = 0,
        .is_loopback = false,
    };
    defer iface.deinit(allocator);

    // Clone should work with null fields
    var cloned = try iface.clone(allocator);
    defer cloned.deinit(allocator);

    try std.testing.expectEqualStrings("test0", cloned.name);
    try std.testing.expectEqual(@as(?[]const u8, null), cloned.ipv4);
    try std.testing.expectEqual(@as(?[]const u8, null), cloned.ipv6);
    try std.testing.expectEqual(@as(?[]const u8, null), cloned.mac);
    try std.testing.expectEqual(@as(?[]const u8, null), cloned.netmask);
}

test "formatIpv4Address edge cases" {
    const allocator = std.testing.allocator;

    // Test common network addresses
    const private_a = [4]u8{ 10, 0, 0, 1 };
    const str_a = try formatIpv4Address(allocator, private_a);
    defer allocator.free(str_a);
    try std.testing.expectEqualStrings("10.0.0.1", str_a);

    const private_b = [4]u8{ 172, 16, 0, 1 };
    const str_b = try formatIpv4Address(allocator, private_b);
    defer allocator.free(str_b);
    try std.testing.expectEqualStrings("172.16.0.1", str_b);

    const private_c = [4]u8{ 192, 168, 0, 1 };
    const str_c = try formatIpv4Address(allocator, private_c);
    defer allocator.free(str_c);
    try std.testing.expectEqualStrings("192.168.0.1", str_c);
}

test "formatIpv6Address edge cases" {
    const allocator = std.testing.allocator;

    // Test all zeros (unspecified address)
    const unspecified = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const str1 = try formatIpv6Address(allocator, unspecified);
    defer allocator.free(str1);
    try std.testing.expectEqualStrings("0:0:0:0:0:0:0:0", str1);

    // Test IPv4-mapped IPv6 address (::ffff:192.168.1.1)
    const ipv4_mapped = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1 };
    const str2 = try formatIpv6Address(allocator, ipv4_mapped);
    defer allocator.free(str2);
    try std.testing.expect(str2.len > 0);
}
