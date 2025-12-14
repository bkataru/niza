//! Niza CLI - Network Interface Information Tool
//!
//! A cross-platform command-line utility for displaying network interface information.
//! Uses native OS APIs for reliable, fast interface enumeration.
//!
//! ## Usage
//!
//! ```
//! niza [OPTIONS]
//!
//! OPTIONS:
//!     -h, --help      Show this help message
//!     -a, --all       Show all interfaces (including inactive)
//!     -6, --ipv6      Show IPv6 addresses
//!     -m, --mac       Show MAC addresses
//!     -j, --json      Output in JSON format
//!     -q, --quiet     Quiet mode (minimal output)
//!     -v, --version   Show version information
//! ```

const std = @import("std");
const builtin = @import("builtin");

const niza = @import("niza");

/// Application version
const VERSION = "0.1.0";

/// ANSI color codes for terminal output
const Color = struct {
    const cyan = "\x1b[38;2;0;230;230m";
    const green = "\x1b[38;2;0;255;128m";
    const blue = "\x1b[38;2;100;149;237m";
    const yellow = "\x1b[38;2;255;220;0m";
    const magenta = "\x1b[38;2;255;0;255m";
    const red = "\x1b[38;2;255;69;58m";
    const dim = "\x1b[2m";
    const bold = "\x1b[1m";
    const reset = "\x1b[0m";
};

/// CLI options parsed from command-line arguments
const Options = struct {
    show_all: bool = false,
    show_ipv6: bool = false,
    show_mac: bool = false,
    json_output: bool = false,
    quiet_mode: bool = false,
    show_help: bool = false,
    show_version: bool = false,
    use_colors: bool = true,
};

/// Helper to get color string or empty string based on options
fn col(options: Options, comptime color: []const u8) []const u8 {
    return if (options.use_colors) color else "";
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip program name
    _ = args.skip();

    var options = Options{};

    // Check if stdout is a TTY for color support
    const stdout_file = std.fs.File.stdout();
    options.use_colors = stdout_file.isTty();

    // Parse arguments
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            options.show_help = true;
        } else if (std.mem.eql(u8, arg, "--all") or std.mem.eql(u8, arg, "-a")) {
            options.show_all = true;
        } else if (std.mem.eql(u8, arg, "--ipv6") or std.mem.eql(u8, arg, "-6")) {
            options.show_ipv6 = true;
        } else if (std.mem.eql(u8, arg, "--mac") or std.mem.eql(u8, arg, "-m")) {
            options.show_mac = true;
        } else if (std.mem.eql(u8, arg, "--json") or std.mem.eql(u8, arg, "-j")) {
            options.json_output = true;
            options.use_colors = false;
        } else if (std.mem.eql(u8, arg, "--quiet") or std.mem.eql(u8, arg, "-q")) {
            options.quiet_mode = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            options.show_version = true;
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            options.use_colors = false;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try printError(options, "Unknown option: {s}", .{arg});
            try printError(options, "Use --help for usage information", .{});
            std.process.exit(1);
        }
    }

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&stdout_buf);

    if (options.show_help) {
        try printHelp(&stdout_writer.interface, options);
        try stdout_writer.interface.flush();
        return;
    }

    if (options.show_version) {
        try printVersion(&stdout_writer.interface, options);
        try stdout_writer.interface.flush();
        return;
    }

    // Get network interfaces
    const interfaces = niza.getNetworkInterfaces(allocator) catch |err| {
        try printError(options, "Failed to retrieve network interfaces: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer niza.freeNetworkInterfaces(allocator, interfaces);

    if (options.json_output) {
        try outputJson(allocator, &stdout_writer.interface, interfaces, options);
    } else {
        try outputText(&stdout_writer.interface, interfaces, options);
    }
    try stdout_writer.interface.flush();
}

fn printHelp(writer: *std.Io.Writer, options: Options) !void {
    try writer.print(
        \\{s}{s}niza{s} - Cross-Platform Network Interface Information Tool
        \\
        \\{s}USAGE:{s}
        \\    niza [OPTIONS]
        \\
        \\{s}OPTIONS:{s}
        \\    {s}-h, --help{s}      Show this help message
        \\    {s}-a, --all{s}       Show all interfaces (including inactive)
        \\    {s}-6, --ipv6{s}      Show IPv6 addresses
        \\    {s}-m, --mac{s}       Show MAC addresses
        \\    {s}-j, --json{s}      Output in JSON format
        \\    {s}-q, --quiet{s}     Quiet mode (minimal output)
        \\    {s}-v, --version{s}   Show version information
        \\    {s}--no-color{s}      Disable colored output
        \\
        \\{s}EXAMPLES:{s}
        \\    niza                  Show active interfaces with IPv4
        \\    niza --all            Show all interfaces
        \\    niza -a -6 -m         Show all interfaces with IPv6 and MAC
        \\    niza --json           Output as JSON for scripting
        \\
        \\{s}SUPPORTED PLATFORMS:{s}
        \\    Linux, Windows, macOS, FreeBSD, NetBSD, OpenBSD
        \\
    , .{
        col(options, Color.bold),   col(options, Color.cyan),   col(options, Color.reset),
        col(options, Color.yellow), col(options, Color.reset),  col(options, Color.yellow),
        col(options, Color.reset),  col(options, Color.green),  col(options, Color.reset),
        col(options, Color.green),  col(options, Color.reset),  col(options, Color.green),
        col(options, Color.reset),  col(options, Color.green),  col(options, Color.reset),
        col(options, Color.green),  col(options, Color.reset),  col(options, Color.green),
        col(options, Color.reset),  col(options, Color.green),  col(options, Color.reset),
        col(options, Color.green),  col(options, Color.reset),  col(options, Color.yellow),
        col(options, Color.reset),  col(options, Color.yellow), col(options, Color.reset),
    });
}

fn printVersion(writer: *std.Io.Writer, options: Options) !void {
    const os_name = switch (builtin.os.tag) {
        .linux => "linux",
        .windows => "windows",
        .macos => "macos",
        .freebsd => "freebsd",
        .netbsd => "netbsd",
        .openbsd => "openbsd",
        .dragonfly => "dragonfly",
        else => "unknown",
    };

    const arch_name = switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .x86 => "x86",
        .aarch64 => "aarch64",
        .arm => "arm",
        .riscv64 => "riscv64",
        else => "unknown",
    };

    try writer.print("{s}{s}niza{s} {s}\n", .{
        col(options, Color.bold),
        col(options, Color.cyan),
        col(options, Color.reset),
        VERSION,
    });
    try writer.print("{s}Platform: {s}-{s}{s}\n", .{
        col(options, Color.dim),
        os_name,
        arch_name,
        col(options, Color.reset),
    });
    try writer.print("{s}Built with Zig {s}{s}\n", .{
        col(options, Color.dim),
        builtin.zig_version_string,
        col(options, Color.reset),
    });
}

fn printError(options: Options, comptime fmt: []const u8, args: anytype) !void {
    const stderr_file = std.fs.File.stderr();
    var buf: [4096]u8 = undefined;
    var stderr_writer = stderr_file.writer(&buf);

    if (options.use_colors) {
        try stderr_writer.interface.print("{s}✗ Error:{s} " ++ fmt ++ "\n", .{ Color.red, Color.reset } ++ args);
    } else {
        try stderr_writer.interface.print("Error: " ++ fmt ++ "\n", args);
    }
    try stderr_writer.interface.flush();
}

fn outputText(writer: *std.Io.Writer, interfaces: []const niza.NetworkInterface, options: Options) !void {
    // Print header unless in quiet mode
    if (!options.quiet_mode) {
        try writer.print(
            \\{s}╔══════════════════════════════════════════╗{s}
            \\{s}║{s}     {s}niza{s} - Network Interface Info       {s}║{s}
            \\{s}╚══════════════════════════════════════════╝{s}
            \\
        , .{
            col(options, Color.cyan), col(options, Color.reset),
            col(options, Color.cyan), col(options, Color.reset),
            col(options, Color.bold), col(options, Color.reset),
            col(options, Color.cyan), col(options, Color.reset),
            col(options, Color.cyan), col(options, Color.reset),
        });
        try writer.print("\n", .{});
    }

    var active_count: usize = 0;
    var displayed_count: usize = 0;

    for (interfaces) |iface| {
        const is_active = iface.status == .up;
        if (is_active) active_count += 1;

        // Skip inactive interfaces unless --all is specified
        if (!options.show_all and !is_active) continue;

        // Skip interfaces without IP addresses unless --all is specified
        const has_ip = iface.ipv4 != null or iface.ipv6 != null;
        if (!options.show_all and !has_ip) continue;

        displayed_count += 1;

        if (options.quiet_mode) {
            // Minimal output: just interface name and IPs
            try writer.print("{s}", .{iface.name});
            if (iface.ipv4) |ip| {
                try writer.print(" {s}", .{ip});
            }
            if (options.show_ipv6) {
                if (iface.ipv6) |ip| {
                    try writer.print(" {s}", .{ip});
                }
            }
            try writer.print("\n", .{});
        } else {
            // Full output with formatting

            // Interface header
            const status_icon = if (is_active) "●" else "○";
            const status_color = if (is_active) col(options, Color.green) else col(options, Color.dim);

            try writer.print("{s}{s}{s} {s}{s}{s}{s}", .{
                status_color,
                status_icon,
                col(options, Color.reset),
                col(options, Color.bold),
                col(options, Color.blue),
                iface.name,
                col(options, Color.reset),
            });

            // Status badge
            const status_str = iface.status.toString();
            try writer.print(" {s}[{s}]{s}", .{ status_color, status_str, col(options, Color.reset) });

            // Loopback indicator
            if (iface.is_loopback) {
                try writer.print(" {s}(loopback){s}", .{ col(options, Color.dim), col(options, Color.reset) });
            }

            try writer.print("\n", .{});

            // IPv4 address
            if (iface.ipv4) |ipv4| {
                try writer.print("  {s}IPv4:{s}  {s}{s}{s}\n", .{
                    col(options, Color.yellow),
                    col(options, Color.reset),
                    col(options, Color.green),
                    ipv4,
                    col(options, Color.reset),
                });
            }

            // IPv6 address (if requested)
            if (options.show_ipv6) {
                if (iface.ipv6) |ipv6| {
                    try writer.print("  {s}IPv6:{s}  {s}{s}{s}\n", .{
                        col(options, Color.yellow),
                        col(options, Color.reset),
                        col(options, Color.magenta),
                        ipv6,
                        col(options, Color.reset),
                    });
                }
            }

            // MAC address (if requested)
            if (options.show_mac) {
                if (iface.mac) |mac| {
                    try writer.print("  {s}MAC:{s}   {s}{s}{s}\n", .{
                        col(options, Color.yellow),
                        col(options, Color.reset),
                        col(options, Color.dim),
                        mac,
                        col(options, Color.reset),
                    });
                }
            }

            // Netmask (if available)
            if (iface.netmask) |netmask| {
                try writer.print("  {s}Mask:{s}  {s}{s}{s}\n", .{
                    col(options, Color.yellow),
                    col(options, Color.reset),
                    col(options, Color.dim),
                    netmask,
                    col(options, Color.reset),
                });
            }

            try writer.print("\n", .{});
        }
    }

    // Summary (unless quiet mode)
    if (!options.quiet_mode) {
        if (displayed_count == 0) {
            try writer.print("{s}No network interfaces found matching criteria.{s}\n", .{
                col(options, Color.dim),
                col(options, Color.reset),
            });
            try writer.print("{s}Try using --all to show inactive interfaces.{s}\n", .{
                col(options, Color.dim),
                col(options, Color.reset),
            });
        } else {
            try writer.print("{s}─────────────────────────────────────────────{s}\n", .{
                col(options, Color.dim),
                col(options, Color.reset),
            });
            try writer.print("{s}Displayed {d} interface(s), {d} active{s}\n", .{
                col(options, Color.dim),
                displayed_count,
                active_count,
                col(options, Color.reset),
            });
        }
    }
}

fn outputJson(allocator: std.mem.Allocator, writer: *std.Io.Writer, interfaces: []const niza.NetworkInterface, options: Options) !void {
    var json_array: std.ArrayListUnmanaged(u8) = .empty;
    defer json_array.deinit(allocator);

    const json_writer = json_array.writer(allocator);

    try json_writer.writeAll("{\n  \"interfaces\": [\n");

    var first = true;
    for (interfaces) |iface| {
        const is_active = iface.status == .up;

        // Apply same filtering as text output
        if (!options.show_all and !is_active) continue;

        const has_ip = iface.ipv4 != null or iface.ipv6 != null;
        if (!options.show_all and !has_ip) continue;

        if (!first) {
            try json_writer.writeAll(",\n");
        }
        first = false;

        try json_writer.writeAll("    {\n");
        try json_writer.print("      \"name\": \"{s}\",\n", .{iface.name});
        try json_writer.print("      \"index\": {d},\n", .{iface.index});
        try json_writer.print("      \"status\": \"{s}\",\n", .{iface.status.toString()});
        try json_writer.print("      \"is_loopback\": {s},\n", .{if (iface.is_loopback) "true" else "false"});

        if (iface.ipv4) |ip| {
            try json_writer.print("      \"ipv4\": \"{s}\",\n", .{ip});
        } else {
            try json_writer.writeAll("      \"ipv4\": null,\n");
        }

        if (iface.ipv6) |ip| {
            try json_writer.print("      \"ipv6\": \"{s}\",\n", .{ip});
        } else {
            try json_writer.writeAll("      \"ipv6\": null,\n");
        }

        if (iface.mac) |mac| {
            try json_writer.print("      \"mac\": \"{s}\",\n", .{mac});
        } else {
            try json_writer.writeAll("      \"mac\": null,\n");
        }

        if (iface.netmask) |nm| {
            try json_writer.print("      \"netmask\": \"{s}\"\n", .{nm});
        } else {
            try json_writer.writeAll("      \"netmask\": null\n");
        }

        try json_writer.writeAll("    }");
    }

    try json_writer.writeAll("\n  ],\n");
    try json_writer.print("  \"count\": {d}\n", .{interfaces.len});
    try json_writer.writeAll("}\n");

    try writer.writeAll(json_array.items);
}

// =============================================================================
// CLI Tests
// =============================================================================

test "Options default values" {
    const options = Options{};
    try std.testing.expect(!options.show_all);
    try std.testing.expect(!options.show_ipv6);
    try std.testing.expect(!options.show_mac);
    try std.testing.expect(!options.json_output);
    try std.testing.expect(!options.quiet_mode);
    try std.testing.expect(!options.show_help);
    try std.testing.expect(!options.show_version);
    try std.testing.expect(options.use_colors);
}

test "Color constants exist" {
    // Just verify the color constants are valid strings
    try std.testing.expect(Color.cyan.len > 0);
    try std.testing.expect(Color.green.len > 0);
    try std.testing.expect(Color.blue.len > 0);
    try std.testing.expect(Color.yellow.len > 0);
    try std.testing.expect(Color.magenta.len > 0);
    try std.testing.expect(Color.red.len > 0);
    try std.testing.expect(Color.dim.len > 0);
    try std.testing.expect(Color.bold.len > 0);
    try std.testing.expect(Color.reset.len > 0);
}

test "col helper function" {
    const with_colors = Options{ .use_colors = true };
    const without_colors = Options{ .use_colors = false };

    try std.testing.expectEqualStrings(Color.cyan, col(with_colors, Color.cyan));
    try std.testing.expectEqualStrings("", col(without_colors, Color.cyan));
}
