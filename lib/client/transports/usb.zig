const std = @import("std");

const hidapi = @cImport({
    @cInclude("hidapi/hidapi.h");
});

const d = @import("../device.zig");
const Authenticator = d.Authenticator;
const Transport = d.Transport;
const TransportTag = d.TransportTag;
const IOError = d.IOError;

const ALL_VENDORS = 0;
const ALL_PRODUCTS = 0;

pub fn init() void {
    _ = hidapi.hid_init();
}

/// Opens a HID device at the specified path and returns an opaque pointer to the device.
///
/// # Arguments
///
/// * `path` - The device path, e.g., "/dev/hidraw0".
///
/// # Returns
///
/// Returns an opaque pointer to the opened device on success, or returns an `IOError` error type on failure.
pub fn open(path: [:0]const u8) IOError!*anyopaque {
    var device = hidapi.hid_open_path(path);
    if (device == null) return IOError.Open;
    return @ptrCast(*anyopaque, device);
}

/// Closes the specified HID device.
///
/// # Arguments
///
/// * `dev` - A pointer to the opened HID device to be closed.
///
/// # Returns
///
/// This function does not return a value.
pub fn close(dev: *anyopaque) void {
    hidapi.hid_close(@ptrCast(*hidapi.hid_device, dev));
}

/// Write data to a HID device.
///
/// # Arguments
///
/// - `dev` - A pointer to an opaque HID device object returned by `open`.
/// - `data` - The data to be written to the device.
///
/// # Returns
///
/// Returns `IOError.Write` if an error occurs during the write operation, otherwise returns `void`.
///
/// # Example
///
/// ```
/// const path = "/dev/hidraw0";
/// const dev = try open(path);
/// defer close(dev);
///
/// var data: [1]u8 = [0];
/// try write(dev, data);
/// ```
pub fn write(dev: *anyopaque, data: []const u8) IOError!void {
    var buffer: [65]u8 = undefined;
    buffer[0] = 0;
    std.mem.copy(u8, buffer[1..], data);

    if (hidapi.hid_write(@ptrCast(*hidapi.hid_device, dev), &buffer[0], buffer.len) == -1) {
        return IOError.Write;
    }
}

/// Reads data from a HID device with a timeout of 1 second.
///
/// # Arguments
///
/// * `dev` - A pointer to a device returned by `open`.
/// * `buffer` - A mutable slice to store the read data.
///
/// # Returns
///
/// * `IOError.Write` if there was an error reading from the device.
/// * `IOError.Timeout` if the read operation timed out.
/// * The number of bytes read from the device if the operation was successful.
pub fn read_timeout(dev: *anyopaque, buffer: []u8) IOError!usize {
    const r = hidapi.hid_read_timeout(@ptrCast(*hidapi.hid_device, dev), &buffer[0], buffer.len, 1000);

    if (r == -1) {
        return IOError.Write;
    } else if (r == 0) {
        return IOError.Timeout;
    }

    return @intCast(usize, r);
}

/// Read data from the HID device identified by `dev` and return it as a slice of bytes.
///
/// This function reads data from the HID device, using a buffer to accumulate all received data
/// until the expected amount of data is received. The expected amount of data is determined by
/// the packet header, which contains the total number of bytes in the packet.
///
/// If the `dev` argument is a null pointer or if an error occurs while reading data, an `IOError`
/// is returned.
///
/// # Arguments
///
/// - `dev`: A pointer to the opaque device handle.
/// - `allocator`: An allocator to use for the internal buffer.
///
/// # Returns
///
/// A slice of bytes containing the data received from the HID device.
pub fn read(dev: *anyopaque, allocator: std.mem.Allocator) IOError![]const u8 {
    var data = std.ArrayList(u8).init(allocator);
    errdefer data.deinit();

    var first: bool = true;
    // The ammount of expected data bytes
    var bcnt_total: usize = 0;
    // Last sequence number
    var seq: ?u8 = 0;

    while (first or data.items.len < bcnt_total) {
        //std.debug.print("expected: {x}, actual: {x}\n", .{ bcnt_total, data.items.len });
        var buffer: [65]u8 = undefined;

        const nr = try read_timeout(dev, buffer[0..]);
        const packet = buffer[0..nr];

        if (first) {
            bcnt_total = @intCast(usize, packet[5]) << 8 | @intCast(usize, packet[6]);
            var l = if (bcnt_total - data.items.len > 57) 57 else bcnt_total - data.items.len;
            try data.appendSlice(packet[7 .. l + 7]);
            first = false;
            std.debug.print("packet: {s}\n", .{std.fmt.fmtSliceHexLower(packet)});
        } else {
            seq = packet[4];
        }
    }

    return try data.toOwnedSlice();
}

/// Enumerates all attached USB HID devices and returns an array of `Authenticator`
/// instances. Only HID devices with usage page `0xF1D0` and usage `0x01` are considered
/// authenticators.
///
/// This function uses the `hidapi` library to enumerate HID devices and allocate memory
/// using the provided allocator. All `Authenticator` instances created during the
/// execution of this function will be properly deinitialized when an error occures.
///
/// The caller is responsible to call deinit() on all Authenticators returned; he is also
/// responsible for freeing the returned slice.
///
/// # Arguments
/// - `allocator`: An allocator used to allocate memory for the `Authenticator` instances
///
/// # Returns
/// An array of `Authenticator` instances representing the connected authenticators
pub fn enumerate(allocator: std.mem.Allocator) ![]Authenticator {
    var dev = hidapi.hid_enumerate(ALL_VENDORS, ALL_PRODUCTS);
    defer hidapi.hid_free_enumeration(dev);

    var authenticators = std.ArrayList(Authenticator).init(allocator);
    errdefer {
        for (authenticators.items) |*auth| {
            auth.deinit();
        }
    }

    var devices = dev;
    while (devices != null) {
        if (devices.*.usage_page == 0xF1D0 and devices.*.usage == 0x01) {
            var auth = Authenticator{
                .transport = .{
                    .path = try copy_c_string(allocator, devices.*.path),
                    .io = .{
                        .open = open,
                        .close = close,
                        .write = write,
                        .read = read,
                    },
                    .type = .usb,
                },
                .allocator = allocator,
            };

            // Build info string for usb authenticator
            var x = std.ArrayList(u8).init(allocator);
            var xwriter = x.writer();
            try xwriter.writeAll(auth.transport.path[0..]);
            try xwriter.writeAll(": vendor=");
            try std.fmt.format(x.writer(), "0x{x}", .{devices.*.vendor_id});
            try xwriter.writeAll(", product=");
            try std.fmt.format(x.writer(), "0x{x}", .{devices.*.product_id});
            try xwriter.writeAll(" (");
            try write_wchar_t_string(xwriter, devices.*.manufacturer_string);
            try xwriter.writeAll(" ");
            try write_wchar_t_string(xwriter, devices.*.product_string);
            try xwriter.writeAll(")");
            auth.transport.info = try x.toOwnedSlice();

            try authenticators.append(auth);
        }
        devices = devices.*.next;
    }

    return try authenticators.toOwnedSlice();
}

// ++++++++++++++++++++++++++++++++++++++++
// Misc
// ++++++++++++++++++++++++++++++++++++++++

/// Copy a standard c string
///
/// This will return an utf-8 string
pub fn copy_c_string(allocator: std.mem.Allocator, s: [*c]u8) ![:0]u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    var s_copy: [:0]u8 = try allocator.allocSentinel(u8, i, 0);
    std.mem.copy(u8, s_copy, s[0..i]);
    return s_copy;
}

/// Copy a wchar_t string
///
/// This will return a utf-16 string
pub fn copy_wchar_t_string(allocator: std.mem.Allocator, s: [*c]hidapi.wchar_t) ![:0]u8 {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    var s_copy: [:0]u8 = try allocator.allocSentinel(u8, i * 2, 0); // wchar_t is 16 bit unicode
    var j: usize = 0;
    var k: usize = 0;
    while (j < i) : (j += 1) {
        const wchar = s[j];
        s_copy[k] = @intCast(u8, wchar & 0xff);
        s_copy[k + 1] = @intCast(u8, wchar >> 8);
        k += 2;
    }
    return s_copy;
}

pub fn write_wchar_t_string(out: anytype, s: [*c]hidapi.wchar_t) !void {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    var j: usize = 0;
    while (j < i) : (j += 1) {
        const wchar = s[j];
        try out.writeByte(@intCast(u8, wchar & 0xff));
        try out.writeByte(@intCast(u8, wchar >> 8));
    }
}
