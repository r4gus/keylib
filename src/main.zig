const std = @import("std");

const hidapi = @cImport({
    @cInclude("hidapi/hidapi.h");
});

const misc = @import("misc.zig");

const fido = @import("fido");
const Authenticator = fido.client.device.Authenticator;
const Transport = fido.client.device.Transport;
const TransportTag = fido.client.device.TransportTag;
const IOError = fido.client.device.IOError;

const ALL_VENDORS = 0;
const ALL_PRODUCTS = 0;

pub fn open(transport: *const Transport) IOError!*anyopaque {
    switch (transport.*) {
        .usb => |t| {
            var device = hidapi.hid_open_path(t.path);
            if (device == null) return IOError.Open;
            return @ptrCast(*anyopaque, device);
        },
        .nfc, .bluetooth => return IOError.UnexpectedTransport,
    }
}

pub fn close(dev: *anyopaque) void {
    hidapi.hid_close(@ptrCast(*hidapi.hid_device, dev));
}

pub fn write(dev: *anyopaque, data: []const u8) IOError!void {
    if (hidapi.hid_write(@ptrCast(*hidapi.hid_device, dev), &data[0], data.len) == -1) {
        return IOError.Write;
    }
}

pub fn read_timeout(dev: *anyopaque, buffer: []u8, millis: i32) IOError!usize {
    const read = hidapi.hid_read_timeout(@ptrCast(*hidapi.hid_device, dev), &buffer[0], buffer.len, millis);

    if (read == -1) {
        return IOError.Write;
    } else if (read == 0) {
        return IOError.Timeout;
    }

    return @intCast(usize, read);
}

/// Enumerate all given usb devices on the system, looking for usage page 0xF1D0 and usage 1
///
/// The caller is responsible to call deinit() on all Authenticators returned; he is also
/// responsible for freeing the returned slice.
pub fn find_authenticator(allocator: std.mem.Allocator) ![]fido.client.device.Authenticator {
    var devices = hidapi.hid_enumerate(ALL_VENDORS, ALL_PRODUCTS);
    defer hidapi.hid_free_enumeration(devices);

    var authenticators = std.ArrayList(fido.client.device.Authenticator).init(allocator);
    errdefer {
        for (authenticators.items) |*auth| {
            auth.deinit();
        }
    }

    while (devices != null) {
        if (devices.*.usage_page == 0xF1D0 and devices.*.usage == 0x01) {
            var auth = fido.client.device.Authenticator{
                .transport = .{ .usb = .{
                    .path = try misc.copy_c_string(allocator, devices.*.path),
                    .vendor_id = devices.*.vendor_id,
                    .product_id = devices.*.product_id,
                    .serial_number = try misc.copy_wchar_t_string(allocator, devices.*.serial_number),
                    .release_number = devices.*.release_number,
                    .manufacturer_string = try misc.copy_wchar_t_string(allocator, devices.*.manufacturer_string),
                    .product_string = try misc.copy_wchar_t_string(allocator, devices.*.product_string),
                    .interface_number = devices.*.interface_number,
                } },
                .io = .{
                    .open = open,
                    .close = close,
                    .write = write,
                    .read_timeout = read_timeout,
                },
                .allocator = allocator,
            };

            try authenticators.append(auth);
        }
        devices = devices.*.next;
    }

    return try authenticators.toOwnedSlice();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    _ = hidapi.hid_init();

    var authenticators = try find_authenticator(allocator);
    defer {
        for (authenticators) |*auth| {
            auth.deinit();
        }
    }

    for (authenticators) |*auth| {
        std.debug.print("{s}: vendor={x}, product={x} ({s} {s})\n", .{
            auth.transport.usb.path,
            auth.transport.usb.vendor_id,
            auth.transport.usb.product_id,
            auth.transport.usb.manufacturer_string,
            auth.transport.usb.product_string,
        });
        auth.open() catch {
            std.debug.print("can't open device\n", .{});
        };
        const cid = fido.client.device.ctaphid_init(auth, allocator) catch {
            std.debug.print("couldn't send init request\n", .{});
            auth.close();
            return;
        };
        std.debug.print("cid: {x}\n", .{cid});
        auth.close();
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
