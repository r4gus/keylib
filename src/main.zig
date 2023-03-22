const std = @import("std");

const hidapi = @cImport({
    @cInclude("hidapi/hidapi.h");
});

const fido = @import("fido");

const misc = @import("misc.zig");

const ALL_VENDORS = 0;
const ALL_PRODUCTS = 0;

/// Enumerate all given usb devices on the system, looking for usage page 0xF1D0 and usage 1
///
/// The caller is responsible to call deinit() on all Authenticators returned; he is also
/// responsible for freeing the returned slice.
pub fn find_authenticator(allocator: std.mem.Allocator) ![]fido.client.device.Authenticator {
    var devices = hidapi.hid_enumerate(ALL_VENDORS, ALL_PRODUCTS);
    defer hidapi.hid_free_enumeration(devices);

    var authenticators = std.ArrayList(fido.client.device.Authenticator).init(allocator);

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
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
