const std = @import("std");

const hidapi = @cImport({
    @cInclude("hidapi/hidapi.h");
});

const ALL_VENDORS = 0;
const ALL_PRODUCTS = 0;

pub fn main() !void {
    _ = hidapi.hid_init();

    var devices = hidapi.hid_enumerate(ALL_VENDORS, ALL_PRODUCTS);
    defer hidapi.hid_free_enumeration(devices);

    while (devices != null) {
        if (devices.*.usage_page == 0xF1D0 and devices.*.usage == 0x01) {
            std.debug.print("{s}\n", .{devices.*.path});
        }
        devices = devices.*.next;
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
