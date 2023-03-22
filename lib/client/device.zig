const std = @import("std");

/// Abstract representation of an authenticator the client communicates with
pub const Authenticator = struct {
    transport: Transport,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *@This()) void {
        switch (self.transport) {
            .usb => |usbt| {
                self.allocator.free(usbt.path);
                self.allocator.free(usbt.serial_number);
                self.allocator.free(usbt.manufacturer_string);
                self.allocator.free(usbt.product_string);
            },
            .nfc => {},
            .bluetooth => {},
        }
    }
};

pub const TransportTag = enum { usb, nfc, bluetooth };

/// The transport of the authenticator
pub const Transport = union(TransportTag) {
    usb: struct {
        /// Device path, e.g., /dev/hidraw0
        path: []const u8,
        /// Device Vendor ID
        vendor_id: u16,
        /// Device Product ID
        product_id: u16,
        /// Serial Number
        serial_number: []const u8,
        /// Device Release Number in binary-coded decimal, also known as Device Version Number
        release_number: u16,
        /// Manufacturer string
        manufacturer_string: []const u8,
        /// Product string
        product_string: []const u8,
        /// The USB interface which this logical device represents.
        interface_number: i32,
    },
    nfc: void,
    bluetooth: void,
};
