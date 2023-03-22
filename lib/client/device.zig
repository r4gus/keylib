const std = @import("std");

pub const IOError = error{
    /// The authenticator uses an unexpected transport
    UnexpectedTransport,
    /// Cannot open device connection
    Open,
    /// Can not write to the device
    Write,
    /// Can not read from the device
    Read,
    /// A timeout occured
    Timeout,
};

/// Abstract representation of an authenticator the client communicates with
pub const Authenticator = struct {
    /// Information about the connected device
    transport: Transport,
    /// Callbacks for interacting with a device
    io: ?struct {
        /// Open a connection to the given device
        open: *const fn (transport: *const Transport) IOError!*anyopaque,
        /// Close the connection to a device
        close: *const fn (dev: *anyopaque) void,
        /// Write data to the device
        write: *const fn (dev: *anyopaque, data: []const u8) IOError!void,
        /// Read data from the device with timeout
        read_timeout: *const fn (dev: *anyopaque, buffer: []u8, millis: i32) IOError!void,
    } = null,
    /// Opaque pointer to the device struct returned by open and used by close, read and write
    device: ?*anyopaque = null,
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
        path: [:0]const u8,
        /// Device Vendor ID
        vendor_id: u16,
        /// Device Product ID
        product_id: u16,
        /// Serial Number
        serial_number: [:0]const u8,
        /// Device Release Number in binary-coded decimal, also known as Device Version Number
        release_number: u16,
        /// Manufacturer string
        manufacturer_string: [:0]const u8,
        /// Product string
        product_string: [:0]const u8,
        /// The USB interface which this logical device represents.
        interface_number: i32,
    },
    nfc: void,
    bluetooth: void,
};
