const std = @import("std");

const fido = @import("../main.zig");
const CtapHidMessageIterator = fido.transport_specific_bindings.ctaphid.CtapHidMessageIterator;
const Cmd = fido.transport_specific_bindings.ctaphid.Cmd;

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
    MissingCallbacks,
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
        read_timeout: *const fn (dev: *anyopaque, buffer: []u8, millis: i32) IOError!usize,
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

    /// Open a connection to the given device
    pub fn open(self: *@This()) IOError!void {
        if (self.io) |io| {
            self.device = try io.open(&self.transport);
        } else {
            return IOError.Open;
        }
    }

    /// Close the connection to the given device
    pub fn close(self: *@This()) void {
        if (self.io) |io| {
            if (self.device) |device| {
                io.close(device);
            }
        }
    }

    /// Sent a CTAPHID request to the device
    pub fn ctaphid_write(self: *@This(), iter: *CtapHidMessageIterator) IOError!void {
        var buffer: [65]u8 = undefined;

        // Open device if not already done
        if (self.device == null) try self.open();

        if (self.io) |io| {
            while (iter.next()) |r| {
                buffer[0] = 0;
                std.mem.copy(u8, buffer[1..], r);
                try io.write(self.device.?, buffer[0..]);
            }
        } else {
            return IOError.MissingCallbacks;
        }
    }

    /// Read a CTAPHID response from a device
    ///
    /// Timeout is set to 250 ms TODO: expose this???
    pub fn ctaphid_read(self: *@This(), allocator: std.mem.Allocator) ![]const u8 {
        if (self.io) |io| {
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

                const nr = try io.read_timeout(self.device.?, buffer[0..], 250);
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
        } else {
            return IOError.MissingCallbacks;
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
