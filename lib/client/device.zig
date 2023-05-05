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
    OutOfMemory,
};

/// Abstract representation of an authenticator the client communicates with
pub const Authenticator = struct {
    /// Information about the connected device
    transport: Transport,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.transport.path);
        if (self.transport.info) |info| {
            self.allocator.free(info);
        }
        self.transport.close();
    }

    /// Open a connection to the given device
    pub fn open(self: *@This()) IOError!void {
        self.transport.open();
    }

    /// Close the connection to the given device
    pub fn close(self: *@This()) void {
        self.transport.close();
    }

    /// Sent a CTAPHID request to the device
    pub fn write(self: *@This(), iter: *CtapHidMessageIterator) IOError!void {
        self.transport.write(iter);
    }

    /// Read a CTAPHID response from a device
    ///
    /// Timeout is set to 250 ms TODO: expose this???
    pub fn ctaphid_read(self: *@This(), allocator: std.mem.Allocator) ![]const u8 {
        return self.transport.read(allocator);
    }
};

pub const TransportType = enum { usb, nfc, bluetooth, ipc };

/// A struct representing a communication transport.
///
/// This struct contains information about the communication transport being used, such as
/// the device path, I/O functions, and the transport type. It provides methods for opening and
/// closing the transport, as well as reading and writing data over the transport.
pub const Transport = struct {
    /// Device path, e.g., /dev/hidraw0
    path: [:0]const u8,
    /// An optional info string
    info: ?[]const u8 = null,
    /// Input/ output functions
    io: IO,
    /// Opaque device pointer
    device: ?*anyopaque = null,
    /// Transport type
    type: TransportType,

    /// Opens the communication transport.
    pub fn open(self: *@This()) IOError!void {
        self.device = try self.io.open(self.path);
    }

    /// Closes the communication transport.
    pub fn close(self: *@This()) void {
        if (self.device) |device| {
            self.io.close(device);
        }
    }

    /// Writes data to the communication transport.
    ///
    /// This function writes data from an iterator to the communication transport. If the transport
    /// is not currently open, it will be opened automatically.
    ///
    /// # Arguments
    ///
    /// * `iter`: an iterator over the data to be written
    ///
    /// # Errors
    ///
    /// If an error occurs while writing to the transport, an `IOError` will be returned.
    pub fn write(self: *@This(), iter: anytype) IOError!void {
        if (self.device == null) try self.open();

        while (iter.next()) |r| {
            try self.io.write(self.device.?, r);
        }
    }

    /// Reads data from the communication transport.
    ///
    /// This function reads data from the communication transport and returns it as a slice.
    /// If the transport is not currently open, it will be opened automatically.
    ///
    /// # Arguments
    ///
    /// * `allocator`: an allocator to use for the returned slice
    ///
    /// # Returns
    ///
    /// A slice containing the data read from the transport, or an error if an I/O error occurred.
    pub fn read(self: *@This(), allocator: std.mem.Allocator) ![]const u8 {
        if (self.device == null) try self.open();
        return try self.io.read(self.device.?, allocator);
    }
};

pub const IO = struct {
    /// Open a connection to the given device
    open: *const fn (path: [:0]const u8) IOError!*anyopaque,
    /// Close the connection to a device
    close: *const fn (dev: *anyopaque) void,
    /// Write data to the device
    write: *const fn (dev: *anyopaque, data: []const u8) IOError!void,
    /// Read data from the device with timeout
    read: *const fn (dev: *anyopaque, allocator: std.mem.Allocator) IOError![]const u8,
};
