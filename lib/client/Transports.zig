//! A collection of Transport's
//!
//! Each Transport is the abstract representation of a (authenticator) device
//! you can communicate with.

const std = @import("std");

pub const Transport = @import("Transport.zig");
pub const usb = @import("transports/usb.zig");

pub const Error = error{
    OutOfMemory,
};

pub const EnumerateOptions = struct {
    funs: []const *const fn (a: std.mem.Allocator) Error!?[]Transport = &.{
        usb.enumerate,
    },
};

const Self = @This();

devices: []Transport,
allocator: std.mem.Allocator,

pub fn deinit(self: *const Self) void {
    for (self.devices) |*dev| {
        dev.deinit();
    }
    self.allocator.free(self.devices);
}

/// Find all connected devices
pub fn enumerate(a: std.mem.Allocator, options: EnumerateOptions) Error!Self {
    var arr = std.ArrayList(Transport).init(a);
    defer arr.deinit();

    for (options.funs) |fun| {
        if (try fun(a)) |v| {
            try arr.appendSlice(v);
        }
    }

    return Self{
        .devices = try arr.toOwnedSlice(),
        .allocator = a,
    };
}
