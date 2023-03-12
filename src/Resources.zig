//! Resources provided by the underlying platform

const std = @import("std");
const data = @import("data.zig");

pub const LoadError = error{
    DoesNotExist,
    NotEnoughMemory,
};

/// Fill the given buffer with random bytes
rand: *const fn (b: []u8) void,

/// Get the time in ms since boot
millis: *const fn () u32,

/// Load data from memory
load: *const fn (a: std.mem.Allocator) LoadError![]u8,

/// Store data to memory
store: *const fn (d: []const u8) void,

/// Request permission (user presence) from the user
request_permission: *const fn (user: ?*const data.User, rp: ?*const data.RelyingParty) bool,
