//! Representation of a user

const std = @import("std");

/// The user handle of the user account. A user handle is an opaque byte
/// sequence with a maximum size of 64 bytes, and is not meant to be
/// displayed to the user.
id: []const u8,
/// A human-palatable identifier for a user account. It is intended only for
/// display, i.e., aiding the user in determining the difference between user
/// accounts with similar displayNames. For example, "alexm",
/// "alex.mueller@example.com" or "+14255551234".
name: ?[]const u8 = null,
/// A human-palatable name for the user account, intended only for display.
/// For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let
/// the user choose this, and SHOULD NOT restrict the choice more than necessary.
displayName: ?[]const u8 = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    if (self.name) |name| {
        allocator.free(name);
    }
    if (self.displayName) |name| {
        allocator.free(name);
    }
}
