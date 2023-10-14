//! Representation of a user

const cbor = @import("zbor");

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

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    // Not perfect but this way we don't rely on options providing the allocator
    var buffer: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const a = fba.allocator();

    var b = try cbor.Builder.withType(a, .Map);
    try b.pushTextString("id");
    try b.pushByteString(self.id);
    if (self.name) |name| {
        try b.pushTextString("name");
        try b.pushTextString(name);
    }
    if (self.displayName) |displayName| {
        try b.pushTextString("displayName");
        try b.pushTextString(displayName);
    }
    const x = try b.finish();
    try out.writeAll(x);
}
