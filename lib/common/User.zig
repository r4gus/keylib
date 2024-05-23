//! Representation of a user

const std = @import("std");
const cbor = @import("zbor");
const dt = @import("data_types.zig");

/// The user handle of the user account. A user handle is an opaque byte
/// sequence with a maximum size of 64 bytes, and is not meant to be
/// displayed to the user.
id: dt.ABS64B = .{},
/// A human-palatable identifier for a user account. It is intended only for
/// display, i.e., aiding the user in determining the difference between user
/// accounts with similar displayNames. For example, "alexm",
/// "alex.mueller@example.com" or "+14255551234".
name: ?dt.ABS64T = null,
/// A human-palatable name for the user account, intended only for display.
/// For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let
/// the user choose this, and SHOULD NOT restrict the choice more than necessary.
displayName: ?dt.ABS64T = null,

pub fn new(
    id: []const u8,
    name: ?[]const u8,
    displayName: ?[]const u8,
) !@This() {
    return .{
        .id = (try dt.ABS64B.fromSlice(id)).?,
        .name = try dt.ABS64T.fromSlice(name),
        .displayName = try dt.ABS64T.fromSlice(displayName),
    };
}

pub fn getName(self: *const @This()) []const u8 {
    if (self.displayName) |dn| return dn.get();
    if (self.name) |n| return n.get();
    return "";
}

test "User test #1" {
    const klaus = try new("\x0c\x43\x0e\xff\xff\x5f\x5f\x5f\x44\x45\x4d\x4f", "klaus", "klaus");
    const expected = "\xa3\x62\x69\x64\x4c\x0c\x43\x0e\xff\xff\x5f\x5f\x5f\x44\x45\x4d\x4f\x64\x6e\x61\x6d\x65\x65\x6b\x6c\x61\x75\x73\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x65\x6b\x6c\x61\x75\x73";

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();

    try cbor.stringify(klaus, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, expected, arr.items);

    const di = try cbor.DataItem.new(expected);
    const klaus2 = try cbor.parse(@This(), di, .{});

    try std.testing.expectEqualStrings(klaus.id.get(), klaus2.id.get());
    try std.testing.expectEqualStrings(klaus.name.?.get(), klaus2.name.?.get());
    try std.testing.expectEqualStrings(klaus.displayName.?.get(), klaus2.displayName.?.get());
}
