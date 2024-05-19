//! Representation of a user

const cbor = @import("zbor");
const std = @import("std");
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
