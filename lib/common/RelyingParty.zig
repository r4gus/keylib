//! Representation of a relying party

const std = @import("std");
const cbor = @import("zbor");
const dt = @import("data_types.zig");

/// Relying party identifier
///
/// A relying party identifier is a valid domain string identifying the WebAuthn
/// Relying Party on whose behalf a given registration or authentication ceremony
/// is being performed.
///
/// TODO: 128 bytes should be enough but maybe we can also truncate the id as
/// described by the CTAP2 spec.
id: dt.ABS128T,
/// Name of the relying party
name: ?dt.ABS64T = null,

pub fn new(
    id: []const u8,
    name: ?[]const u8,
) !@This() {
    return .{
        .id = (try dt.ABS128T.fromSlice(id)).?,
        .name = try dt.ABS64T.fromSlice(name),
    };
}

test "RelyingParty test #1" {
    const pkorg = try new("passkey.org", "Yubico Demo");
    const expected = "\xa2\x62\x69\x64\x6b\x70\x61\x73\x73\x6b\x65\x79\x2e\x6f\x72\x67\x64\x6e\x61\x6d\x65\x6b\x59\x75\x62\x69\x63\x6f\x20\x44\x65\x6d\x6f";

    var arr = std.ArrayList(u8).init(std.testing.allocator);
    defer arr.deinit();

    try cbor.stringify(pkorg, .{}, arr.writer());

    try std.testing.expectEqualSlices(u8, expected, arr.items);

    const di = try cbor.DataItem.new(expected);
    const pkorg2 = try cbor.parse(@This(), di, .{});

    try std.testing.expectEqualStrings(pkorg.id.get(), pkorg2.id.get());
    try std.testing.expectEqualStrings(pkorg.name.?.get(), pkorg2.name.?.get());
}
