//! Contains the attributes that are specified by a caller when referring to a
//! public key credential. See WebAuthn §5.8.3.

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../main.zig");

const AuthenticatorTransports = fido.common.AuthenticatorTransports;
const PublicKeyCredentialType = fido.common.PublicKeyCredentialType;

/// The credential id
id: []const u8,
/// Type of the credential
type: PublicKeyCredentialType,
/// Transport methods
transports: ?[]const AuthenticatorTransports = null,

/// Free all allocated memory of this data structure
pub fn deinit(self: *const @This(), allocator: @import("std").mem.Allocator) void {
    allocator.free(self.id);
    if (self.transports) |trans| {
        allocator.free(trans);
    }
}

test "serialize PublicKeyCredentialDescriptor" {
    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    const d = @This(){
        .type = .@"public-key",
        .id = "\x5c\x7b\xc6\x57\x09\xed\xcd\xbc\x8a\x61\x2f\x1f\x5e\x97\xd0\x15\xbd\x0e\xc7\x33\x28\x0b\x5c\xb5\x78\x62\x6d\xba\x37\xa1\xe5\x10\xc3\x9e\x79\xf8\x20\x0e\x95\xf7\x9d\x50\x5c\x44\x35\x61\xac\x07\x1e\xa7\x14\x3a\xd0\x6e\xf4\x8b\x56\xdd\x5d\x71\x22\x79\x77\x51",
    };

    try @import("zbor").stringify(d, .{}, str.writer());
    try std.testing.expectEqualSlices(u8, "\xa2\x62\x69\x64\x58\x40\x5c\x7b\xc6\x57\x09\xed\xcd\xbc\x8a\x61\x2f\x1f\x5e\x97\xd0\x15\xbd\x0e\xc7\x33\x28\x0b\x5c\xb5\x78\x62\x6d\xba\x37\xa1\xe5\x10\xc3\x9e\x79\xf8\x20\x0e\x95\xf7\x9d\x50\x5c\x44\x35\x61\xac\x07\x1e\xa7\x14\x3a\xd0\x6e\xf4\x8b\x56\xdd\x5d\x71\x22\x79\x77\x51\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79", str.items);
}
