//! Parameters of the client pin command

const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

const cbor = @import("zbor");
const fido = @import("../../main.zig");

/// pinUvAuthProtocol: PIN protocol version chosen by the client.
pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol,
/// subCommand: The authenticator Client PIN sub command currently
/// being requested.
subCommand: fido.ctap.pinuv.common.SubCommand,
/// keyAgreement: Public key of platformKeyAgreementKey. The
/// COSE_Key-encoded public key MUST contain the optional "alg"
/// parameter and MUST NOT contain any other optional parameters.
/// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
keyAgreement: ?cbor.cose.Key,
/// pinUvAuth: HMAC-SHA-256 of encrypted contents
/// using sharedSecret. See Setting a new PIN, Changing existing
/// PIN and Getting pinToken from the authenticator for more details.
pinUvAuthParam: ?[Hmac.mac_length]u8,
/// newPinEnc: Encrypted new PIN using sharedSecret. Encryption is
/// done over UTF-8 representation of new PIN.
newPinEnc: ?[]const u8, // TODO: this should always be 64 bytes
/// pinHashEnc: Encrypted first 16 bytes of SHA-256 of PIN using
/// sharedSecret.
pinHashEnc: ?[32]u8,
/// permissions: Bitfield of permissions. If present, MUST NOT be 0.
permissions: ?u8,
/// rpId: The RP ID to assign as the permissions RP ID.
rpId: ?[]const u8,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.newPinEnc) |pin| {
        allocator.free(pin);
    }

    if (self.rpId) |id| {
        allocator.free(id);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    try cbor.stringify(self.*, .{
        .field_settings = &.{
            .{ .name = "pinUvAuthProtocol", .alias = "1", .options = .{} },
            .{ .name = "subCommand", .alias = "2", .options = .{} },
            .{ .name = "keyAgreement", .alias = "3", .options = .{} },
            .{ .name = "pinUvAuthParam", .alias = "4", .options = .{} },
            .{ .name = "newPinEnc", .alias = "5", .options = .{} },
            .{ .name = "pinHashEnc", .alias = "6", .options = .{} },
            .{ .name = "permissions", .alias = "9", .options = .{} },
            .{ .name = "rpId", .alias = "10", .options = .{} },
        },
        .from_cborStringify = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.ParseOptions) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .from_cborParse = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "pinUvAuthProtocol", .alias = "1", .options = .{} },
            .{ .name = "subCommand", .alias = "2", .options = .{} },
            .{ .name = "keyAgreement", .alias = "3", .options = .{} },
            .{ .name = "pinUvAuthParam", .alias = "4", .options = .{} },
            .{ .name = "newPinEnc", .alias = "5", .options = .{} },
            .{ .name = "pinHashEnc", .alias = "6", .options = .{} },
            .{ .name = "permissions", .alias = "9", .options = .{} },
            .{ .name = "rpId", .alias = "10", .options = .{} },
        },
    });
}

pub fn mcPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x01 != 0 else false;
}

pub fn gaPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x02 != 0 else false;
}

pub fn cmPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x04 != 0 else false;
}

pub fn bePermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x08 != 0 else false;
}

pub fn lbwPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x10 != 0 else false;
}

pub fn acfgPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x20 != 0 else false;
}
